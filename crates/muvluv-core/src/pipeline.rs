use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::rugp::crsa::{
    find_vm_msg_commands, infer_pool_base, is_crsa_record, parse_crsa_record, read_pool_slot,
    rebuild_crsa, scan_translatable_counted_strings, sha256_hex, CrsaRebuildReport, CVM_MSG3_DECL,
};
use crate::rugp::crypto::decode_extent_offset;
use crate::rugp::ici::load_toc;
use crate::rugp::ruo::{build_cumulative_ruo, read_ruo_footer, RuoBuildReport, RuoReplacement};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LgEntry {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub index: usize,
    pub kind: String, // "cvm_msg", "pipe_ui", "choice_or_ui"
    pub source_raw_offset: u32,
    #[serde(default)]
    pub cmd_order: usize,
    #[serde(default)]
    pub marker_offset: usize,
    #[serde(default)]
    pub jp_prefix: String,
    #[serde(default)]
    pub jp_reference: String,
    #[serde(default)]
    pub has_speaker: bool,
    #[serde(default)]
    pub orig_speaker: String,
    #[serde(default)]
    pub leading_controls: String,
    #[serde(default)]
    pub trailing_controls: String,
    #[serde(default)]
    pub inline_tags: Vec<String>,
    pub orig_exported_msg: String,
    pub orig_raw_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    pub filename: String,
    pub scene_title: String,
    pub source_raw_hexes: Vec<String>,
    pub entry_count: usize,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrsaMeta {
    pub source_raw_offset: u32,
    pub source_raw_hex: String,
    pub global_offset_hex: String,
    pub record_sha256: String,
    pub plaintext_sha256: String,
    pub record_size: usize,
    pub plaintext_size: usize,
    pub pool_base: Option<usize>,
    pub pool_units: u32,
    pub msg_cmd_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub game: String,
    pub active_ruo_name: String,
    pub unit_size: u64,
    pub crsa_by_hex: HashMap<String, CrsaMeta>,
    pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractSummary {
    pub active_ruo: String,
    pub total_crsa_records: usize,
    pub exported_files: usize,
    pub total_entries: usize,
    pub dialogue_entries: usize,
    pub choice_ui_entries: usize,
    pub pipe_ui_entries: usize,
    pub unique_speakers: usize,
    pub round_trip_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub file: String,
    pub index: i64,
    pub severity: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sample: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub manifest_files: usize,
    pub present_files: usize,
    pub missing_files: usize,
    pub total_entries: usize,
    pub translated_entries: usize,
    pub untranslated_in_present_files: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub passed: bool,
    pub issues: Vec<ValidationIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildSummary {
    pub base_ruo_path: String,
    pub output_ruo_path: String,
    pub modified_crsa_count: usize,
    pub total_changed_entries: usize,
    pub total_in_place_msgs: usize,
    pub total_appended_msgs: usize,
    pub total_counted_edits: usize,
    pub ruo_report: RuoBuildReport,
    pub crsa_reports: HashMap<String, CrsaRebuildReport>,
    pub final_readback_ok: bool,
}

pub fn detect_active_ruo(game_dir: &Path) -> Result<PathBuf> {
    let exe_path = game_dir.join("muvluv16.exe");
    if let Ok(exe_bytes) = fs::read(&exe_path) {
        if exe_bytes
            .windows(b".drcruo1".len())
            .any(|w| w == b".drcruo1")
        {
            let p = game_dir.join("muvluv16.rio.drcruo1");
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    for name in ["muvluv16.rio.drcruo1", "muvluv16.rio.ruo1"] {
        let p = game_dir.join(name);
        if p.is_file() {
            return Ok(p);
        }
    }
    bail!(
        "no muvluv16.rio.drcruo1 or muvluv16.rio.ruo1 found in {}",
        game_dir.display()
    );
}

fn has_visible_text(s: &str) -> bool {
    s.chars().any(|r| (r as u32) >= 0x20 && !r.is_whitespace())
}

fn is_strippable_edge_control(r: char) -> bool {
    matches!(r, '\x01' | '\x02' | '\x05' | '\r' | '\n')
}

/// Splits speaker, strips edge controls, and replaces inline controls with `<WAIT>` / `<CTRLxx>`.
fn encode_for_linguagacha(
    raw: &str,
    split_speaker: bool,
) -> (String, String, String, String, bool, Vec<String>) {
    let chars: Vec<char> = raw.chars().collect();

    let mut start = 0usize;
    while start < chars.len() && is_strippable_edge_control(chars[start]) {
        start += 1;
    }
    let lead: String = chars[..start].iter().collect();

    let mut end = chars.len();
    while end > start && is_strippable_edge_control(chars[end - 1]) {
        end -= 1;
    }
    let trail: String = chars[end..].iter().collect();

    let mut core: String = chars[start..end].iter().collect();
    let mut name = String::new();
    let mut has_speaker = false;

    if split_speaker && core.starts_with('【') {
        let open_len = '【'.len_utf8();
        if let Some(rel_close) = core[open_len..].find('】') {
            if rel_close > 0 {
                let close_idx = open_len + rel_close;
                name = core[open_len..close_idx].to_string();
                core = core[close_idx + '】'.len_utf8()..].to_string();
                has_speaker = true;
            }
        }
    }

    let mut msg = String::with_capacity(core.len());
    let mut inline_tags = Vec::new();
    for r in core.chars() {
        let code = r as u32;
        if code < 0x20 && r != '\n' && r != '\r' && r != '\t' {
            let tag = if code == 0x02 {
                "<WAIT>".to_string()
            } else {
                format!("<CTRL{:02X}>", code)
            };
            msg.push_str(&tag);
            inline_tags.push(tag);
        } else {
            msg.push(r);
        }
    }

    (name, msg, lead, trail, has_speaker, inline_tags)
}

fn parse_ctrl_tag_at(s: &str, pos: usize) -> Option<(usize, char, String)> {
    let rest = &s[pos..];
    if rest.starts_with("<WAIT>") {
        return Some((6, '\x02', "<WAIT>".to_string()));
    }
    if rest.len() >= 8 && rest.starts_with("<CTRL") && rest.as_bytes()[7] == b'>' {
        let hex_part = &rest[5..7];
        if hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            if let Ok(v) = u8::from_str_radix(hex_part, 16) {
                return Some((8, v as char, rest[..8].to_string()));
            }
        }
    }
    None
}

fn extract_inline_tags(s: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            if let Some((len, _, tag)) = parse_ctrl_tag_at(s, i) {
                tags.push(tag);
                i += len;
                continue;
            }
        }
        i += 1;
    }
    tags
}

fn replace_inline_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < s.len() {
        if s.as_bytes()[i] == b'<' {
            if let Some((len, ch, _)) = parse_ctrl_tag_at(s, i) {
                out.push(ch);
                i += len;
                continue;
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

pub fn decode_from_linguagacha(entry: &ManifestEntry, translated: &LgEntry) -> Result<String> {
    if translated.name.contains('\0') || translated.message.contains('\0') {
        bail!("embedded NUL (U+0000) is forbidden");
    }
    let restored = replace_inline_tags(&translated.message);
    if entry.kind == "pipe_ui" {
        return Ok(format!(
            "{}\\|{}{}{}",
            entry.jp_prefix, entry.leading_controls, restored, entry.trailing_controls
        ));
    }
    let mut out = String::new();
    out.push_str(&entry.leading_controls);
    if entry.has_speaker {
        let spk = if translated.name.is_empty() {
            &entry.orig_speaker
        } else {
            &translated.name
        };
        out.push('【');
        out.push_str(spk);
        out.push('】');
    }
    out.push_str(&restored);
    out.push_str(&entry.trailing_controls);
    Ok(out)
}

fn sanitize_filename(s: &str) -> String {
    let mut out = String::new();
    let mut last_underscore = false;
    for r in s.chars() {
        if r.is_ascii_alphanumeric() {
            out.push(r);
            last_underscore = false;
        } else if matches!(r, '-' | '/' | ' ' | '_') && !last_underscore && !out.is_empty() {
            if r == '/' {
                out.push('-');
            } else {
                out.push('_');
            }
            last_underscore = true;
        }
    }
    let trimmed = out.trim_matches(|c| c == '_' || c == '-');
    if trimmed.len() > 40 {
        trimmed[..40].to_string()
    } else {
        trimmed.to_string()
    }
}

/// Extracts all 102 scene mappings (63,242 entries) directly in memory from the original game files.
pub fn extract_manifest_in_memory<F>(
    game_dir: &Path,
    base_ruo_override: Option<&Path>,
    mut on_progress: F,
) -> Result<(Manifest, ExtractSummary)>
where
    F: FnMut(usize, usize),
{
    let base_ruo_path = match base_ruo_override {
        Some(p) => p.to_path_buf(),
        None => detect_active_ruo(game_dir)?,
    };
    let toc = load_toc(game_dir, "muvluv16").context("load TOC")?;
    let ruo = read_ruo_footer(&base_ruo_path, toc.unit_size).context("read RUO")?;

    struct CrsaItem {
        src_raw: u32,
        g_off: u64,
        rec: crate::rugp::crsa::CrsaRecord,
    }

    let mut crsa_list: Vec<CrsaItem> = Vec::new();
    let mut ruo_file = File::open(&base_ruo_path)?;
    for red in &ruo.redirects {
        let Some(raw) = ruo.read_record_from_file(&mut ruo_file, red.source_raw_offset)? else {
            continue;
        };
        if !is_crsa_record(&raw) {
            continue;
        }
        let parsed = parse_crsa_record(&raw)
            .with_context(|| format!("parse CRsa 0x{:08X}", red.source_raw_offset))?;
        crsa_list.push(CrsaItem {
            src_raw: red.source_raw_offset,
            g_off: decode_extent_offset(red.source_raw_offset, toc.unit_size),
            rec: parsed,
        });
    }
    crsa_list.sort_by_key(|item| item.g_off);

    let mut manifest = Manifest {
        schema_version: 1,
        game: "Muv-Luv Steam 2016 (muvluv16)".to_string(),
        active_ruo_name: base_ruo_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        unit_size: toc.unit_size,
        crsa_by_hex: HashMap::with_capacity(crsa_list.len()),
        files: Vec::new(),
    };

    let mut speaker_counts: HashMap<String, usize> = HashMap::new();
    let mut ui_entries: Vec<ManifestEntry> = Vec::new();
    let mut ui_src_set: HashSet<String> = HashSet::new();

    let mut dialogue_count = 0usize;
    let mut choice_ui_count = 0usize;
    let mut pipe_ui_count = 0usize;
    let mut scene_number = 0usize;

    let total_crsa = crsa_list.len();

    for (idx, item) in crsa_list.iter().enumerate() {
        on_progress(idx + 1, total_crsa);
        let src_hex = format!("0x{:08X}", item.src_raw);
        let plain = &item.rec.plaintext;

        let mut cmds = Vec::new();
        let mut pool_base: Option<usize> = None;
        let mut pool_units: u32 = 0;

        if plain.windows(CVM_MSG3_DECL.len()).any(|w| w == CVM_MSG3_DECL) {
            cmds = find_vm_msg_commands(plain)
                .with_context(|| format!("CRsa {} FindVmMsgCommands", src_hex))?;
            if let Some((pb, pu)) = infer_pool_base(plain, &cmds)
                .with_context(|| format!("CRsa {} InferPoolBase", src_hex))?
            {
                pool_base = Some(pb);
                pool_units = pu;
            }
        }

        manifest.crsa_by_hex.insert(
            src_hex.clone(),
            CrsaMeta {
                source_raw_offset: item.src_raw,
                source_raw_hex: src_hex.clone(),
                global_offset_hex: format!("0x{:X}", item.g_off),
                record_sha256: item.rec.record_sha256.clone(),
                plaintext_sha256: item.rec.plaintext_sha256.clone(),
                record_size: item.rec.raw_record.len(),
                plaintext_size: plain.len(),
                pool_base,
                pool_units,
                msg_cmd_count: cmds.len(),
            },
        );

        let counted = scan_translatable_counted_strings(plain, pool_base);

        let has_visible_dialogue = if let Some(pb) = pool_base {
            cmds.iter().any(|c| {
                c.first[1][0] != 0
                    && read_pool_slot(plain, pb, pool_units, c.first[1][0])
                        .is_some_and(|(en, _)| has_visible_text(&en))
            })
        } else {
            false
        };

        if !has_visible_dialogue {
            for cs in &counted {
                if !has_visible_text(&cs.en_text) {
                    continue;
                }
                let (_, msg, lead, trail, _, tags) = encode_for_linguagacha(&cs.en_text, false);
                let me = ManifestEntry {
                    index: ui_entries.len(),
                    kind: cs.kind.clone(),
                    source_raw_offset: item.src_raw,
                    cmd_order: 0,
                    marker_offset: cs.marker_offset,
                    jp_prefix: cs.jp_prefix.clone(),
                    jp_reference: cs.jp_prefix.clone(),
                    has_speaker: false,
                    orig_speaker: String::new(),
                    leading_controls: lead,
                    trailing_controls: trail,
                    inline_tags: tags,
                    orig_exported_msg: msg.clone(),
                    orig_raw_text: cs.text.clone(),
                };
                let lg = LgEntry {
                    name: String::new(),
                    message: msg,
                };
                let rt = decode_from_linguagacha(&me, &lg)?;
                if rt != cs.text {
                    bail!(
                        "lossless check failed for UI {} @0x{:X}: got {:?} want {:?}",
                        src_hex,
                        cs.marker_offset,
                        rt,
                        cs.text
                    );
                }
                ui_entries.push(me);
                ui_src_set.insert(src_hex.clone());
                if cs.kind == "pipe_ui" {
                    pipe_ui_count += 1;
                } else {
                    choice_ui_count += 1;
                }
            }
            continue;
        }

        let pb = pool_base.unwrap();
        let mut scene_entries: Vec<ManifestEntry> = Vec::new();
        let mut scene_title = String::new();

        // 1. Chapter titles (pipe_ui)
        for cs in &counted {
            if cs.kind != "pipe_ui" || !has_visible_text(&cs.en_text) {
                continue;
            }
            if scene_title.is_empty() {
                scene_title = cs.en_text.trim().to_string();
            }
            let (_, msg, lead, trail, _, tags) = encode_for_linguagacha(&cs.en_text, false);
            let me = ManifestEntry {
                index: scene_entries.len(),
                kind: cs.kind.clone(),
                source_raw_offset: item.src_raw,
                cmd_order: 0,
                marker_offset: cs.marker_offset,
                jp_prefix: cs.jp_prefix.clone(),
                jp_reference: cs.jp_prefix.clone(),
                has_speaker: false,
                orig_speaker: String::new(),
                leading_controls: lead,
                trailing_controls: trail,
                inline_tags: tags,
                orig_exported_msg: msg.clone(),
                orig_raw_text: cs.text.clone(),
            };
            let lg = LgEntry {
                name: String::new(),
                message: msg,
            };
            let rt = decode_from_linguagacha(&me, &lg)?;
            if rt != cs.text {
                bail!(
                    "lossless check failed for title {} @0x{:X}: got {:?} want {:?}",
                    src_hex,
                    cs.marker_offset,
                    rt,
                    cs.text
                );
            }
            scene_entries.push(me);
            pipe_ui_count += 1;
        }

        // 2. All visible EN CVmMsg3 lines in exact command stream order
        for (i, c) in cmds.iter().enumerate() {
            let en_idx = c.first[1][0];
            if en_idx == 0 {
                continue;
            }
            let Some((en, _)) = read_pool_slot(plain, pb, pool_units, en_idx) else {
                continue;
            };
            if !has_visible_text(&en) {
                continue;
            }
            let jp = if c.first[0][0] != 0 {
                read_pool_slot(plain, pb, pool_units, c.first[0][0])
                    .map(|(s, _)| s)
                    .unwrap_or_default()
            } else {
                String::new()
            };
            let (name, msg, lead, trail, has_spk, tags) = encode_for_linguagacha(&en, true);
            if has_spk {
                *speaker_counts.entry(name.clone()).or_insert(0) += 1;
            }
            let me = ManifestEntry {
                index: scene_entries.len(),
                kind: "cvm_msg".to_string(),
                source_raw_offset: item.src_raw,
                cmd_order: i,
                marker_offset: 0,
                jp_prefix: String::new(),
                jp_reference: jp,
                has_speaker: has_spk,
                orig_speaker: name.clone(),
                leading_controls: lead,
                trailing_controls: trail,
                inline_tags: tags,
                orig_exported_msg: msg.clone(),
                orig_raw_text: en.clone(),
            };
            let lg = LgEntry { name, message: msg };
            let rt = decode_from_linguagacha(&me, &lg)?;
            if rt != en {
                bail!(
                    "lossless check failed for {} cmd {}: got {:?} want {:?}",
                    src_hex,
                    i,
                    rt,
                    en
                );
            }
            scene_entries.push(me);
            dialogue_count += 1;
        }

        // 3. Branching choices in this scene
        for cs in &counted {
            if cs.kind == "pipe_ui" || !has_visible_text(&cs.en_text) {
                continue;
            }
            let (_, msg, lead, trail, _, tags) = encode_for_linguagacha(&cs.en_text, false);
            let me = ManifestEntry {
                index: scene_entries.len(),
                kind: cs.kind.clone(),
                source_raw_offset: item.src_raw,
                cmd_order: 0,
                marker_offset: cs.marker_offset,
                jp_prefix: String::new(),
                jp_reference: String::new(),
                has_speaker: false,
                orig_speaker: String::new(),
                leading_controls: lead,
                trailing_controls: trail,
                inline_tags: tags,
                orig_exported_msg: msg.clone(),
                orig_raw_text: cs.text.clone(),
            };
            let lg = LgEntry {
                name: String::new(),
                message: msg,
            };
            let rt = decode_from_linguagacha(&me, &lg)?;
            if rt != cs.text {
                bail!(
                    "lossless check failed for choice {} @0x{:X}: got {:?} want {:?}",
                    src_hex,
                    cs.marker_offset,
                    rt,
                    cs.text
                );
            }
            scene_entries.push(me);
            choice_ui_count += 1;
        }

        scene_number += 1;
        let mut clean_title = sanitize_filename(&scene_title);
        if clean_title.is_empty() {
            clean_title = "Scene".to_string();
        }
        let filename = format!("{:03}_{}_{:08X}.json", scene_number, clean_title, item.src_raw);
        let entry_count = scene_entries.len();
        manifest.files.push(ManifestFile {
            filename,
            scene_title,
            source_raw_hexes: vec![src_hex],
            entry_count,
            entries: scene_entries,
        });
    }

    if !ui_entries.is_empty() {
        let mut ui_hexes: Vec<String> = ui_src_set.into_iter().collect();
        ui_hexes.sort();
        let entry_count = ui_entries.len();
        let ui_file = ManifestFile {
            filename: "000_UI_System_Menus.json".to_string(),
            scene_title: "UI, Menus & System Dialogs".to_string(),
            source_raw_hexes: ui_hexes,
            entry_count,
            entries: ui_entries,
        };
        manifest.files.insert(0, ui_file);
    }

    let summary = ExtractSummary {
        active_ruo: base_ruo_path.to_string_lossy().into_owned(),
        total_crsa_records: total_crsa,
        exported_files: manifest.files.len(),
        total_entries: dialogue_count + choice_ui_count + pipe_ui_count,
        dialogue_entries: dialogue_count,
        choice_ui_entries: choice_ui_count,
        pipe_ui_entries: pipe_ui_count,
        unique_speakers: speaker_counts.len(),
        round_trip_verified: true,
    };

    Ok((manifest, summary))
}

fn strip_utf8_bom(raw: &[u8]) -> &[u8] {
    raw.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(raw)
}

pub fn validate_translations(
    manifest: &Manifest,
    translated_dir: &Path,
    strict_complete: bool,
) -> ValidationReport {
    let mut rep = ValidationReport {
        manifest_files: manifest.files.len(),
        present_files: 0,
        missing_files: 0,
        total_entries: 0,
        translated_entries: 0,
        untranslated_in_present_files: 0,
        error_count: 0,
        warning_count: 0,
        passed: false,
        issues: Vec::new(),
    };

    for mf in &manifest.files {
        rep.total_entries += mf.entry_count;
        let p = translated_dir.join(&mf.filename);
        let raw = match fs::read(&p) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                rep.missing_files += 1;
                if strict_complete {
                    rep.error_count += 1;
                    rep.issues.push(ValidationIssue {
                        file: mf.filename.clone(),
                        index: -1,
                        severity: "error".to_string(),
                        reason: "missing translated file".to_string(),
                        sample: String::new(),
                    });
                }
                continue;
            }
            Err(e) => {
                rep.error_count += 1;
                rep.issues.push(ValidationIssue {
                    file: mf.filename.clone(),
                    index: -1,
                    severity: "error".to_string(),
                    reason: format!("read error: {}", e),
                    sample: String::new(),
                });
                continue;
            }
        };

        rep.present_files += 1;
        let items: Vec<LgEntry> = match serde_json::from_slice(strip_utf8_bom(&raw)) {
            Ok(v) => v,
            Err(e) => {
                rep.error_count += 1;
                rep.issues.push(ValidationIssue {
                    file: mf.filename.clone(),
                    index: -1,
                    severity: "error".to_string(),
                    reason: format!("invalid JSON array: {}", e),
                    sample: String::new(),
                });
                continue;
            }
        };

        if items.len() != mf.entries.len() {
            rep.error_count += 1;
            rep.issues.push(ValidationIssue {
                file: mf.filename.clone(),
                index: -1,
                severity: "error".to_string(),
                reason: format!(
                    "array length mismatch: got {}, expected {}",
                    items.len(),
                    mf.entries.len()
                ),
                sample: String::new(),
            });
            continue;
        }

        for (i, entry) in mf.entries.iter().enumerate() {
            let it = &items[i];
            if it.message.contains('\0') || it.name.contains('\0') {
                rep.error_count += 1;
                rep.issues.push(ValidationIssue {
                    file: mf.filename.clone(),
                    index: i as i64,
                    severity: "error".to_string(),
                    reason: "embedded U+0000 NUL character forbidden (causes AGES InternalError 8311)"
                        .to_string(),
                    sample: it.message.clone(),
                });
                continue;
            }
            if it.message.trim().is_empty() {
                rep.error_count += 1;
                rep.issues.push(ValidationIssue {
                    file: mf.filename.clone(),
                    index: i as i64,
                    severity: "error".to_string(),
                    reason: "translated message is empty".to_string(),
                    sample: entry.orig_exported_msg.clone(),
                });
                continue;
            }
            let got_tags = extract_inline_tags(&it.message);
            if got_tags.len() != entry.inline_tags.len() {
                rep.error_count += 1;
                rep.issues.push(ValidationIssue {
                    file: mf.filename.clone(),
                    index: i as i64,
                    severity: "error".to_string(),
                    reason: format!(
                        "inline control tag count mismatch: got {:?}, expected {:?}",
                        got_tags, entry.inline_tags
                    ),
                    sample: it.message.clone(),
                });
            }
            if entry.has_speaker && it.name.trim().is_empty() {
                rep.warning_count += 1;
                if rep.issues.len() < 200 {
                    rep.issues.push(ValidationIssue {
                        file: mf.filename.clone(),
                        index: i as i64,
                        severity: "warning".to_string(),
                        reason: format!(
                            "speaker name omitted (will auto-restore {:?} on build)",
                            entry.orig_speaker
                        ),
                        sample: String::new(),
                    });
                }
            }
            if entry.kind == "pipe_ui" && it.message.contains(r"\|") {
                rep.error_count += 1;
                rep.issues.push(ValidationIssue {
                    file: mf.filename.clone(),
                    index: i as i64,
                    severity: "error".to_string(),
                    reason: r"translated UI text must not contain '\|' delimiter".to_string(),
                    sample: it.message.clone(),
                });
            }

            match decode_from_linguagacha(entry, it) {
                Ok(rebuilt) => {
                    if rebuilt != entry.orig_raw_text {
                        rep.translated_entries += 1;
                    } else {
                        rep.untranslated_in_present_files += 1;
                    }
                }
                Err(e) => {
                    rep.error_count += 1;
                    rep.issues.push(ValidationIssue {
                        file: mf.filename.clone(),
                        index: i as i64,
                        severity: "error".to_string(),
                        reason: e.to_string(),
                        sample: String::new(),
                    });
                }
            }
        }
    }

    rep.passed = rep.error_count == 0;
    rep
}

#[derive(Debug, Clone, Copy)]
pub enum BuildProgressEvent {
    RebuildingCrsa { current: usize, total: usize },
    WritingRuo { copied: u64, total: u64 },
    VerifyingOutput,
}

/// Builds a cumulative RUO directly from an in-memory Manifest and translated JSON directory.
/// Writes to `<output_ruo_path>.tmp`, validates footer + every CRsa on `.tmp`, then swaps atomically.
pub fn build_from_manifest<F>(
    base_ruo_path: &Path,
    manifest: &Manifest,
    translated_dir: &Path,
    output_ruo_path: &Path,
    strict_complete: bool,
    mut on_progress: F,
) -> Result<BuildSummary>
where
    F: FnMut(BuildProgressEvent),
{
    let val_rep = validate_translations(manifest, translated_dir, strict_complete);
    if !val_rep.passed {
        let first = val_rep
            .issues
            .iter()
            .find(|i| i.severity == "error")
            .map(|i| format!("{}[{}]: {}", i.file, i.index, i.reason))
            .unwrap_or_default();
        bail!(
            "validação da tradução falhou com {} erro(s): {}",
            val_rep.error_count,
            first
        );
    }

    let base_ruo = read_ruo_footer(base_ruo_path, manifest.unit_size)?;

    let mut msg_edits_by_crsa: HashMap<u32, HashMap<usize, String>> = HashMap::new();
    let mut counted_edits_by_crsa: HashMap<u32, HashMap<usize, String>> = HashMap::new();
    let mut changed_entries = 0usize;

    for mf in &manifest.files {
        let p = translated_dir.join(&mf.filename);
        let raw = match fs::read(&p) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let items: Vec<LgEntry> = serde_json::from_slice(strip_utf8_bom(&raw))
            .with_context(|| format!("parse {}", mf.filename))?;
        for (i, entry) in mf.entries.iter().enumerate() {
            let rebuilt = decode_from_linguagacha(entry, &items[i])
                .with_context(|| format!("{}[{}]", mf.filename, i))?;
            if rebuilt == entry.orig_raw_text {
                continue;
            }
            changed_entries += 1;
            if entry.kind == "cvm_msg" {
                msg_edits_by_crsa
                    .entry(entry.source_raw_offset)
                    .or_default()
                    .insert(entry.cmd_order, rebuilt);
            } else {
                counted_edits_by_crsa
                    .entry(entry.source_raw_offset)
                    .or_default()
                    .insert(entry.marker_offset, rebuilt);
            }
        }
    }

    let mut mod_key_set: HashSet<u32> = HashSet::new();
    mod_key_set.extend(msg_edits_by_crsa.keys().copied());
    mod_key_set.extend(counted_edits_by_crsa.keys().copied());
    let mut mod_keys: Vec<u32> = mod_key_set.into_iter().collect();
    mod_keys.sort_unstable();

    let mut replacements = Vec::with_capacity(mod_keys.len());
    let mut crsa_reports = HashMap::with_capacity(mod_keys.len());
    let mut total_in_place = 0usize;
    let mut total_appended = 0usize;
    let mut total_counted = 0usize;

    let empty_map: HashMap<usize, String> = HashMap::new();
    let mut base_file = File::open(base_ruo_path)?;

    for (idx, &src_raw) in mod_keys.iter().enumerate() {
        on_progress(BuildProgressEvent::RebuildingCrsa {
            current: idx + 1,
            total: mod_keys.len(),
        });
        let src_hex = format!("0x{:08X}", src_raw);
        let meta = manifest
            .crsa_by_hex
            .get(&src_hex)
            .ok_or_else(|| anyhow::anyhow!("CRsa {} missing from manifest", src_hex))?;
        let orig_rec = base_ruo
            .read_record_from_file(&mut base_file, src_raw)?
            .ok_or_else(|| anyhow::anyhow!("base RUO missing CRsa {}", src_hex))?;
        if sha256_hex(&orig_rec) != meta.record_sha256 {
            bail!(
                "CRsa {} SHA-256 drift detected (base RUO does not match manifest)",
                src_hex
            );
        }
        let msg_edits = msg_edits_by_crsa.get(&src_raw).unwrap_or(&empty_map);
        let counted_edits = counted_edits_by_crsa.get(&src_raw).unwrap_or(&empty_map);
        let (rebuilt_rec, crep) = rebuild_crsa(&orig_rec, msg_edits, counted_edits)
            .with_context(|| format!("rebuild CRsa {}", src_hex))?;

        total_in_place += crep.msg_in_place_edits;
        total_appended += crep.msg_appended_edits;
        total_counted += crep.counted_edits;
        crsa_reports.insert(src_hex, crep);
        replacements.push(RuoReplacement {
            source_raw_offset: src_raw,
            record: rebuilt_rec,
        });
    }
    drop(base_file);

    let ruo_rep = build_cumulative_ruo(
        base_ruo_path,
        output_ruo_path,
        manifest.unit_size,
        &replacements,
        |copied, total| {
            on_progress(BuildProgressEvent::WritingRuo { copied, total });
        },
    )
    .context("build cumulative RUO")?;

    on_progress(BuildProgressEvent::VerifyingOutput);

    // Final confirmation on the swapped output file
    let out_ruo = read_ruo_footer(output_ruo_path, manifest.unit_size)
        .context("re-open final output RUO")?;
    let mut out_file = File::open(output_ruo_path)?;
    for rep in &replacements {
        let disk_rec = out_ruo
            .read_record_from_file(&mut out_file, rep.source_raw_offset)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "output RUO missing replaced CRsa 0x{:08X}",
                    rep.source_raw_offset
                )
            })?;
        if disk_rec != rep.record {
            bail!(
                "output RUO CRsa 0x{:08X} bytes mismatch on disk",
                rep.source_raw_offset
            );
        }
        parse_crsa_record(&disk_rec).with_context(|| {
            format!(
                "output RUO CRsa 0x{:08X} failed final parse",
                rep.source_raw_offset
            )
        })?;
    }

    Ok(BuildSummary {
        base_ruo_path: base_ruo_path.to_string_lossy().into_owned(),
        output_ruo_path: output_ruo_path.to_string_lossy().into_owned(),
        modified_crsa_count: replacements.len(),
        total_changed_entries: changed_entries,
        total_in_place_msgs: total_in_place,
        total_appended_msgs: total_appended,
        total_counted_edits: total_counted,
        ruo_report: ruo_rep,
        crsa_reports,
        final_readback_ok: true,
    })
}
