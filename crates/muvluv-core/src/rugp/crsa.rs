use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::crypto::{
    decode_crsa_encrypted, decode_encrypted_generic, encode_crsa_encrypted, RIO_KEY,
};
use super::ici::decode_utf16le;

pub const CRSA_PREFIX: &[u8] = &[0x00, 0x05, 0x6e, 0x03, 0x01, 0x00];
pub const CVM_MSG3_DECL: &[u8] = &[0xff, 0xff, 0x15, 0x00, 0x05, 0x6a, 0xda, 0x31, 0x7d, 0xff];
pub const UNICODE_MARKER: &[u8] = &[0xff, 0xfe, 0xff];
pub const CRSA_HEADER_SIZE: usize = 11;

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn rfind_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

pub fn sha256_hex(b: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b);
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone)]
pub struct CrsaRecord {
    pub header: Vec<u8>,
    pub encrypted_header: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub raw_record: Vec<u8>,
    pub has_final_partial: bool,
    pub record_sha256: String,
    pub plaintext_sha256: String,
}

pub fn is_crsa_record(raw: &[u8]) -> bool {
    raw.len() >= CRSA_HEADER_SIZE + 8 && raw.starts_with(CRSA_PREFIX)
}

pub fn parse_crsa_record(raw: &[u8]) -> Result<CrsaRecord> {
    if !is_crsa_record(raw) {
        bail!("not a CRsa record (len={})", raw.len());
    }
    let (plain, consumed, has_partial) =
        decode_crsa_encrypted(&raw[CRSA_HEADER_SIZE..], RIO_KEY).context("decrypt CRsa")?;
    if CRSA_HEADER_SIZE + consumed != raw.len() {
        bail!(
            "CRsa extent mismatch: header+consumed={} != len={}",
            CRSA_HEADER_SIZE + consumed,
            raw.len()
        );
    }
    let record_sha256 = sha256_hex(raw);
    let plaintext_sha256 = sha256_hex(&plain);
    Ok(CrsaRecord {
        header: raw[..CRSA_HEADER_SIZE].to_vec(),
        encrypted_header: raw[CRSA_HEADER_SIZE..CRSA_HEADER_SIZE + 8].to_vec(),
        plaintext: plain,
        raw_record: raw.to_vec(),
        has_final_partial: has_partial,
        record_sha256,
        plaintext_sha256,
    })
}

pub fn encode_utf16le_no_nul(s: &str) -> Result<Vec<u8>> {
    if s.contains('\0') {
        bail!("embedded U+0000 NUL forbidden in rUGP text (prevents InternalError 8311)");
    }
    let mut out = Vec::with_capacity(s.len() * 2);
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(out)
}

pub fn decode_count(data: &[u8], offset: usize) -> Result<(u32, usize)> {
    if offset >= data.len() {
        bail!("count truncated at 0x{:X}", offset);
    }
    let s = data[offset];
    if s < 0xFF {
        return Ok((u32::from(s), 1));
    }
    if offset + 3 > data.len() {
        bail!("u16 count truncated at 0x{:X}", offset);
    }
    let m = u16::from_le_bytes(data[offset + 1..offset + 3].try_into().unwrap());
    if m < 0xFFFF {
        return Ok((u32::from(m), 3));
    }
    if offset + 7 > data.len() {
        bail!("u32 count truncated at 0x{:X}", offset);
    }
    let v = u32::from_le_bytes(data[offset + 3..offset + 7].try_into().unwrap());
    Ok((v, 7))
}

pub fn encode_count(v: u32) -> Vec<u8> {
    if v < 0xFF {
        return vec![v as u8];
    }
    if v < 0xFFFF {
        let mut out = Vec::with_capacity(3);
        out.push(0xFF);
        out.extend_from_slice(&(v as u16).to_le_bytes());
        return out;
    }
    let mut out = Vec::with_capacity(7);
    out.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
    out.extend_from_slice(&v.to_le_bytes());
    out
}

#[derive(Debug, Clone)]
pub struct CountedUnicodeString {
    pub marker_offset: usize,
    pub text_offset: usize,
    pub end_offset: usize,
    pub code_units: u32,
    pub text: String,
    pub kind: String,      // "pipe_ui" or "choice_or_ui"
    pub jp_prefix: String, // non-empty for pipe_ui (text before \|)
    pub en_text: String,   // active English text to translate
}

pub fn parse_counted_unicode_at(data: &[u8], marker_offset: usize) -> Result<CountedUnicodeString> {
    if marker_offset + 3 > data.len() || &data[marker_offset..marker_offset + 3] != UNICODE_MARKER {
        bail!("no FF FE FF marker at 0x{:X}", marker_offset);
    }
    let (units, len_sz) = decode_count(data, marker_offset + 3)?;
    let text_off = marker_offset + 3 + len_sz;
    let byte_len = (units as usize)
        .checked_mul(2)
        .ok_or_else(|| anyhow::anyhow!("counted unicode overflow at 0x{:X}", marker_offset))?;
    let end_off = text_off
        .checked_add(byte_len)
        .ok_or_else(|| anyhow::anyhow!("counted unicode overflow at 0x{:X}", marker_offset))?;
    if end_off > data.len() {
        bail!("counted unicode string truncated at 0x{:X}", marker_offset);
    }
    let raw = &data[text_off..end_off];
    for pair in raw.chunks_exact(2) {
        if pair[0] == 0 && pair[1] == 0 {
            bail!(
                "embedded NUL in counted unicode string at 0x{:X}",
                marker_offset
            );
        }
    }
    Ok(CountedUnicodeString {
        marker_offset,
        text_offset: text_off,
        end_offset: end_off,
        code_units: units,
        text: decode_utf16le(raw),
        kind: String::new(),
        jp_prefix: String::new(),
        en_text: String::new(),
    })
}

fn has_japanese(s: &str) -> bool {
    s.chars().any(|c| {
        let r = c as u32;
        (0x3040..=0x30FF).contains(&r) || (0x4E00..=0x9FFF).contains(&r)
    })
}

fn has_ascii_letter(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_alphabetic())
}

fn is_all_caps_ident(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut has_under_or_dig = false;
    for c in s.chars() {
        if c == '_' || c.is_ascii_digit() {
            has_under_or_dig = true;
        } else if !c.is_ascii_uppercase() {
            return false;
        }
    }
    has_under_or_dig || s.len() >= 3
}

fn is_skip_pipe_en(s: &str) -> bool {
    matches!(
        s.trim(),
        "" | "No.$NO" | "%Y/%m/%d" | "%H:%M:%S" | "$TR"
    )
}

/// Scans the command stream (strictly before pool_base-4 if pool_base > 0)
/// for all player-facing counted Unicode CStrings.
pub fn scan_translatable_counted_strings(
    plain: &[u8],
    pool_base: Option<usize>,
) -> Vec<CountedUnicodeString> {
    let mut limit = plain.len();
    if let Some(pb) = pool_base {
        if pb > 4 && pb - 4 < limit {
            limit = pb - 4;
        }
    }
    let mut out = Vec::new();
    let mut cur = 0usize;
    while cur < limit {
        let Some(idx) = find_bytes(&plain[cur..limit], UNICODE_MARKER) else {
            break;
        };
        let pos = cur + idx;
        cur = pos + 1;
        let Ok(mut cs) = parse_counted_unicode_at(plain, pos) else {
            continue;
        };
        if cs.code_units == 0 || cs.code_units > 10_000 || cs.end_offset > limit {
            continue;
        }
        if let Some((jp, en)) = cs.text.split_once(r"\|") {
            if is_skip_pipe_en(en) {
                continue;
            }
            cs.kind = "pipe_ui".to_string();
            cs.jp_prefix = jp.to_string();
            cs.en_text = en.to_string();
            out.push(cs);
            continue;
        }
        if cs.text == r"\A"
            || cs.text.starts_with("CTxtStDlg_")
            || cs.text == "muvluv16_steam"
        {
            continue;
        }
        if has_japanese(&cs.text) || !has_ascii_letter(&cs.text) {
            continue;
        }
        if is_all_caps_ident(&cs.text) && cs.text != "OK" {
            continue;
        }
        if pos >= 4 {
            let tag1 = u32::from_le_bytes(plain[pos - 4..pos].try_into().unwrap());
            if (tag1 & 3) == 1 {
                cs.kind = "choice_or_ui".to_string();
                cs.en_text = cs.text.clone();
                out.push(cs);
            }
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct VmMsgCmd {
    pub order: usize,
    pub obj_offset: usize,
    pub body_offset: usize,
    pub end_offset: usize,
    pub class_ref: u16,
    pub cmd_offset: u32,
    pub flags: u32,
    pub group: u16,
    pub index: u16,
    pub first: Vec<[u32; 3]>,
    pub second: Vec<[u8; 10]>,
}

fn parse_msg_body(payload: &[u8], body_off: usize) -> Option<VmMsgCmd> {
    const FIXED_SIZE: usize = 14;
    if body_off + FIXED_SIZE > payload.len() {
        return None;
    }
    let cmd = u32::from_le_bytes(payload[body_off..body_off + 4].try_into().unwrap());
    let flags = u32::from_le_bytes(payload[body_off + 4..body_off + 8].try_into().unwrap());
    let group = u16::from_le_bytes(payload[body_off + 8..body_off + 10].try_into().unwrap());
    let index = u16::from_le_bytes(payload[body_off + 10..body_off + 12].try_into().unwrap());
    let first_count = payload[body_off + 12] as usize;
    let second_count = payload[body_off + 13] as usize;
    if cmd % 4 != 0 || cmd > 0x4000_0000 || group != 1 || first_count != 2 || second_count > 32 {
        return None;
    }
    let first_base = body_off + FIXED_SIZE;
    let second_base = first_base + first_count * 12;
    let end_off = second_base + second_count * 10;
    if end_off > payload.len() {
        return None;
    }

    let mut first = Vec::with_capacity(first_count);
    for i in 0..first_count {
        let o = first_base + i * 12;
        first.push([
            u32::from_le_bytes(payload[o..o + 4].try_into().unwrap()),
            u32::from_le_bytes(payload[o + 4..o + 8].try_into().unwrap()),
            u32::from_le_bytes(payload[o + 8..o + 12].try_into().unwrap()),
        ]);
    }
    let src_idx = first[0][0];
    let trn_idx = first[1][0];
    if (src_idx as usize) * 2 >= payload.len() || (trn_idx as usize) * 2 >= payload.len() {
        return None;
    }
    if src_idx != 0 && trn_idx != 0 && src_idx >= trn_idx {
        return None;
    }

    let mut second = Vec::with_capacity(second_count);
    for i in 0..second_count {
        let mut arr = [0u8; 10];
        arr.copy_from_slice(&payload[second_base + i * 10..second_base + (i + 1) * 10]);
        second.push(arr);
    }

    Some(VmMsgCmd {
        order: 0,
        obj_offset: 0,
        body_offset: body_off,
        end_offset: end_off,
        class_ref: 0,
        cmd_offset: cmd,
        flags,
        group,
        index,
        first,
        second,
    })
}

pub fn find_vm_msg_commands(payload: &[u8]) -> Result<Vec<VmMsgCmd>> {
    let Some(decl_off) = find_bytes(payload, CVM_MSG3_DECL) else {
        return Ok(Vec::new());
    };
    let mut first = parse_msg_body(payload, decl_off + CVM_MSG3_DECL.len())
        .ok_or_else(|| anyhow::anyhow!("invalid first CVmMsg3 body at 0x{:X}", decl_off))?;
    first.obj_offset = decl_off;

    let mut candidates: HashMap<u16, Vec<VmMsgCmd>> = HashMap::new();
    let start_scan = first.end_offset + 2;
    if payload.len() >= 38 && start_scan <= payload.len() - 38 {
        for body_off in start_scan..=(payload.len() - 38) {
            let cref = u16::from_le_bytes(payload[body_off - 2..body_off].try_into().unwrap());
            if (cref & 0x8000) == 0 || cref == 0xFFFF {
                continue;
            }
            if let Some(mut c) = parse_msg_body(payload, body_off) {
                c.obj_offset = body_off - 2;
                c.class_ref = cref;
                candidates.entry(cref).or_default().push(c);
            }
        }
    }

    let mut matching: Vec<Vec<VmMsgCmd>> = Vec::new();
    for (_cref, mut list) in candidates {
        list.sort_by_key(|c| c.obj_offset);
        let mut ok = first.cmd_offset < list[0].cmd_offset;
        for w in list.windows(2) {
            if !ok {
                break;
            }
            if w[0].cmd_offset >= w[1].cmd_offset {
                ok = false;
            }
        }
        if ok {
            matching.push(list);
        }
    }

    let mut out = if matching.is_empty() {
        vec![first]
    } else {
        let best = matching.iter().map(Vec::len).max().unwrap_or(0);
        let mut best_list: Vec<Vec<VmMsgCmd>> =
            matching.into_iter().filter(|m| m.len() == best).collect();
        if best_list.len() != 1 {
            bail!(
                "ambiguous CVmMsg3 class refs: {} tied with len {}",
                best_list.len(),
                best
            );
        }
        let mut v = Vec::with_capacity(1 + best);
        v.push(first);
        v.extend(best_list.pop().unwrap());
        v
    };

    for (i, c) in out.iter_mut().enumerate() {
        c.order = i;
    }
    Ok(out)
}

pub fn read_pool_slot(payload: &[u8], base: usize, units: u32, idx: u32) -> Option<(String, usize)> {
    let pool_end = base + (units as usize) * 2;
    let off = base + (idx as usize) * 2;
    if off < base || off >= pool_end || pool_end > payload.len() {
        return None;
    }
    let mut cur = off;
    while cur + 2 <= pool_end {
        if payload[cur] == 0 && payload[cur + 1] == 0 {
            return Some((decode_utf16le(&payload[off..cur]), cur + 2 - off));
        }
        cur += 2;
    }
    None
}

fn is_valid_pool_unit(u: u16) -> bool {
    if u == 0 || u >= 0x20 {
        return true;
    }
    matches!(u, 1 | 2 | 3 | 5 | 9 | 10 | 12 | 13 | 16)
}

pub fn infer_pool_base(payload: &[u8], cmds: &[VmMsgCmd]) -> Result<Option<(usize, u32)>> {
    if cmds.is_empty() {
        return Ok(None);
    }
    let mut max_idx = 0u32;
    let mut has_any = false;
    let mut max_cmd_end = 0usize;
    for c in cmds {
        if c.end_offset > max_cmd_end {
            max_cmd_end = c.end_offset;
        }
        for lang in 0..2 {
            for f in 0..3 {
                if c.first[lang][f] > max_idx {
                    max_idx = c.first[lang][f];
                    has_any = true;
                }
            }
        }
    }
    if !has_any {
        return Ok(None);
    }
    let min_units = max_idx + 1;
    let mut start_base = max_cmd_end + 4;
    if let Some(last_cmd_decl) = rfind_bytes(payload, &[0xff, 0xff, 0x15, 0x00]) {
        if last_cmd_decl + 14 > start_base {
            start_base = last_cmd_decl + 14;
        }
    }

    let min_bytes = (min_units as usize) * 2;
    if payload.len() < min_bytes || start_base > payload.len() - min_bytes {
        bail!("expected 1 strict pool base, found 0");
    }

    let mut cands = Vec::new();
    for base in start_base..=(payload.len() - min_bytes) {
        let units = u32::from_le_bytes(payload[base - 4..base].try_into().unwrap());
        if units < min_units || base + (units as usize) * 2 > payload.len() {
            continue;
        }
        if payload[base] != 0 || payload[base + 1] != 0 {
            continue;
        }
        let pool_end = base + (units as usize) * 2;
        if payload[pool_end - 2] != 0 || payload[pool_end - 1] != 0 {
            continue;
        }
        let mut all_valid_units = true;
        for pair in payload[base..pool_end].chunks_exact(2) {
            let u = u16::from_le_bytes([pair[0], pair[1]]);
            if (0xD800..=0xDFFF).contains(&u) {
                continue;
            }
            if !is_valid_pool_unit(u) {
                all_valid_units = false;
                break;
            }
        }
        if !all_valid_units {
            continue;
        }

        let mut ok = true;
        'cmd_check: for c in cmds {
            for lang in 0..2 {
                let idx = c.first[lang][0];
                if idx == 0 {
                    continue;
                }
                let off = base + (idx as usize) * 2;
                if payload[off - 2] != 0 || payload[off - 1] != 0 {
                    ok = false;
                    break 'cmd_check;
                }
                match read_pool_slot(payload, base, units, idx) {
                    Some((s, _)) if !s.is_empty() => {}
                    _ => {
                        ok = false;
                        break 'cmd_check;
                    }
                }
            }
        }
        if ok {
            cands.push(base);
        }
    }

    if cands.len() != 1 {
        bail!(
            "expected 1 strict pool base, found {}: {:?}",
            cands.len(),
            cands
        );
    }
    let chosen = cands[0];
    let units = u32::from_le_bytes(payload[chosen - 4..chosen].try_into().unwrap());
    Ok(Some((chosen, units)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrsaRebuildReport {
    pub plain_len_before: usize,
    pub plain_len_after: usize,
    pub record_len_before: usize,
    pub record_len_after: usize,
    pub pool_units_before: u32,
    pub pool_units_after: u32,
    pub msg_in_place_edits: usize,
    pub msg_appended_edits: usize,
    pub counted_edits: usize,
    pub readback_verified: bool,
    pub record_sha256_after: String,
}

/// Applies CVmMsg3 EN slot edits (by 0-based cmdOrder) and counted Unicode CString edits
/// (by original MarkerOffset) to orig_raw, re-encrypts with full checksums, and performs strict readback verification.
pub fn rebuild_crsa(
    orig_raw: &[u8],
    msg_edits: &HashMap<usize, String>,
    counted_edits: &HashMap<usize, String>,
) -> Result<(Vec<u8>, CrsaRebuildReport)> {
    let orig = parse_crsa_record(orig_raw)?;

    // Verify unchanged identity re-encode first!
    let ident_enc = encode_crsa_encrypted(
        &orig.plaintext,
        RIO_KEY,
        &orig.encrypted_header,
        orig.has_final_partial || orig.plaintext.len() % 0x20 != 0,
    )
    .context("identity re-encode failed")?;
    if ident_enc != orig_raw[CRSA_HEADER_SIZE..] {
        bail!("identity CRsa re-encode was not byte-identical");
    }

    let mut plain = orig.plaintext.clone();
    let mut orig_cmds: Vec<VmMsgCmd> = Vec::new();
    let mut orig_pool_base: Option<usize> = None;
    let mut orig_pool_units: u32 = 0;
    let mut orig_suffix: Vec<u8> = Vec::new();
    let mut orig_jp_texts: HashMap<usize, String> = HashMap::new();
    let mut orig_en_texts: HashMap<usize, String> = HashMap::new();

    if find_bytes(&plain, CVM_MSG3_DECL).is_some() {
        orig_cmds = find_vm_msg_commands(&plain).context("find CVmMsg3")?;
        if let Some((pb, pu)) = infer_pool_base(&plain, &orig_cmds).context("infer pool base")? {
            orig_pool_base = Some(pb);
            orig_pool_units = pu;
            let orig_pool_end = pb + (pu as usize) * 2;
            orig_suffix = plain[orig_pool_end..].to_vec();
            for (i, c) in orig_cmds.iter().enumerate() {
                if c.first[0][0] != 0 {
                    let (s, _) = read_pool_slot(&plain, pb, pu, c.first[0][0])
                        .ok_or_else(|| anyhow::anyhow!("failed reading JP slot for cmd {}", i))?;
                    orig_jp_texts.insert(i, s);
                }
                if c.first[1][0] != 0 {
                    let (s, _) = read_pool_slot(&plain, pb, pu, c.first[1][0])
                        .ok_or_else(|| anyhow::anyhow!("failed reading EN slot for cmd {}", i))?;
                    orig_en_texts.insert(i, s);
                }
            }
        }
    }

    // Step 1: Apply CVmMsg3 pool edits
    let mut in_place_count = 0usize;
    let mut appended_count = 0usize;
    let mut new_pool_units = orig_pool_units;

    if !msg_edits.is_empty() {
        let pb = orig_pool_base
            .ok_or_else(|| anyhow::anyhow!("msgEdits provided but CRsa has no CVmMsg3 pool"))?;
        let mut en_ref_count: HashMap<u32, usize> = HashMap::new();
        for c in &orig_cmds {
            if c.first[1][0] != 0 {
                *en_ref_count.entry(c.first[1][0]).or_insert(0) += 1;
            }
        }
        let orig_pool_end = pb + (orig_pool_units as usize) * 2;
        let mut new_prefix = plain[..pb - 4].to_vec();
        let mut new_pool = plain[pb..orig_pool_end].to_vec();

        let mut orders: Vec<usize> = msg_edits.keys().copied().collect();
        orders.sort_unstable();

        for ord in orders {
            if ord >= orig_cmds.len() {
                bail!("cmdOrder {} out of range [0..{})", ord, orig_cmds.len());
            }
            let new_text = &msg_edits[&ord];
            let mut new_slot = encode_utf16le_no_nul(new_text)
                .with_context(|| format!("cmdOrder {}", ord))?;
            new_slot.extend_from_slice(&[0x00, 0x00]);

            let c = &orig_cmds[ord];
            let en_idx = c.first[1][0];

            let mut wrote_in_place = false;
            if en_idx != 0 && en_ref_count.get(&en_idx).copied().unwrap_or(0) == 1 {
                if let Some((_, orig_slot_bytes)) =
                    read_pool_slot(&plain, pb, orig_pool_units, en_idx)
                {
                    if new_slot.len() <= orig_slot_bytes {
                        let start = (en_idx as usize) * 2;
                        new_pool[start..start + new_slot.len()].copy_from_slice(&new_slot);
                        for b in &mut new_pool[start + new_slot.len()..start + orig_slot_bytes] {
                            *b = 0;
                        }
                        wrote_in_place = true;
                        in_place_count += 1;
                    }
                }
            }
            if !wrote_in_place {
                if new_pool.len() % 2 != 0 {
                    bail!("pool lost UTF-16 alignment");
                }
                let new_idx = u32::try_from(new_pool.len() / 2)?;
                new_pool.extend_from_slice(&new_slot);
                let idx_field_off = c.body_offset + 14 + 12;
                if idx_field_off + 4 > new_prefix.len() {
                    bail!("cmdOrder {} index field exceeds prefix", ord);
                }
                new_prefix[idx_field_off..idx_field_off + 4]
                    .copy_from_slice(&new_idx.to_le_bytes());
                appended_count += 1;
            }
        }

        new_pool_units = u32::try_from(new_pool.len() / 2)
            .map_err(|_| anyhow::anyhow!("rebuilt pool exceeds uint32 code units"))?;

        let mut rebuilt = Vec::with_capacity(new_prefix.len() + 4 + new_pool.len() + orig_suffix.len());
        rebuilt.extend_from_slice(&new_prefix);
        rebuilt.extend_from_slice(&new_pool_units.to_le_bytes());
        rebuilt.extend_from_slice(&new_pool);
        rebuilt.extend_from_slice(&orig_suffix);
        plain = rebuilt;
    }

    // Step 2: Apply counted Unicode CString edits in reverse offset order
    struct ShiftedCheck {
        shifted_off: usize,
        target: String,
    }
    let mut counted_checks: Vec<ShiftedCheck> = Vec::new();

    if !counted_edits.is_empty() {
        let mut offsets: Vec<usize> = counted_edits.keys().copied().collect();
        offsets.sort_unstable();

        let mut orig_parsed: HashMap<usize, CountedUnicodeString> =
            HashMap::with_capacity(offsets.len());
        for (i, &off) in offsets.iter().enumerate() {
            if let Some(pb) = orig_pool_base {
                if pb > 0 && off >= pb - 4 {
                    bail!(
                        "counted CString offset 0x{:X} is not before poolBase-4 (0x{:X})",
                        off,
                        pb - 4
                    );
                }
            }
            let cs = parse_counted_unicode_at(&plain, off)
                .with_context(|| format!("parse counted CString at 0x{:X}", off))?;
            if let Some(pb) = orig_pool_base {
                if pb > 0 && cs.end_offset > pb - 4 {
                    bail!("counted CString at 0x{:X} overlaps pool header", off);
                }
            }
            if i > 0 && off < orig_parsed[&offsets[i - 1]].end_offset {
                bail!(
                    "overlapping counted CStrings at 0x{:X} and 0x{:X}",
                    offsets[i - 1],
                    off
                );
            }
            orig_parsed.insert(off, cs);
        }

        let mut cum_delta: isize = 0;
        for &off in &offsets {
            let cs = &orig_parsed[&off];
            let new_text = &counted_edits[&off];
            let raw_utf16 = encode_utf16le_no_nul(new_text)
                .with_context(|| format!("counted CString at 0x{:X}", off))?;
            let field_len = 3 + encode_count((raw_utf16.len() / 2) as u32).len() + raw_utf16.len();
            let old_len = cs.end_offset - cs.marker_offset;
            counted_checks.push(ShiftedCheck {
                shifted_off: (off as isize + cum_delta) as usize,
                target: new_text.clone(),
            });
            cum_delta += field_len as isize - old_len as isize;
        }

        for &off in offsets.iter().rev() {
            let cs = &orig_parsed[&off];
            let new_text = &counted_edits[&off];
            let raw_utf16 = encode_utf16le_no_nul(new_text)?;
            let count_bytes = encode_count((raw_utf16.len() / 2) as u32);
            let mut replacement = Vec::with_capacity(3 + count_bytes.len() + raw_utf16.len());
            replacement.extend_from_slice(UNICODE_MARKER);
            replacement.extend_from_slice(&count_bytes);
            replacement.extend_from_slice(&raw_utf16);

            let mut rebuilt =
                Vec::with_capacity(plain.len() - (cs.end_offset - cs.marker_offset) + replacement.len());
            rebuilt.extend_from_slice(&plain[..cs.marker_offset]);
            rebuilt.extend_from_slice(&replacement);
            rebuilt.extend_from_slice(&plain[cs.end_offset..]);
            plain = rebuilt;
        }
    }

    // Step 3: Re-encrypt with full chunk checksums
    let reenc = encode_crsa_encrypted(&plain, RIO_KEY, &orig.encrypted_header, true)
        .context("re-encrypt CRsa")?;
    let mut rebuilt_rec = Vec::with_capacity(CRSA_HEADER_SIZE + reenc.len());
    rebuilt_rec.extend_from_slice(&orig.header);
    rebuilt_rec.extend_from_slice(&reenc);

    // Step 4: MANDATORY READBACK VERIFICATION
    let readback = parse_crsa_record(&rebuilt_rec).context("strict readback failed")?;
    if readback.plaintext != plain {
        bail!("strict readback plaintext mismatch");
    }
    let (generic_plain, _) = decode_encrypted_generic(&rebuilt_rec[CRSA_HEADER_SIZE..], RIO_KEY)
        .context("GARbro-compatible generic readback failed")?;
    if generic_plain != plain {
        bail!("GARbro-compatible generic readback plaintext mismatch");
    }

    for chk in &counted_checks {
        let cs = parse_counted_unicode_at(&readback.plaintext, chk.shifted_off).with_context(
            || {
                format!(
                    "counted CString readback failed at shifted 0x{:X}",
                    chk.shifted_off
                )
            },
        )?;
        if cs.text != chk.target {
            bail!(
                "counted CString readback mismatch at 0x{:X}: got {:?} want {:?}",
                chk.shifted_off,
                cs.text,
                chk.target
            );
        }
    }

    if !orig_cmds.is_empty() {
        let new_cmds = find_vm_msg_commands(&readback.plaintext)
            .context("CVmMsg3 readback parse failed")?;
        if new_cmds.len() != orig_cmds.len() {
            bail!(
                "CVmMsg3 command count changed: {} -> {}",
                orig_cmds.len(),
                new_cmds.len()
            );
        }
        let (new_pool_base, parsed_units) = infer_pool_base(&readback.plaintext, &new_cmds)
            .context("CVmMsg3 readback pool inference failed")?
            .ok_or_else(|| anyhow::anyhow!("CVmMsg3 readback missing pool"))?;
        if parsed_units != new_pool_units {
            bail!(
                "CVmMsg3 pool units mismatch: {} != {}",
                parsed_units,
                new_pool_units
            );
        }
        let new_pool_end = new_pool_base + (parsed_units as usize) * 2;
        if readback.plaintext[new_pool_end..] != orig_suffix[..] {
            bail!("CRsa suffix after pool changed during rebuild");
        }
        for (i, c) in new_cmds.iter().enumerate() {
            if let Some(orig_jp) = orig_jp_texts.get(&i) {
                let Some((got_jp, _)) =
                    read_pool_slot(&readback.plaintext, new_pool_base, parsed_units, c.first[0][0])
                else {
                    bail!("cmd {} JP slot corrupted on readback", i);
                };
                if &got_jp != orig_jp {
                    bail!("cmd {} JP slot corrupted on readback", i);
                }
            }
            if let Some(want_en) = msg_edits.get(&i) {
                let Some((got_en, _)) =
                    read_pool_slot(&readback.plaintext, new_pool_base, parsed_units, c.first[1][0])
                else {
                    bail!("cmd {} edited EN readback missing", i);
                };
                if &got_en != want_en {
                    bail!(
                        "cmd {} edited EN readback mismatch: got {:?} want {:?}",
                        i,
                        got_en,
                        want_en
                    );
                }
            } else if let Some(orig_en) = orig_en_texts.get(&i) {
                let Some((got_en, _)) =
                    read_pool_slot(&readback.plaintext, new_pool_base, parsed_units, c.first[1][0])
                else {
                    bail!("cmd {} unmodified EN slot missing on readback", i);
                };
                if &got_en != orig_en {
                    bail!("cmd {} unmodified EN slot changed on readback", i);
                }
            }
        }
    }

    let report = CrsaRebuildReport {
        plain_len_before: orig.plaintext.len(),
        plain_len_after: plain.len(),
        record_len_before: orig_raw.len(),
        record_len_after: rebuilt_rec.len(),
        pool_units_before: orig_pool_units,
        pool_units_after: new_pool_units,
        msg_in_place_edits: in_place_count,
        msg_appended_edits: appended_count,
        counted_edits: counted_edits.len(),
        readback_verified: true,
        record_sha256_after: readback.record_sha256,
    };

    Ok((rebuilt_rec, report))
}
