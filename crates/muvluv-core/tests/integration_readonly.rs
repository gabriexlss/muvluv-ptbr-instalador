use std::collections::HashMap;
use std::fs::{self, File};
use std::path::Path;

use muvluv_core::exe_patch::{
    apply_5rf_gdi_fallback_patch, is_exe_5rf_patched, restore_original_exe, ExePatchOutcome,
};
use muvluv_core::metadata::{load_translation_metadata, sha256_file, validate_package_hashes};
use muvluv_core::pipeline::{build_from_manifest, extract_manifest_in_memory};
use muvluv_core::rugp::crsa::{is_crsa_record, parse_crsa_record, rebuild_crsa};
use muvluv_core::rugp::ruo::read_ruo_footer;
use muvluv_core::{EXPECTED_BASE_RUO_SHA256, EXPECTED_BASE_RUO_SIZE, EXPECTED_EXE_SHA256};

const GAME_DIR: &str = "/mnt/d/Jogos/Muv-Luv";
const ORIG_RUO: &str = "/mnt/d/Jogos/Muv-Luv/_ptbr_pipeline/backups/muvluv16.rio.drcruo1.orig";
const REPO_DIR: &str = "/mnt/d/Jogos/Muv-Luv/_ptbr_pipeline/repo_traducao";

#[test]
fn test_roundtrip_all_253_crsa() {
    let orig_ruo = Path::new(ORIG_RUO);
    if !orig_ruo.is_file() {
        eprintln!(
            "Skipping test_roundtrip_all_253_crsa: {} not found",
            ORIG_RUO
        );
        return;
    }

    let meta = fs::metadata(orig_ruo).expect("stat orig ruo");
    assert_eq!(meta.len(), EXPECTED_BASE_RUO_SIZE);

    let ruo = read_ruo_footer(orig_ruo, 2).expect("read RUO footer");
    assert_eq!(ruo.redirects.len(), 458);

    let empty_msg = HashMap::new();
    let empty_counted = HashMap::new();

    let mut f = File::open(orig_ruo).expect("open orig ruo");
    let mut total_crsa = 0usize;
    let mut exact = 0usize;

    for red in &ruo.redirects {
        let raw = ruo
            .read_record_from_file(&mut f, red.source_raw_offset)
            .expect("read record")
            .expect("record exists");
        if !is_crsa_record(&raw) {
            continue;
        }
        total_crsa += 1;
        let (rebuilt, report) =
            rebuild_crsa(&raw, &empty_msg, &empty_counted).expect("identity rebuild_crsa");
        assert!(report.readback_verified);
        assert_eq!(
            rebuilt, raw,
            "byte mismatch on CRsa 0x{:08X}",
            red.source_raw_offset
        );
        exact += 1;
    }

    assert_eq!(total_crsa, 253, "expected 253 CRsa objects");
    assert_eq!(exact, 253, "all 253 CRsa objects must match byte-for-byte");
}

#[test]
fn test_extract_matches_translation_repo() {
    let game_dir = Path::new(GAME_DIR);
    let orig_ruo = Path::new(ORIG_RUO);
    let repo_dir = Path::new(REPO_DIR);
    if !game_dir.is_dir() || !orig_ruo.is_file() || !repo_dir.is_dir() {
        eprintln!("Skipping test_extract_matches_translation_repo: reference paths missing");
        return;
    }

    let meta = load_translation_metadata(repo_dir).expect("load metadata.json");
    assert_eq!(meta.file_count, 102);
    assert_eq!(meta.total_entries, 63_242);

    let (manifest, summary) =
        extract_manifest_in_memory(game_dir, Some(orig_ruo), |_, _| {}).expect("extract manifest");

    assert_eq!(summary.total_crsa_records, 253);
    assert_eq!(summary.exported_files, 102);
    assert_eq!(summary.total_entries, 63_242);
    assert_eq!(manifest.files.len(), meta.files.len());

    for (mf, expected) in manifest.files.iter().zip(meta.files.iter()) {
        assert_eq!(mf.filename, expected.filename, "filename mismatch");
        assert_eq!(
            mf.entry_count, expected.entry_count,
            "entry count mismatch in {}",
            mf.filename
        );
    }
}

#[test]
fn test_full_build_and_readback() {
    let game_dir = Path::new(GAME_DIR);
    let orig_ruo = Path::new(ORIG_RUO);
    let repo_dir = Path::new(REPO_DIR);
    if !game_dir.is_dir() || !orig_ruo.is_file() || !repo_dir.is_dir() {
        eprintln!("Skipping test_full_build_and_readback: reference paths missing");
        return;
    }

    let meta = load_translation_metadata(repo_dir).expect("load metadata.json");
    let trans_dir = validate_package_hashes(repo_dir, &meta, |_, _, _| {})
        .expect("validate all 102 translation JSON SHA-256 hashes");

    let (manifest, _) =
        extract_manifest_in_memory(game_dir, Some(orig_ruo), |_, _| {}).expect("extract manifest");

    let out_path = Path::new("/tmp/test_muvluv16.rio.drcruo1");
    if out_path.exists() {
        let _ = fs::remove_file(out_path);
    }

    let summary =
        build_from_manifest(orig_ruo, &manifest, &trans_dir, out_path, true, |_| {})
            .expect("full RUO build");

    assert_eq!(summary.ruo_report.final_redirect_count, 458);
    assert_eq!(summary.modified_crsa_count, 108);
    assert_eq!(summary.total_changed_entries, 55_343);
    assert!(summary.final_readback_ok);

    // Independent readback check of ALL 253 CRsa records in the built file
    let built_ruo = read_ruo_footer(out_path, 2).expect("re-open built RUO");
    assert_eq!(built_ruo.redirects.len(), 458);
    let mut f = File::open(out_path).expect("open built RUO");
    let mut crsa_ok = 0usize;
    for red in &built_ruo.redirects {
        let raw = built_ruo
            .read_record_from_file(&mut f, red.source_raw_offset)
            .expect("read record")
            .expect("exists");
        if is_crsa_record(&raw) {
            parse_crsa_record(&raw).expect("parse rebuilt CRsa");
            crsa_ok += 1;
        }
    }
    assert_eq!(crsa_ok, 253);

    // Clean up large temp file
    let _ = fs::remove_file(out_path);
}

#[test]
fn test_exe_5rf_patch_and_restore_in_tmp() {
    let orig_exe = Path::new(GAME_DIR).join("muvluv16.exe");
    if !orig_exe.is_file() {
        eprintln!("Skipping test_exe_5rf_patch_and_restore_in_tmp: muvluv16.exe not found");
        return;
    }

    let tmp_dir = Path::new("/tmp/test_muvluv_exe_patch");
    let _ = fs::remove_dir_all(tmp_dir);
    fs::create_dir_all(tmp_dir).expect("mkdir tmp");
    let tmp_exe = tmp_dir.join("muvluv16.exe");
    fs::copy(&orig_exe, &tmp_exe).expect("copy exe to tmp");

    assert_eq!(sha256_file(&tmp_exe).unwrap(), EXPECTED_EXE_SHA256);
    assert!(!is_exe_5rf_patched(tmp_dir));

    let outcome = apply_5rf_gdi_fallback_patch(tmp_dir).expect("apply patch");
    assert_eq!(outcome, ExePatchOutcome::Applied);
    assert!(is_exe_5rf_patched(tmp_dir));
    assert!(tmp_dir.join("_ptbr_backup/muvluv16.exe.orig").is_file());

    // Idempotent second call
    let outcome2 = apply_5rf_gdi_fallback_patch(tmp_dir).expect("re-apply patch");
    assert_eq!(outcome2, ExePatchOutcome::AlreadyApplied);

    // Restore original
    let restored = restore_original_exe(tmp_dir).expect("restore exe");
    assert!(restored);
    assert!(!is_exe_5rf_patched(tmp_dir));
    assert_eq!(sha256_file(&tmp_exe).unwrap(), EXPECTED_EXE_SHA256);

    // Confirm base RUO constant is sane
    assert_eq!(EXPECTED_BASE_RUO_SHA256.len(), 64);

    let _ = fs::remove_dir_all(tmp_dir);
}
