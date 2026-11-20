use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::backup::backup_dir;
use crate::metadata::sha256_file;
use crate::EXPECTED_EXE_SHA256;

pub const EXE_CONTEXT_OFFSET: usize = 0x1DB9FB;
pub const EXE_PATCH_OFFSET: usize = 0x1DBA02;
pub const EXE_ORIGINAL_CONTEXT: &[u8; 13] = &[
    0x0F, 0xB7, 0x40, 0x1E, 0x83, 0xE0, 0x10, 0x75, 0x04, 0xB3, 0x01, 0xEB, 0x02,
];
pub const EXE_PATCHED_CONTEXT: &[u8; 13] = &[
    0x0F, 0xB7, 0x40, 0x1E, 0x83, 0xE0, 0x10, 0x90, 0x90, 0xB3, 0x01, 0xEB, 0x02,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExePatchOutcome {
    Applied,
    AlreadyApplied,
    SkippedWithWarning(String),
}

pub fn is_exe_5rf_patched(game_dir: &Path) -> bool {
    let exe_path = game_dir.join("muvluv16.exe");
    let Ok(bytes) = fs::read(exe_path) else {
        return false;
    };
    if bytes.len() < EXE_CONTEXT_OFFSET + EXE_PATCHED_CONTEXT.len() {
        return false;
    }
    &bytes[EXE_CONTEXT_OFFSET..EXE_CONTEXT_OFFSET + 13] == EXE_PATCHED_CONTEXT
}

/// Applies the optional `.5RF` GDI fallback patch (`75 04` -> `90 90` at file offset `0x1DBA02`).
/// Always verifies SHA-256 + 13-byte context and creates permanent `_ptbr_backup/muvluv16.exe.orig`
/// before touching `muvluv16.exe`. Never corrupts the executable if anything does not match.
pub fn apply_5rf_gdi_fallback_patch(game_dir: &Path) -> Result<ExePatchOutcome> {
    let exe_path = game_dir.join("muvluv16.exe");
    let bdir = backup_dir(game_dir);
    let exe_orig_path = bdir.join("muvluv16.exe.orig");

    if !exe_path.is_file() {
        return Ok(ExePatchOutcome::SkippedWithWarning(
            "muvluv16.exe não encontrado para o patch opcional .5RF.".to_string(),
        ));
    }

    let mut bytes = fs::read(&exe_path).context("ler muvluv16.exe")?;
    if bytes.len() < EXE_CONTEXT_OFFSET + 13 {
        return Ok(ExePatchOutcome::SkippedWithWarning(
            "muvluv16.exe tem tamanho inesperado; patch opcional .5RF ignorado com segurança."
                .to_string(),
        ));
    }

    let ctx = &bytes[EXE_CONTEXT_OFFSET..EXE_CONTEXT_OFFSET + 13];
    if ctx == EXE_PATCHED_CONTEXT && exe_orig_path.is_file() {
        return Ok(ExePatchOutcome::AlreadyApplied);
    }

    let current_sha = sha256_file(&exe_path)?;
    if !current_sha.eq_ignore_ascii_case(EXPECTED_EXE_SHA256) {
        return Ok(ExePatchOutcome::SkippedWithWarning(format!(
            "SHA-256 de muvluv16.exe ({}) não corresponde à build Steam 2016 esperada; patch opcional .5RF abortado sem alterar o .exe.",
            &current_sha[..12]
        )));
    }

    if ctx != EXE_ORIGINAL_CONTEXT {
        return Ok(ExePatchOutcome::SkippedWithWarning(
            "Bytes de contexto em 0x1DB9FB..0x1DBA07 não conferem; patch opcional .5RF abortado sem alterar o .exe."
                .to_string(),
        ));
    }

    fs::create_dir_all(&bdir)?;
    if !exe_orig_path.exists() {
        fs::copy(&exe_path, &exe_orig_path).context("criar backup muvluv16.exe.orig")?;
    }

    // Apply exact 2-byte NOP patch at 0x1DBA02..0x1DBA04
    bytes[EXE_PATCH_OFFSET] = 0x90;
    bytes[EXE_PATCH_OFFSET + 1] = 0x90;

    let tmp_exe = game_dir.join("muvluv16.exe.ptbr.tmp");
    fs::write(&tmp_exe, &bytes).context("gravar muvluv16.exe temporário")?;
    // Verify written temp file
    let check = fs::read(&tmp_exe)?;
    if &check[EXE_CONTEXT_OFFSET..EXE_CONTEXT_OFFSET + 13] != EXE_PATCHED_CONTEXT {
        let _ = fs::remove_file(&tmp_exe);
        bail!("verificação do muvluv16.exe temporário falhou");
    }
    fs::rename(&tmp_exe, &exe_path).context("substituir muvluv16.exe")?;

    Ok(ExePatchOutcome::Applied)
}

/// Restores `muvluv16.exe` from `_ptbr_backup/muvluv16.exe.orig` if present.
pub fn restore_original_exe(game_dir: &Path) -> Result<bool> {
    let exe_path = game_dir.join("muvluv16.exe");
    let exe_orig_path = backup_dir(game_dir).join("muvluv16.exe.orig");
    if !exe_orig_path.is_file() {
        return Ok(false);
    }
    let tmp_exe = game_dir.join("muvluv16.exe.restore.tmp");
    fs::copy(&exe_orig_path, &tmp_exe).context("copiar muvluv16.exe.orig")?;
    fs::rename(&tmp_exe, &exe_path).context("restaurar muvluv16.exe")?;
    Ok(true)
}
