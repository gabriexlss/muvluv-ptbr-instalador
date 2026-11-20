use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::exe_patch::{is_exe_5rf_patched, restore_original_exe};
use crate::metadata::sha256_file;
use crate::{EXPECTED_BASE_RUO_SHA256, EXPECTED_BASE_RUO_SIZE};

pub const BACKUP_DIR_NAME: &str = "_ptbr_backup";
pub const ORIG_RUO_NAME: &str = "muvluv16.rio.drcruo1.orig";
pub const ORIG_EXE_NAME: &str = "muvluv16.exe.orig";
pub const INSTALLED_META_NAME: &str = "ptbr_installed.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledState {
    pub version: String,
    pub installed_at: String,
    pub compiled_ruo_sha256: String,
    pub compiled_ruo_size: u64,
    pub exe_5rf_patched: bool,
    pub source_label: String,
}

pub fn backup_dir(game_dir: &Path) -> PathBuf {
    game_dir.join(BACKUP_DIR_NAME)
}

pub fn orig_ruo_backup_path(game_dir: &Path) -> PathBuf {
    backup_dir(game_dir).join(ORIG_RUO_NAME)
}

pub fn installed_state_path(game_dir: &Path) -> PathBuf {
    backup_dir(game_dir).join(INSTALLED_META_NAME)
}

pub fn read_installed_state(game_dir: &Path) -> Option<InstalledState> {
    let p = installed_state_path(game_dir);
    let raw = fs::read(p).ok()?;
    serde_json::from_slice(&raw).ok()
}

pub fn write_installed_state(game_dir: &Path, state: &InstalledState) -> Result<()> {
    let bdir = backup_dir(game_dir);
    fs::create_dir_all(&bdir)?;
    let data = serde_json::to_vec_pretty(state)?;
    fs::write(installed_state_path(game_dir), data)?;
    Ok(())
}

/// Ensures `<gameDir>/_ptbr_backup/muvluv16.rio.drcruo1.orig` exists and is clean.
/// Golden rule:
/// - Never overwrite an existing `.orig`.
/// - Only create `.orig` if current `muvluv16.rio.drcruo1` matches `EXPECTED_BASE_RUO_SHA256`.
pub fn ensure_clean_base_backup(game_dir: &Path, expected_sha256: &str) -> Result<PathBuf> {
    let bdir = backup_dir(game_dir);
    let orig_backup = orig_ruo_backup_path(game_dir);

    if orig_backup.is_file() {
        let hash = sha256_file(&orig_backup)?;
        if !hash.eq_ignore_ascii_case(expected_sha256) {
            bail!(
                "O backup existente em {} possui SHA-256 inesperado ({}). Verifique a integridade dos arquivos na Steam antes de continuar.",
                orig_backup.display(),
                &hash[..12]
            );
        }
        return Ok(orig_backup);
    }

    let current_ruo = game_dir.join("muvluv16.rio.drcruo1");
    if !current_ruo.is_file() {
        bail!("muvluv16.rio.drcruo1 não encontrado na pasta selecionada.");
    }
    let meta = fs::metadata(&current_ruo)?;
    let current_hash = sha256_file(&current_ruo)?;
    if !current_hash.eq_ignore_ascii_case(expected_sha256) {
        bail!(
            "O arquivo muvluv16.rio.drcruo1 atual ({} bytes, SHA-256 {}...) parece já ter sido modificado e não existe backup original em _ptbr_backup/. Restaure os arquivos originais pela Steam (Verificar integridade dos arquivos) e tente novamente.",
            meta.len(),
            &current_hash[..12]
        );
    }

    fs::create_dir_all(&bdir)?;
    let tmp_backup = bdir.join(format!("{}.tmp", ORIG_RUO_NAME));
    fs::copy(&current_ruo, &tmp_backup).context("copiar muvluv16.rio.drcruo1 para backup")?;
    let verify_hash = sha256_file(&tmp_backup)?;
    if !verify_hash.eq_ignore_ascii_case(expected_sha256) {
        let _ = fs::remove_file(&tmp_backup);
        bail!("Falha ao verificar integridade do backup recém-criado.");
    }
    fs::rename(&tmp_backup, &orig_backup)?;
    Ok(orig_backup)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreReport {
    pub ruo_restored: bool,
    pub exe_restored: bool,
    pub restored_ruo_sha256: String,
}

/// Restores `muvluv16.rio.drcruo1` (and `muvluv16.exe` if `.orig` exists) back to original English.
pub fn restore_original_game(game_dir: &Path) -> Result<RestoreReport> {
    let orig_backup = orig_ruo_backup_path(game_dir);
    if !orig_backup.is_file() {
        bail!("Backup original não encontrado em _ptbr_backup/muvluv16.rio.drcruo1.orig.");
    }
    let target_ruo = game_dir.join("muvluv16.rio.drcruo1");
    let tmp_restore = game_dir.join("muvluv16.rio.drcruo1.restore.tmp");

    fs::copy(&orig_backup, &tmp_restore).context("copiar backup para restauração")?;
    let restored_hash = sha256_file(&tmp_restore)?;
    let backup_hash = sha256_file(&orig_backup)?;
    if restored_hash != backup_hash {
        let _ = fs::remove_file(&tmp_restore);
        bail!("Falha na verificação SHA-256 durante a restauração do overlay original.");
    }
    fs::rename(&tmp_restore, &target_ruo).context("substituir muvluv16.rio.drcruo1")?;

    let exe_restored = restore_original_exe(game_dir)?;

    let state_path = installed_state_path(game_dir);
    if state_path.exists() {
        let _ = fs::remove_file(state_path);
    }

    Ok(RestoreReport {
        ruo_restored: true,
        exe_restored,
        restored_ruo_sha256: restored_hash,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub ok: bool,
    pub summary: String,
    pub current_ruo_sha256: String,
    pub current_ruo_size: u64,
    pub backup_exists: bool,
    pub backup_valid: bool,
    pub installed_version: Option<String>,
    pub exe_5rf_patched: bool,
}

pub fn verify_installation_integrity(game_dir: &Path) -> Result<IntegrityReport> {
    let current_ruo = game_dir.join("muvluv16.rio.drcruo1");
    if !current_ruo.is_file() {
        bail!("muvluv16.rio.drcruo1 não encontrado na pasta selecionada.");
    }
    let current_size = fs::metadata(&current_ruo)?.len();
    let current_sha = sha256_file(&current_ruo)?;

    let orig_backup = orig_ruo_backup_path(game_dir);
    let backup_exists = orig_backup.is_file();
    let backup_valid = if backup_exists {
        sha256_file(&orig_backup)
            .map(|h| h.eq_ignore_ascii_case(EXPECTED_BASE_RUO_SHA256))
            .unwrap_or(false)
    } else {
        false
    };

    let installed = read_installed_state(game_dir);
    let exe_patched = is_exe_5rf_patched(game_dir);

    let (ok, summary) = if let Some(ref st) = installed {
        if current_sha.eq_ignore_ascii_case(&st.compiled_ruo_sha256) {
            // Also confirm RUO footer parses cleanly
            match crate::rugp::ruo::read_ruo_footer(&current_ruo, 2) {
                Ok(ruo) => (
                    true,
                    format!(
                        "Tradução PT-BR v{} íntegra ({} redirecionamentos rUGP válidos).",
                        st.version,
                        ruo.redirects.len()
                    ),
                ),
                Err(e) => (
                    false,
                    format!("Overlay compilado com rodapé rUGP inválido: {}", e),
                ),
            }
        } else {
            (
                false,
                "O arquivo muvluv16.rio.drcruo1 difere do SHA-256 registrado na última instalação."
                    .to_string(),
            )
        }
    } else if current_sha.eq_ignore_ascii_case(EXPECTED_BASE_RUO_SHA256)
        && current_size == EXPECTED_BASE_RUO_SIZE
    {
        (
            true,
            "Jogo original em inglês íntegro (Steam 2016 + Director's Cut 18+ válido).".to_string(),
        )
    } else {
        (
            false,
            "muvluv16.rio.drcruo1 não corresponde ao original nem a uma instalação registrada."
                .to_string(),
        )
    };

    Ok(IntegrityReport {
        ok,
        summary,
        current_ruo_sha256: current_sha,
        current_ruo_size: current_size,
        backup_exists,
        backup_valid,
        installed_version: installed.map(|s| s.version),
        exe_5rf_patched: exe_patched,
    })
}

pub fn make_installed_state(
    version: String,
    compiled_ruo_sha256: String,
    compiled_ruo_size: u64,
    exe_5rf_patched: bool,
    source_label: String,
) -> InstalledState {
    InstalledState {
        version,
        installed_at: Utc::now().to_rfc3339(),
        compiled_ruo_sha256,
        compiled_ruo_size,
        exe_5rf_patched,
        source_label,
    }
}
