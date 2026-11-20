use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationFileMeta {
    pub filename: String,
    pub entry_count: usize,
    #[serde(default)]
    pub wait_tag_count: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationMetadata {
    pub schema_version: u32,
    pub version: String,
    pub language: String,
    pub game: String,
    pub required_executable: String,
    pub required_overlay: String,
    pub expected_base_ruo_sha256: String,
    pub expected_base_ruo_size: u64,
    pub expected_exe_sha256: String,
    pub unit_size: u64,
    pub file_count: usize,
    pub total_entries: usize,
    pub translation_dir: String,
    pub files: Vec<TranslationFileMeta>,
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn load_translation_metadata(package_root: &Path) -> Result<TranslationMetadata> {
    let meta_path = package_root.join("metadata.json");
    let raw = fs::read(&meta_path)
        .with_context(|| format!("read metadata.json at {}", meta_path.display()))?;
    let meta: TranslationMetadata =
        serde_json::from_slice(&raw).context("parse metadata.json")?;
    if meta.files.len() != meta.file_count {
        bail!(
            "metadata.json inconsistente: file_count={} mas files.len()={}",
            meta.file_count,
            meta.files.len()
        );
    }
    Ok(meta)
}

/// Validates SHA-256 of every translation JSON listed in `metadata.json`.
/// Returns the resolved path to the `translation/` directory.
pub fn validate_package_hashes<F>(
    package_root: &Path,
    meta: &TranslationMetadata,
    mut on_file: F,
) -> Result<PathBuf>
where
    F: FnMut(usize, usize, &str),
{
    let trans_dir = package_root.join(&meta.translation_dir);
    if !trans_dir.is_dir() {
        bail!(
            "Diretório de tradução {:?} não encontrado em {}",
            meta.translation_dir,
            package_root.display()
        );
    }
    let total = meta.files.len();
    for (idx, fmeta) in meta.files.iter().enumerate() {
        on_file(idx + 1, total, &fmeta.filename);
        let p = trans_dir.join(&fmeta.filename);
        if !p.is_file() {
            bail!("Arquivo de tradução ausente no pacote: {}", fmeta.filename);
        }
        let got_hash = sha256_file(&p)?;
        if !got_hash.eq_ignore_ascii_case(&fmeta.sha256) {
            bail!(
                "SHA-256 inválido para {}: esperado {}, obtido {}",
                fmeta.filename,
                fmeta.sha256,
                got_hash
            );
        }
    }
    Ok(trans_dir)
}
