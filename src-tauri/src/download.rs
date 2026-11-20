use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use muvluv_core::metadata::sha256_file;
use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::config::{latest_release_api_url, latest_zip_sha256_url, latest_zip_url};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteReleaseInfo {
    pub tag_name: String,
    pub version: String,
    pub html_url: String,
    pub published_at: Option<String>,
}

#[derive(Deserialize)]
struct GitHubReleaseApi {
    tag_name: String,
    html_url: String,
    published_at: Option<String>,
}

fn build_client(timeout_secs: u64) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("muvluv-ptbr-instalador/1.0")
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .context("create HTTP client")
}

/// Queries GitHub Releases API to show the latest translation version.
/// Never fails fatally on rate-limit or offline; caller can treat `None` gracefully.
pub async fn fetch_latest_release_info() -> Option<RemoteReleaseInfo> {
    let client = build_client(8).ok()?;
    let resp = client.get(latest_release_api_url()).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let data: GitHubReleaseApi = resp.json().await.ok()?;
    let version = data.tag_name.trim_start_matches('v').to_string();
    Some(RemoteReleaseInfo {
        tag_name: data.tag_name,
        version,
        html_url: data.html_url,
        published_at: data.published_at,
    })
}

/// Downloads `muvluv-ptbr-translation.zip` directly from `/releases/latest/download/...`
/// (bypassing API rate-limits) and optionally verifies against `.zip.sha256` if published.
pub async fn download_latest_translation_zip<F>(
    dest_zip: &Path,
    mut on_progress: F,
) -> Result<()>
where
    F: FnMut(u64, Option<u64>),
{
    let client = build_client(120)?;
    let url = latest_zip_url();
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("baixar {}", url))?;
    if !resp.status().is_success() {
        bail!(
            "Falha ao baixar pacote da tradução (HTTP {}). Verifique se existe uma Release publicada em {} ou use um arquivo .zip local.",
            resp.status(),
            url
        );
    }

    let total = resp.content_length();
    let mut file = File::create(dest_zip).context("criar arquivo .zip temporário")?;
    let mut downloaded: u64 = 0;
    let mut stream = resp.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let bytes = chunk.context("erro de rede durante o download")?;
        file.write_all(&bytes)?;
        downloaded += bytes.len() as u64;
        on_progress(downloaded, total);
    }
    file.flush()?;
    drop(file);

    // Optional integrity check against published `.zip.sha256`
    if let Ok(sha_resp) = client.get(latest_zip_sha256_url()).send().await {
        if sha_resp.status().is_success() {
            if let Ok(text) = sha_resp.text().await {
                if let Some(expected_hex) = text.split_whitespace().next() {
                    if expected_hex.len() == 64
                        && expected_hex.chars().all(|c| c.is_ascii_hexdigit())
                    {
                        let got_hex = sha256_file(dest_zip)?;
                        if !got_hex.eq_ignore_ascii_case(expected_hex) {
                            bail!(
                                "SHA-256 do arquivo .zip baixado não confere (esperado {}, obtido {}).",
                                &expected_hex[..12],
                                &got_hex[..12]
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Safely extracts a zip archive preventing Zip Slip and returns the directory containing `metadata.json`.
pub fn extract_zip_safely(zip_path: &Path, dest_dir: &Path) -> Result<PathBuf> {
    let file = File::open(zip_path)
        .with_context(|| format!("abrir pacote .zip {}", zip_path.display()))?;
    let mut archive = ZipArchive::new(file).context("ler arquivo .zip")?;
    fs::create_dir_all(dest_dir)?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let Some(rel_path) = entry.enclosed_name().map(|p| p.to_path_buf()) else {
            bail!("Entrada insegura (Zip Slip) detectada no arquivo .zip");
        };
        let out_path = dest_dir.join(&rel_path);
        if entry.is_dir() {
            fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut out_file = File::create(&out_path)?;
            std::io::copy(&mut entry, &mut out_file)?;
        }
    }

    resolve_package_root(dest_dir)
}

/// Finds `metadata.json` either directly in `dir` or inside a single top-level wrapper folder.
pub fn resolve_package_root(dir: &Path) -> Result<PathBuf> {
    if dir.join("metadata.json").is_file() {
        return Ok(dir.to_path_buf());
    }
    let mut subdirs = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().is_dir() {
            subdirs.push(entry.path());
        }
    }
    if subdirs.len() == 1 && subdirs[0].join("metadata.json").is_file() {
        return Ok(subdirs.remove(0));
    }
    bail!(
        "metadata.json não encontrado no pacote de tradução em {}.",
        dir.display()
    );
}
