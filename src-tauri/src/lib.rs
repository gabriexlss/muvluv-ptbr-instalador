pub mod config;
pub mod detect;
pub mod download;
pub mod sys_checks;

use std::path::PathBuf;

use muvluv_core::backup::{
    ensure_clean_base_backup, make_installed_state, restore_original_game,
    verify_installation_integrity, write_installed_state, IntegrityReport, RestoreReport,
};
use muvluv_core::exe_patch::{apply_5rf_gdi_fallback_patch, is_exe_5rf_patched, ExePatchOutcome};
use muvluv_core::metadata::{load_translation_metadata, validate_package_hashes};
use muvluv_core::pipeline::{
    build_from_manifest, extract_manifest_in_memory, BuildProgressEvent,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use crate::config::{
    repo_web_url, RECOMMENDED_FREE_SPACE_BYTES, TRANSLATION_REPO_NAME, TRANSLATION_REPO_OWNER,
};
use crate::detect::{auto_detect_game_dir, inspect_game_dir, GameInspection};
use crate::download::{
    download_latest_translation_zip, extract_zip_safely, fetch_latest_release_info,
    resolve_package_root, RemoteReleaseInfo,
};
use crate::sys_checks::{available_disk_space, is_game_running};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoConfigInfo {
    pub owner: String,
    pub name: String,
    pub web_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallProgressPayload {
    pub stage: String,
    pub percent: u8,
    pub message: String,
    pub log_line: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PackageSource {
    Online,
    LocalZip { path: String },
    LocalDir { path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallRequest {
    pub game_dir: String,
    pub source: PackageSource,
    pub apply_5rf_patch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallResult {
    pub version: String,
    pub modified_crsa_count: usize,
    pub total_changed_entries: usize,
    pub compiled_ruo_sha256: String,
    pub exe_5rf_patched: bool,
    pub warnings: Vec<String>,
}

fn emit_progress(
    app: &AppHandle,
    stage: &str,
    percent: u8,
    message: impl Into<String>,
    log_line: Option<String>,
) {
    let _ = app.emit(
        "install-progress",
        InstallProgressPayload {
            stage: stage.to_string(),
            percent: percent.min(100),
            message: message.into(),
            log_line,
        },
    );
}

#[tauri::command]
fn get_repo_config() -> RepoConfigInfo {
    RepoConfigInfo {
        owner: TRANSLATION_REPO_OWNER.to_string(),
        name: TRANSLATION_REPO_NAME.to_string(),
        web_url: repo_web_url(),
    }
}

#[tauri::command]
fn detect_game_command() -> Option<GameInspection> {
    auto_detect_game_dir()
}

#[tauri::command]
fn inspect_game_command(path: String) -> GameInspection {
    inspect_game_dir(&PathBuf::from(path))
}

#[tauri::command]
async fn fetch_remote_release_command() -> Option<RemoteReleaseInfo> {
    fetch_latest_release_info().await
}

#[tauri::command]
async fn verify_integrity_command(game_dir: String) -> Result<IntegrityReport, String> {
    let dir = PathBuf::from(game_dir);
    tokio::task::spawn_blocking(move || verify_installation_integrity(&dir))
        .await
        .map_err(|e| format!("erro interno: {}", e))?
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn restore_original_command(
    app: AppHandle,
    game_dir: String,
) -> Result<RestoreReport, String> {
    let dir = PathBuf::from(game_dir);
    if is_game_running() {
        return Err(
            "muvluv16.exe está em execução. Feche o jogo antes de restaurar o inglês original."
                .to_string(),
        );
    }
    emit_progress(
        &app,
        "restore",
        25,
        "Restaurando overlay original de _ptbr_backup/...",
        Some("[INFO] Restaurando muvluv16.rio.drcruo1.orig...".to_string()),
    );
    let rep = tokio::task::spawn_blocking(move || restore_original_game(&dir))
        .await
        .map_err(|e| format!("erro interno: {}", e))?
        .map_err(|e| e.to_string())?;

    emit_progress(
        &app,
        "done",
        100,
        "Inglês original restaurado com sucesso!",
        Some(format!(
            "[OK] Restauração concluída (SHA-256: {}...{}, exe restaurado={})",
            &rep.restored_ruo_sha256[..10],
            &rep.restored_ruo_sha256[rep.restored_ruo_sha256.len() - 6..],
            rep.exe_restored
        )),
    );
    Ok(rep)
}

#[tauri::command]
async fn install_translation_command(
    app: AppHandle,
    request: InstallRequest,
) -> Result<InstallResult, String> {
    let game_dir = PathBuf::from(&request.game_dir);

    let inspection = inspect_game_dir(&game_dir);
    if !inspection.valid {
        return Err(inspection
            .error_message
            .unwrap_or_else(|| "Pasta do jogo inválida.".to_string()));
    }
    if is_game_running() {
        return Err(
            "muvluv16.exe está aberto no momento. Feche o jogo antes de aplicar a tradução."
                .to_string(),
        );
    }
    if let Some(free) = available_disk_space(&game_dir) {
        if free < RECOMMENDED_FREE_SPACE_BYTES {
            let mb = free / (1024 * 1024);
            return Err(format!(
                "Espaço livre insuficiente no drive do jogo ({} MB disponíveis; recomenda-se ao menos 1024 MB livres para backup e compilação segura).",
                mb
            ));
        }
    }

    let temp_work = tempfile::tempdir().map_err(|e| format!("criar pasta temporária: {}", e))?;
    let mut warnings: Vec<String> = Vec::new();

    // 1. Obtain translation package directory
    let (package_root, source_label) = match &request.source {
        PackageSource::Online => {
            emit_progress(
                &app,
                "download",
                3,
                "Baixando pacote oficial da tradução no GitHub...",
                Some(format!(
                    "[INFO] Baixando pacote de {}/{}...",
                    TRANSLATION_REPO_OWNER, TRANSLATION_REPO_NAME
                )),
            );
            let zip_path = temp_work.path().join("muvluv-ptbr-translation.zip");
            let app_dl = app.clone();
            let mut last_pct: u8 = 0;
            download_latest_translation_zip(&zip_path, |got, total| {
                let pct = match total {
                    Some(t) if t > 0 => 3 + ((got.saturating_mul(17)) / t) as u8,
                    _ => 10,
                };
                if pct != last_pct {
                    last_pct = pct;
                    emit_progress(
                        &app_dl,
                        "download",
                        pct,
                        format!(
                            "Baixando pacote da tradução ({:.1} MB)...",
                            got as f64 / (1024.0 * 1024.0)
                        ),
                        None,
                    );
                }
            })
            .await
            .map_err(|e| e.to_string())?;

            emit_progress(
                &app,
                "download",
                21,
                "Extraindo pacote da tradução...",
                Some("[OK] Download concluído e verificado. Extraindo ZIP...".to_string()),
            );
            let extract_dir = temp_work.path().join("extracted");
            let root = extract_zip_safely(&zip_path, &extract_dir).map_err(|e| e.to_string())?;
            (
                root,
                format!("GitHub ({}/{})", TRANSLATION_REPO_OWNER, TRANSLATION_REPO_NAME),
            )
        }
        PackageSource::LocalZip { path } => {
            emit_progress(
                &app,
                "download",
                12,
                "Extraindo pacote .zip local...",
                Some(format!("[INFO] Usando arquivo local: {}", path)),
            );
            let extract_dir = temp_work.path().join("extracted");
            let root = extract_zip_safely(&PathBuf::from(path), &extract_dir)
                .map_err(|e| e.to_string())?;
            (root, format!("Local ZIP ({})", path))
        }
        PackageSource::LocalDir { path } => {
            emit_progress(
                &app,
                "download",
                15,
                "Lendo pasta local de tradução...",
                Some(format!("[INFO] Usando pasta local: {}", path)),
            );
            let root =
                resolve_package_root(&PathBuf::from(path)).map_err(|e| e.to_string())?;
            (root, format!("Pasta local ({})", path))
        }
    };

    // 2. Heavy CPU/IO pipeline in blocking thread
    let app_blocking = app.clone();
    let apply_5rf = request.apply_5rf_patch;
    let game_dir_clone = game_dir.clone();

    let (result, block_warnings) = tokio::task::spawn_blocking(move || -> anyhow::Result<(InstallResult, Vec<String>)> {
        let mut local_warnings = Vec::new();

        // 2a. Validate metadata.json and SHA-256 of all 102 JSON files
        let meta = load_translation_metadata(&package_root)?;
        emit_progress(
            &app_blocking,
            "validate",
            22,
            format!("Validando {} arquivos JSON da tradução...", meta.file_count),
            Some(format!(
                "[INFO] Pacote v{} ({} arquivos, {} entradas). Verificando SHA-256...",
                meta.version, meta.file_count, meta.total_entries
            )),
        );
        let trans_dir = validate_package_hashes(&package_root, &meta, |cur, total, fname| {
            if cur % 10 == 0 || cur == total {
                let pct = 22 + ((cur * 10) / total.max(1)) as u8;
                emit_progress(
                    &app_blocking,
                    "validate",
                    pct,
                    format!("Validando JSONs ({}/{}): {}", cur, total, fname),
                    None,
                );
            }
        })?;
        emit_progress(
            &app_blocking,
            "validate",
            32,
            "Todos os 102 JSONs validados com sucesso!",
            Some(format!(
                "[OK] {} arquivos JSON validados com SHA-256 íntegro.",
                meta.file_count
            )),
        );

        // 2b. Ensure permanent clean backup in _ptbr_backup/
        emit_progress(
            &app_blocking,
            "analyze",
            34,
            "Verificando backup original seguro em _ptbr_backup/...",
            Some("[INFO] Conferindo SHA-256 do overlay base original...".to_string()),
        );
        let base_orig_path =
            ensure_clean_base_backup(&game_dir_clone, &meta.expected_base_ruo_sha256)?;
        emit_progress(
            &app_blocking,
            "analyze",
            38,
            "Backup original protegido. Mapeando cenas do jogo...",
            Some(format!(
                "[OK] Backup base válido: {}",
                base_orig_path.display()
            )),
        );

        // 2c. Extract manifest in memory from original game
        let (manifest, extract_sum) =
            extract_manifest_in_memory(&game_dir_clone, Some(&base_orig_path), |cur, total| {
                if cur % 15 == 0 || cur == total {
                    let pct = 38 + ((cur * 17) / total.max(1)) as u8;
                    emit_progress(
                        &app_blocking,
                        "analyze",
                        pct,
                        format!("Analisando registros CRsa ({}/{})...", cur, total),
                        None,
                    );
                }
            })?;
        emit_progress(
            &app_blocking,
            "analyze",
            55,
            format!(
                "Mapeamento concluído: {} arquivos, {} entradas.",
                extract_sum.exported_files, extract_sum.total_entries
            ),
            Some(format!(
                "[OK] Extraído em memória: {} CRsa -> {} arquivos ({} entradas).",
                extract_sum.total_crsa_records,
                extract_sum.exported_files,
                extract_sum.total_entries
            )),
        );

        // 2d. Rebuild modified CRsa + cumulative RUO via .tmp + strict readback
        let target_ruo = game_dir_clone.join("muvluv16.rio.drcruo1");
        let mut last_write_pct: u8 = 0;
        let build_sum = build_from_manifest(
            &base_orig_path,
            &manifest,
            &trans_dir,
            &target_ruo,
            true,
            |ev| match ev {
                BuildProgressEvent::RebuildingCrsa { current, total } => {
                    if current % 4 == 0 || current == total {
                        let pct = 55 + ((current * 23) / total.max(1)) as u8;
                        emit_progress(
                            &app_blocking,
                            "rebuild",
                            pct,
                            format!("Recompilando registros CRsa ({}/{})...", current, total),
                            None,
                        );
                    }
                }
                BuildProgressEvent::WritingRuo { copied, total } => {
                    let pct = 78 + ((copied.saturating_mul(14)) / total.max(1)) as u8;
                    if pct != last_write_pct {
                        last_write_pct = pct;
                        emit_progress(
                            &app_blocking,
                            "rebuild",
                            pct,
                            "Gravando overlay seguro em muvluv16.rio.drcruo1.tmp...",
                            None,
                        );
                    }
                }
                BuildProgressEvent::VerifyingOutput => {
                    emit_progress(
                        &app_blocking,
                        "verify",
                        94,
                        "Verificando integridade final byte a byte no disco...",
                        Some("[INFO] Rodando readback completo em todos os CRsa substituídos...".to_string()),
                    );
                }
            },
        )?;

        emit_progress(
            &app_blocking,
            "verify",
            96,
            "Overlay rUGP verificado 100% byte a byte!",
            Some(format!(
                "[OK] Overlay compilado: {} redirecionamentos, {} CRsa modificados, {} falas alteradas (readback OK).",
                build_sum.ruo_report.final_redirect_count,
                build_sum.modified_crsa_count,
                build_sum.total_changed_entries
            )),
        );

        // 2e. Optional .5RF GDI fallback patch on muvluv16.exe
        if apply_5rf {
            match apply_5rf_gdi_fallback_patch(&game_dir_clone)? {
                ExePatchOutcome::Applied => {
                    emit_progress(
                        &app_blocking,
                        "verify",
                        98,
                        "Patch opcional .5RF aplicado em muvluv16.exe.",
                        Some("[OK] Fallback GDI (.5RF) aplicado em muvluv16.exe (backup salvo em _ptbr_backup/muvluv16.exe.orig).".to_string()),
                    );
                }
                ExePatchOutcome::AlreadyApplied => {
                    emit_progress(
                        &app_blocking,
                        "verify",
                        98,
                        "Patch opcional .5RF já estava ativo em muvluv16.exe.",
                        Some("[OK] Fallback GDI (.5RF) já estava aplicado.".to_string()),
                    );
                }
                ExePatchOutcome::SkippedWithWarning(msg) => {
                    emit_progress(
                        &app_blocking,
                        "verify",
                        98,
                        "Tradução concluída (patch opcional .5RF ignorado com segurança).",
                        Some(format!("[AVISO] {}", msg)),
                    );
                    local_warnings.push(msg);
                }
            }
        }

        let exe_patched_now = is_exe_5rf_patched(&game_dir_clone);
        let state = make_installed_state(
            meta.version.clone(),
            build_sum.ruo_report.output_sha256.clone(),
            build_sum.ruo_report.final_file_size,
            exe_patched_now,
            source_label,
        );
        write_installed_state(&game_dir_clone, &state)?;

        emit_progress(
            &app_blocking,
            "done",
            100,
            format!("Tradução PT-BR v{} instalada com sucesso!", meta.version),
            Some(format!(
                "[OK] Instalação concluída! SHA-256 final: {}",
                build_sum.ruo_report.output_sha256
            )),
        );

        Ok((
            InstallResult {
                version: meta.version,
                modified_crsa_count: build_sum.modified_crsa_count,
                total_changed_entries: build_sum.total_changed_entries,
                compiled_ruo_sha256: build_sum.ruo_report.output_sha256,
                exe_5rf_patched: exe_patched_now,
                warnings: Vec::new(),
            },
            local_warnings,
        ))
    })
    .await
    .map_err(|e| format!("erro interno na thread de instalação: {}", e))?
    .map_err(|e| e.to_string())?;

    warnings.extend(block_warnings);
    let mut final_res = result;
    final_res.warnings = warnings;
    Ok(final_res)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            get_repo_config,
            detect_game_command,
            inspect_game_command,
            fetch_remote_release_command,
            verify_integrity_command,
            restore_original_command,
            install_translation_command,
        ])
        .run(tauri::generate_context!())
        .expect("erro ao iniciar o instalador Muv-Luv PT-BR");
}
