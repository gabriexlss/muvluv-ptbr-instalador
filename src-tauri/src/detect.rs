use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use muvluv_core::backup::{orig_ruo_backup_path, read_installed_state, InstalledState};
use muvluv_core::exe_patch::is_exe_5rf_patched;
use serde::{Deserialize, Serialize};

use crate::config::RECOMMENDED_FREE_SPACE_BYTES;
use crate::sys_checks::{available_disk_space, is_game_running};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameInspection {
    pub path: String,
    pub valid: bool,
    pub has_directors_cut: bool,
    pub missing_files: Vec<String>,
    pub warning_message: Option<String>,
    pub error_message: Option<String>,
    pub backup_exists: bool,
    pub installed_state: Option<InstalledState>,
    pub exe_5rf_patched: bool,
    pub game_running: bool,
    pub free_space_bytes: Option<u64>,
    pub has_enough_space: bool,
}

fn push_unique(list: &mut Vec<PathBuf>, seen: &mut HashSet<String>, p: PathBuf) {
    let key = p.to_string_lossy().to_lowercase();
    if seen.insert(key) {
        list.push(p);
    }
}

/// Parses Steam's `libraryfolders.vdf` to extract all library root paths.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_steam_library_folders(vdf_path: &Path) -> Vec<PathBuf> {
    let Ok(content) = fs::read_to_string(vdf_path) else {
        return Vec::new();
    };
    let mut roots = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        let parts: Vec<&str> = trimmed.split('"').collect();
        // Format: "path" "D:\\SteamLibrary" or "1" "D:\\SteamLibrary"
        if parts.len() >= 4 {
            let key = parts[1];
            let val = parts[3];
            if key.eq_ignore_ascii_case("path") || key.chars().all(|c| c.is_ascii_digit()) {
                if val.contains(":\\") || val.contains(":/") || val.starts_with('/') {
                    let unescaped = val.replace("\\\\", "\\");
                    roots.push(PathBuf::from(unescaped));
                }
            }
        }
    }
    roots
}

/// Parses `appmanifest_449830.acf` for `"installdir"` value.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_acf_installdir(acf_path: &Path) -> Option<String> {
    let content = fs::read_to_string(acf_path).ok()?;
    for line in content.lines() {
        let parts: Vec<&str> = line.trim().split('"').collect();
        if parts.len() >= 4 && parts[1].eq_ignore_ascii_case("installdir") {
            return Some(parts[3].to_string());
        }
    }
    None
}

fn collect_candidates() -> Vec<PathBuf> {
    let mut cands = Vec::new();
    let mut seen = HashSet::new();

    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        use winreg::RegKey;

        // 1. AGES3 game registry key
        if let Ok(hkcu) = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(r"Software\AGES3 Applications\age\muvluv_v16_eng\Installation")
        {
            if let Ok(abs_path) = hkcu.get_value::<String, _>("strAbsolutePath") {
                push_unique(&mut cands, &mut seen, PathBuf::from(abs_path));
            }
        }

        // 2. Steam App 449830 uninstall entry
        for sub in [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Steam App 449830",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Steam App 449830",
        ] {
            if let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(sub) {
                if let Ok(loc) = k.get_value::<String, _>("InstallLocation") {
                    push_unique(&mut cands, &mut seen, PathBuf::from(loc));
                }
            }
        }

        // 3. Steam InstallPath -> libraryfolders.vdf -> appmanifest_449830.acf & common/Muv-Luv
        let mut steam_roots: Vec<PathBuf> = Vec::new();
        for (hive, sub, val_name) in [
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam", "InstallPath"),
            (HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath"),
        ] {
            if let Ok(k) = RegKey::predef(hive).open_subkey(sub) {
                if let Ok(p) = k.get_value::<String, _>(val_name) {
                    steam_roots.push(PathBuf::from(p));
                }
            }
        }

        let mut all_libraries = steam_roots.clone();
        for root in &steam_roots {
            let vdf = root.join("steamapps").join("libraryfolders.vdf");
            all_libraries.extend(parse_steam_library_folders(&vdf));
        }

        for lib in all_libraries {
            let steamapps = lib.join("steamapps");
            let acf = steamapps.join("appmanifest_449830.acf");
            if let Some(dir_name) = parse_acf_installdir(&acf) {
                push_unique(&mut cands, &mut seen, steamapps.join("common").join(dir_name));
            }
            push_unique(&mut cands, &mut seen, steamapps.join("common").join("Muv-Luv"));
        }

        // 4. Common fallback paths
        for p in [
            r"C:\Program Files (x86)\Steam\steamapps\common\Muv-Luv",
            r"C:\Program Files\Steam\steamapps\common\Muv-Luv",
            r"C:\SteamLibrary\steamapps\common\Muv-Luv",
            r"D:\SteamLibrary\steamapps\common\Muv-Luv",
            r"D:\Jogos\Muv-Luv",
            r"E:\SteamLibrary\steamapps\common\Muv-Luv",
        ] {
            push_unique(&mut cands, &mut seen, PathBuf::from(p));
        }
    }

    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let steam_common = PathBuf::from(&home).join(".local/share/Steam/steamapps/common/Muv-Luv");
            push_unique(&mut cands, &mut seen, steam_common);
        }
        // Read-only convenience detection on WSL when testing UI
        let wsl_common = PathBuf::from("/mnt/c/Program Files (x86)/Steam/steamapps/common/Muv-Luv");
        push_unique(&mut cands, &mut seen, wsl_common);
    }

    cands
}

pub fn auto_detect_game_dir() -> Option<GameInspection> {
    let candidates = collect_candidates();
    // Prefer a fully valid installation with Director's Cut
    let mut fallback_partial: Option<GameInspection> = None;
    for cand in candidates {
        if !cand.is_dir() {
            continue;
        }
        let insp = inspect_game_dir(&cand);
        if insp.valid && insp.has_directors_cut {
            return Some(insp);
        }
        if fallback_partial.is_none() && cand.join("muvluv16.exe").is_file() {
            fallback_partial = Some(insp);
        }
    }
    fallback_partial
}

pub fn inspect_game_dir(dir: &Path) -> GameInspection {
    let required = [
        "muvluv16.exe",
        "muvluv16.rio",
        "muvluv16.rio.002",
        "muvluv16.rio.ici",
    ];
    let mut missing = Vec::new();
    for file in required {
        if !dir.join(file).is_file() {
            missing.push(file.to_string());
        }
    }

    let has_drcruo1 = dir.join("muvluv16.rio.drcruo1").is_file();
    let has_ruo1 = dir.join("muvluv16.rio.ruo1").is_file();

    let mut error_message = None;
    let mut warning_message = None;

    if !dir.is_dir() {
        error_message = Some("A pasta selecionada não existe.".to_string());
    } else if !missing.is_empty() {
        error_message = Some(format!(
            "Arquivos obrigatórios ausentes nesta pasta: {}. Selecione a pasta raiz de instalação do Muv-Luv (onde está muvluv16.exe).",
            missing.join(", ")
        ));
    } else if !has_drcruo1 {
        if has_ruo1 {
            error_message = Some(
                "Foi detectado apenas muvluv16.rio.ruo1 (versão base sem Director's Cut). Esta tradução requer o patch Director's Cut 18+ aplicado (muvluv16.rio.drcruo1)."
                    .to_string(),
            );
        } else {
            error_message = Some(
                "O overlay muvluv16.rio.drcruo1 não foi encontrado. Aplique o patch Director's Cut 18+ do Muv-Luv antes de instalar a tradução."
                    .to_string(),
            );
        }
    }

    let free_space = available_disk_space(dir);
    let has_enough_space = free_space
        .map(|b| b >= RECOMMENDED_FREE_SPACE_BYTES)
        .unwrap_or(true);
    if !has_enough_space {
        warning_message = Some(
            "Menos de 1 GB livre neste disco. Recomenda-se liberar espaço antes de compilar o overlay com segurança."
                .to_string(),
        );
    }

    let running = is_game_running();
    if running {
        warning_message = Some(
            "muvluv16.exe está em execução no momento. Feche o jogo antes de instalar ou restaurar."
                .to_string(),
        );
    }

    let valid = error_message.is_none();
    let backup_exists = orig_ruo_backup_path(dir).is_file();
    let installed_state = read_installed_state(dir);
    let exe_5rf_patched = is_exe_5rf_patched(dir);

    GameInspection {
        path: dir.to_string_lossy().into_owned(),
        valid,
        has_directors_cut: has_drcruo1,
        missing_files: missing,
        warning_message,
        error_message,
        backup_exists,
        installed_state,
        exe_5rf_patched,
        game_running: running,
        free_space_bytes: free_space,
        has_enough_space,
    }
}
