import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export interface RepoConfigInfo {
  owner: string;
  name: string;
  web_url: string;
}

export interface InstalledState {
  version: string;
  installed_at: string;
  compiled_ruo_sha256: string;
  compiled_ruo_size: number;
  exe_5rf_patched: boolean;
  source_label: string;
}

export interface GameInspection {
  path: string;
  valid: boolean;
  has_directors_cut: boolean;
  missing_files: string[];
  warning_message: string | null;
  error_message: string | null;
  backup_exists: boolean;
  installed_state: InstalledState | null;
  exe_5rf_patched: boolean;
  game_running: boolean;
  free_space_bytes: number | null;
  has_enough_space: boolean;
}

export interface RemoteReleaseInfo {
  tag_name: string;
  version: string;
  html_url: string;
  published_at: string | null;
}

export interface InstallProgressPayload {
  stage: string;
  percent: number;
  message: string;
  log_line: string | null;
}

export type PackageSource =
  | { mode: "online" }
  | { mode: "local_zip"; path: string }
  | { mode: "local_dir"; path: string };

export interface InstallRequest {
  game_dir: string;
  source: PackageSource;
  apply_5rf_patch: boolean;
}

export interface InstallResult {
  version: string;
  modified_crsa_count: number;
  total_changed_entries: number;
  compiled_ruo_sha256: string;
  exe_5rf_patched: boolean;
  warnings: string[];
}

export interface RestoreReport {
  ruo_restored: boolean;
  exe_restored: boolean;
  restored_ruo_sha256: string;
}

export interface IntegrityReport {
  ok: boolean;
  summary: string;
  current_ruo_sha256: string;
  current_ruo_size: number;
  backup_exists: boolean;
  backup_valid: boolean;
  installed_version: string | null;
  exe_5rf_patched: boolean;
}

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export async function getRepoConfig(): Promise<RepoConfigInfo> {
  return invoke<RepoConfigInfo>("get_repo_config");
}

export async function detectGameDir(): Promise<GameInspection | null> {
  return invoke<GameInspection | null>("detect_game_command");
}

export async function inspectGameDir(path: string): Promise<GameInspection> {
  return invoke<GameInspection>("inspect_game_command", { path });
}

export async function fetchRemoteRelease(): Promise<RemoteReleaseInfo | null> {
  return invoke<RemoteReleaseInfo | null>("fetch_remote_release_command");
}

export async function installTranslation(
  request: InstallRequest
): Promise<InstallResult> {
  return invoke<InstallResult>("install_translation_command", { request });
}

export async function restoreOriginal(gameDir: string): Promise<RestoreReport> {
  return invoke<RestoreReport>("restore_original_command", { gameDir });
}

export async function verifyIntegrity(
  gameDir: string
): Promise<IntegrityReport> {
  return invoke<IntegrityReport>("verify_integrity_command", { gameDir });
}

export async function onInstallProgress(
  cb: (payload: InstallProgressPayload) => void
): Promise<UnlistenFn> {
  return listen<InstallProgressPayload>("install-progress", (event) => {
    cb(event.payload);
  });
}
