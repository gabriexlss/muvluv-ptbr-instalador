import { useEffect, useMemo, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { openUrl } from "@tauri-apps/plugin-opener";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  detectGameDir,
  fetchRemoteRelease,
  getRepoConfig,
  inspectGameDir,
  installTranslation,
  isTauriRuntime,
  onInstallProgress,
  restoreOriginal,
  verifyIntegrity,
  type GameInspection,
  type IntegrityReport,
  type PackageSource,
  type RemoteReleaseInfo,
  type RepoConfigInfo,
} from "@/lib/tauri";
import { formatBytes } from "@/lib/utils";

const GAME_ICON_URL =
  "https://shared.fastly.steamstatic.com/community_assets/images/apps/449830/8abc9e0edb513200d094688541cdc4782f45311b.jpg";
const POSTER_URL =
  "https://shared.fastly.steamstatic.com/store_item_assets/steam/apps/802880/library_600x900.jpg";
const LOGO_URL =
  "https://shared.fastly.steamstatic.com/store_item_assets/steam/apps/802880/logo.png";

const TOTAL_SEGMENTS = 20;

export default function App() {
  const [repo, setRepo] = useState<RepoConfigInfo>({
    owner: "gabriexlss",
    name: "muvluv-ptbr-traducao",
    web_url: "https://github.com/gabriexlss/muvluv-ptbr-traducao",
  });
  const [inspection, setInspection] = useState<GameInspection | null>(null);
  const [remoteRelease, setRemoteRelease] = useState<RemoteReleaseInfo | null>(
    null
  );
  const [apply5rf, setApply5rf] = useState<boolean>(false);
  const [packageSource, setPackageSource] = useState<PackageSource>({
    mode: "online",
  });

  const [busy, setBusy] = useState<boolean>(false);
  const [progressPct, setProgressPct] = useState<number>(0);
  const [statusMessage, setStatusMessage] = useState<string>(
    "Aguardando ação · ~1 GB livre recomendado"
  );
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [successBanner, setSuccessBanner] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([
    "[INFO] Muv-Luv PT-BR Patcher inicializado.",
  ]);

  const [logDialogOpen, setLogDialogOpen] = useState(false);
  const [localModalOpen, setLocalModalOpen] = useState(false);
  const [restoreConfirmOpen, setRestoreConfirmOpen] = useState(false);
  const [integrityReport, setIntegrityReport] =
    useState<IntegrityReport | null>(null);

  const [logoFailed, setLogoFailed] = useState(false);

  const appendLog = (line: string) => {
    setLogs((prev) => [...prev.slice(-300), line]);
  };

  useEffect(() => {
    if (!isTauriRuntime()) {
      return;
    }

    let unlisten: (() => void) | undefined;

    (async () => {
      try {
        const cfg = await getRepoConfig();
        setRepo(cfg);
      } catch {
        // fallback defaults already set
      }

      try {
        const detected = await detectGameDir();
        if (detected) {
          setInspection(detected);
          setApply5rf(detected.exe_5rf_patched);
          appendLog(
            detected.valid
              ? `[OK] Jogo detectado automaticamente: ${detected.path}`
              : `[AVISO] Pasta encontrada com pendência: ${detected.path}`
          );
        } else {
          appendLog(
            "[INFO] Pasta do Muv-Luv não encontrada automaticamente. Selecione manualmente."
          );
        }
      } catch (err) {
        appendLog(`[AVISO] Erro na autodetecção: ${String(err)}`);
      }

      fetchRemoteRelease()
        .then((rel) => {
          if (rel) {
            setRemoteRelease(rel);
            appendLog(
              `[OK] Versão mais recente no GitHub: v${rel.version} (${rel.tag_name})`
            );
          }
        })
        .catch(() => {
          // rate-limit or offline: silent fallback
        });

      unlisten = await onInstallProgress((payload) => {
        setProgressPct(payload.percent);
        setStatusMessage(payload.message);
        if (payload.log_line) {
          appendLog(payload.log_line);
        }
      });
    })();

    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  const refreshInspection = async (path: string) => {
    const res = await inspectGameDir(path);
    setInspection(res);
    setApply5rf(res.exe_5rf_patched);
    return res;
  };

  const handleSelectGameFolder = async () => {
    if (busy || !isTauriRuntime()) return;
    setErrorBanner(null);
    setSuccessBanner(null);
    const selected = await openDialog({
      directory: true,
      multiple: false,
      title: "Selecione a pasta de instalação do Muv-Luv",
    });
    if (typeof selected === "string" && selected.length > 0) {
      const res = await refreshInspection(selected);
      appendLog(
        res.valid
          ? `[OK] Pasta selecionada e validada: ${res.path}`
          : `[AVISO] Pasta selecionada inválida: ${res.error_message ?? res.path}`
      );
    }
  };

  const handlePickLocalZip = async () => {
    if (!isTauriRuntime()) return;
    const selected = await openDialog({
      directory: false,
      multiple: false,
      title: "Selecione o arquivo muvluv-ptbr-translation.zip",
      filters: [{ name: "Pacote ZIP", extensions: ["zip"] }],
    });
    if (typeof selected === "string" && selected.length > 0) {
      setPackageSource({ mode: "local_zip", path: selected });
      setLocalModalOpen(false);
      appendLog(`[INFO] Fonte local definida (.zip): ${selected}`);
    }
  };

  const handlePickLocalDir = async () => {
    if (!isTauriRuntime()) return;
    const selected = await openDialog({
      directory: true,
      multiple: false,
      title: "Selecione a pasta contendo metadata.json e translation/",
    });
    if (typeof selected === "string" && selected.length > 0) {
      setPackageSource({ mode: "local_dir", path: selected });
      setLocalModalOpen(false);
      appendLog(`[INFO] Fonte local definida (pasta): ${selected}`);
    }
  };

  const handleInstall = async () => {
    if (busy || !inspection || !inspection.valid || !isTauriRuntime()) return;
    setBusy(true);
    setErrorBanner(null);
    setSuccessBanner(null);
    setProgressPct(2);
    setStatusMessage("Iniciando instalação da tradução PT-BR...");
    appendLog("[INFO] === Iniciando aplicação da tradução PT-BR ===");

    try {
      const result = await installTranslation({
        game_dir: inspection.path,
        source: packageSource,
        apply_5rf_patch: apply5rf,
      });
      await refreshInspection(inspection.path);
      const warnSuffix =
        result.warnings.length > 0
          ? ` Aviso: ${result.warnings.join(" ")}`
          : "";
      setSuccessBanner(
        `Tradução PT-BR v${result.version} aplicada com sucesso! (${result.total_changed_entries.toLocaleString("pt-BR")} falas atualizadas em ${result.modified_crsa_count} arquivos CRsa).${warnSuffix}`
      );
      setProgressPct(100);
      setStatusMessage(`Instalado com sucesso · v${result.version}`);
    } catch (err) {
      const msg = String(err);
      setErrorBanner(msg);
      setStatusMessage("Erro durante a instalação — consulte os detalhes.");
      appendLog(`[ERRO] ${msg}`);
    } finally {
      setBusy(false);
    }
  };

  const handleRestore = async () => {
    if (busy || !inspection || !isTauriRuntime()) return;
    setRestoreConfirmOpen(false);
    setBusy(true);
    setErrorBanner(null);
    setSuccessBanner(null);
    setProgressPct(15);

    try {
      const rep = await restoreOriginal(inspection.path);
      await refreshInspection(inspection.path);
      setSuccessBanner(
        rep.exe_restored
          ? "Inglês original restaurado com sucesso (overlay .drcruo1 e executável muvluv16.exe)."
          : "Inglês original restaurado com sucesso (overlay muvluv16.rio.drcruo1)."
      );
      setProgressPct(100);
    } catch (err) {
      const msg = String(err);
      setErrorBanner(msg);
      setStatusMessage("Falha ao restaurar backup original.");
      appendLog(`[ERRO] ${msg}`);
    } finally {
      setBusy(false);
    }
  };

  const handleVerifyIntegrity = async () => {
    if (busy || !inspection || !isTauriRuntime()) return;
    setBusy(true);
    setErrorBanner(null);
    setStatusMessage("Verificando SHA-256 e rodapé rUGP...");
    appendLog("[INFO] Verificando integridade dos arquivos do jogo...");
    try {
      const rep = await verifyIntegrity(inspection.path);
      setIntegrityReport(rep);
      appendLog(`[${rep.ok ? "OK" : "AVISO"}] ${rep.summary}`);
      setStatusMessage("Verificação de integridade concluída.");
    } catch (err) {
      const msg = String(err);
      setErrorBanner(msg);
      appendLog(`[ERRO] Integridade: ${msg}`);
    } finally {
      setBusy(false);
    }
  };

  const installedVersion = inspection?.installed_state?.version ?? null;
  const remoteVersion = remoteRelease?.version ?? null;

  const hasUpdateAvailable = useMemo(() => {
    return Boolean(
      installedVersion && remoteVersion && installedVersion !== remoteVersion
    );
  }, [installedVersion, remoteVersion]);

  const statusPill = useMemo(() => {
    if (busy) {
      return {
        label: "PROCESSANDO",
        color: "#f6c33b",
        bg: "rgba(246, 195, 59, 0.15)",
      };
    }
    if (!inspection || !inspection.valid) {
      return {
        label: "PENDENTE",
        color: "#ff5794",
        bg: "rgba(255, 87, 148, 0.16)",
      };
    }
    if (hasUpdateAvailable) {
      return {
        label: `ATUALIZAÇÃO v${remoteVersion}`,
        color: "#f6c33b",
        bg: "rgba(246, 195, 59, 0.15)",
      };
    }
    if (installedVersion) {
      return {
        label: `INSTALADO v${installedVersion}`,
        color: "#38e294",
        bg: "rgba(56, 226, 148, 0.14)",
      };
    }
    return {
      label: "PRONTO",
      color: "#38e294",
      bg: "rgba(56, 226, 148, 0.14)",
    };
  }, [busy, inspection, hasUpdateAvailable, installedVersion, remoteVersion]);

  const primaryButtonLabel = useMemo(() => {
    if (busy) return "APLICANDO...";
    if (hasUpdateAvailable) return "ATUALIZAR TRADUÇÃO";
    if (installedVersion) return "REINSTALAR TRADUÇÃO";
    return "INSTALAR TRADUÇÃO";
  }, [busy, hasUpdateAvailable, installedVersion]);

  const activeSegments = Math.round((progressPct / 100) * TOTAL_SEGMENTS);
  const displayVersion = remoteVersion ?? installedVersion ?? "1.0.0";

  const handleMinimize = () => {
    if (isTauriRuntime()) {
      void getCurrentWindow().minimize();
    }
  };

  const handleClose = () => {
    if (isTauriRuntime()) {
      void getCurrentWindow().close();
    }
  };

  const handleOpenRepo = () => {
    if (isTauriRuntime()) {
      void openUrl(repo.web_url);
    }
  };

  return (
    <div className="h-screen w-screen bg-[#0a0d16] border-2 border-[#2b3a58] flex flex-col overflow-hidden">
      {/* Barra superior customizada arrastável (sem função de som) */}
      <header
        data-tauri-drag-region
        className="h-[46px] shrink-0 bg-gradient-to-b from-[#101626] to-[#0b0f1b] border-b-2 border-[#24324c] flex items-center justify-between pr-3"
      >
        <div
          data-tauri-drag-region
          className="brand-ribbon-clip h-full pl-3.5 pr-8 bg-gradient-to-r from-[#f6c33b] to-[#ff9f2e] text-[#110c02] flex items-center gap-2.5 font-extrabold text-[13.5px] font-pixel"
        >
          <img
            src={GAME_ICON_URL}
            alt="Muv-Luv"
            className="w-[26px] h-[26px] rounded-[5px] object-cover border-[1.5px] border-[#110c02]/60 bg-[#141b2e]"
            onError={(e) => {
              (e.currentTarget as HTMLImageElement).style.display = "none";
            }}
          />
          <span data-tauri-drag-region>MUV-LUV PT-BR PATCHER</span>
        </div>

        <div className="flex items-center gap-1.5">
          <Button
            variant="win"
            onClick={handleMinimize}
            title="Minimizar"
            aria-label="Minimizar"
          >
            <span className="material-symbols-outlined !text-[18px]">
              remove
            </span>
          </Button>
          <Button
            variant="winClose"
            onClick={handleClose}
            title="Fechar"
            aria-label="Fechar"
          >
            <span className="material-symbols-outlined !text-[18px]">close</span>
          </Button>
        </div>
      </header>

      {/* Corpo dividido em diagonal */}
      <main className="split-backdrop flex-1 min-h-0 grid grid-cols-[340px_1fr]">
        {/* Lado esquerdo: Key Art oficial Muv-Luv */}
        <aside className="art-side-clip relative overflow-hidden border-r-4 border-[#f6c33b] bg-[#10172b]">
          <img
            src={POSTER_URL}
            alt="Muv-Luv Capa Oficial"
            className="w-full h-full object-cover object-[center_22%] block"
          />
          <div className="absolute top-4 left-4 px-2.5 py-1 bg-[#090d18]/92 border-2 border-[#3cc6ff] shadow-[4px_4px_0_#3cc6ff] text-[11px] text-white font-pixel">
            PT-BR · v{displayVersion}
          </div>

          <div className="absolute inset-x-0 bottom-0 pt-11 pr-10 pb-4 pl-4 bg-gradient-to-t from-[#060912]/98 via-[#060912]/75 to-transparent">
            {!logoFailed ? (
              <img
                src={LOGO_URL}
                alt="Muv-Luv"
                className="w-[186px] h-auto object-contain drop-shadow-[0_3px_12px_rgba(0,0,0,0.95)] mb-1.5 block"
                onError={() => setLogoFailed(true)}
              />
            ) : (
              <h1 className="font-pixel text-[28px] leading-none text-white mb-1.5">
                MUV-LUV
              </h1>
            )}
            <p className="text-[12px] text-[#dce8ff]">
              Extra &amp; Unlimited · Steam 2016 + DC 18+
            </p>
            <div className="mt-2 flex gap-1.5 font-mono-code">
              <span className="text-[10.5px] px-2 py-0.5 bg-[#ff5794]/22 border border-[#ff5794] text-[#ffd0e2] font-semibold rounded-[2px]">
                102 CENAS
              </span>
              <span className="text-[10.5px] px-2 py-0.5 bg-[#ff5794]/22 border border-[#ff5794] text-[#ffd0e2] font-semibold rounded-[2px]">
                63.242 FALAS
              </span>
            </div>
          </div>
        </aside>

        {/* Lado direito: Console de instalação */}
        <section className="py-4 pr-6 pl-2.5 flex flex-col gap-3 min-w-0">
          {/* Cabeçalho */}
          <div className="flex items-center justify-between border-b-2 border-[#3cc6ff]/35 pb-2">
            <h2 className="font-pixel text-[17px] font-normal text-white">
              PAINEL DE INSTALAÇÃO
            </h2>
            <span
              className="inline-flex items-center gap-1.5 text-[11.5px] px-2.5 py-0.5 rounded-[3px] font-mono-code border-[1.5px]"
              style={{
                color: statusPill.color,
                borderColor: statusPill.color,
                backgroundColor: statusPill.bg,
              }}
            >
              <span
                className="w-[7px] h-[7px] rounded-full"
                style={{ backgroundColor: statusPill.color }}
              />
              {statusPill.label}
            </span>
          </div>

          {/* Card 1: Pasta do Jogo */}
          <div className="bg-[#0d1220]/90 border-2 border-[#2a3b5e] border-l-[5px] border-l-[#3cc6ff] rounded-[5px] px-3.5 py-3 shadow-[4px_4px_0_rgba(0,0,0,0.45)]">
            <div className="flex items-center justify-between gap-2 mb-1.5">
              <span
                className="inline-flex items-center gap-1.5 text-[11px] font-pixel uppercase"
                style={{
                  color: inspection?.valid ? "#3cc6ff" : "#ff8cb6",
                }}
              >
                <span className="material-symbols-outlined !text-[17px]">
                  {inspection?.valid ? "check_circle" : "error"}
                </span>
                {inspection?.valid
                  ? "MUV-LUV + DIRECTOR'S CUT DETECTADO"
                  : inspection
                    ? "PASTA INCOMPLETA OU SEM DIRECTOR'S CUT"
                    : "SELECIONE A PASTA DO JOGO"}
              </span>
              <Button
                variant="flat"
                onClick={handleSelectGameFolder}
                disabled={busy}
              >
                <span className="material-symbols-outlined !text-[17px]">
                  folder_open
                </span>
                ALTERAR PASTA
              </Button>
            </div>

            <div className="font-mono-code text-[12px] text-[#e6f0ff] truncate">
              {inspection?.path ??
                "Nenhuma pasta selecionada — clique em ALTERAR PASTA"}
            </div>

            {inspection?.error_message && (
              <p className="mt-1.5 text-[11.5px] text-rose-300 leading-snug">
                {inspection.error_message}
              </p>
            )}
            {!inspection?.error_message && inspection?.warning_message && (
              <p className="mt-1.5 text-[11.5px] text-amber-300 leading-snug">
                {inspection.warning_message}
              </p>
            )}
          </div>

          {/* Card 2: Tradução, Backup e Opções */}
          <div className="bg-[#0d1220]/90 border-2 border-[#2a3b5e] border-l-[5px] border-l-[#ff5794] rounded-[5px] px-3.5 py-3 shadow-[4px_4px_0_rgba(0,0,0,0.45)]">
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="inline-flex items-center gap-1.5 text-[11px] font-pixel uppercase text-[#ff8cb6]">
                <span className="material-symbols-outlined !text-[17px]">
                  translate
                </span>
                TRADUÇÃO &amp; BACKUP SEGURO
              </span>
              <button
                type="button"
                onClick={handleOpenRepo}
                className="font-mono-code text-[11px] text-[#ff8cb6] hover:text-[#ffc2d9] cursor-pointer bg-transparent border-0 p-0"
              >
                {repo.owner}/{repo.name}
              </button>
            </div>

            <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[12px]">
              <div>
                <span className="text-[#b0bed8] block text-[10.5px]">
                  Status da tradução
                </span>
                <strong className="text-white font-semibold">
                  {installedVersion
                    ? hasUpdateAvailable
                      ? `v${installedVersion} (v${remoteVersion} disponível)`
                      : `Instalado v${installedVersion}`
                    : remoteVersion
                      ? `Não instalado (v${remoteVersion} disponível)`
                      : "Não instalado"}
                </strong>
              </div>
              <div>
                <span className="text-[#b0bed8] block text-[10.5px]">
                  Backup original
                </span>
                <strong className="text-[#38e294] font-semibold">
                  {inspection?.backup_exists
                    ? "✓ Backup seguro em _ptbr_backup"
                    : "Automático em _ptbr_backup/"}
                </strong>
              </div>
            </div>

            <div className="mt-2.5 pt-2.5 border-t border-dashed border-white/15 flex items-center justify-between gap-2 text-[11.5px] text-[#dde8fa]">
              <label
                className="inline-flex items-center gap-2 cursor-pointer"
                title="Ativa fallback GDI na fonte bitmap especial .5RF embutida em muvluv16.exe (corrige acentos raros). Faz backup automático de muvluv16.exe.orig."
              >
                <Checkbox
                  checked={apply5rf}
                  onCheckedChange={(v) => setApply5rf(v === true)}
                  disabled={busy}
                />
                <span>
                  Fallback GDI para fonte{" "}
                  <span className="font-mono-code text-[#f6c33b]">.5RF</span>{" "}
                  (acentos raros)
                </span>
              </label>

              {packageSource.mode === "online" ? (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => setLocalModalOpen(true)}
                  className="inline-flex items-center gap-1 text-[#3cc6ff] hover:text-[#8ee0ff] font-semibold text-[11.5px] whitespace-nowrap cursor-pointer bg-transparent border-0 p-0 disabled:opacity-45"
                >
                  <span className="material-symbols-outlined !text-[17px]">
                    folder_zip
                  </span>
                  Usar .zip / pasta local
                </button>
              ) : (
                <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-[#3cc6ff]/15 border border-[#3cc6ff]/50 text-[#8ee0ff] text-[11px] max-w-[205px]">
                  <span className="truncate font-mono-code">
                    {packageSource.mode === "local_zip" ? "ZIP: " : "Pasta: "}
                    {packageSource.path.split(/[\\/]/).pop()}
                  </span>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => setPackageSource({ mode: "online" })}
                    title="Voltar ao download online"
                    className="text-white hover:text-rose-300 cursor-pointer bg-transparent border-0 p-0 leading-none"
                  >
                    ×
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Feedback de erro / sucesso compacto */}
          {errorBanner && (
            <div className="px-3 py-2 rounded-[4px] bg-rose-950/85 border border-rose-400 text-rose-100 text-[11.5px] leading-snug">
              <strong>Erro:</strong> {errorBanner}
            </div>
          )}
          {successBanner && (
            <div className="px-3 py-2 rounded-[4px] bg-emerald-950/85 border border-emerald-400 text-emerald-100 text-[11.5px] leading-snug">
              {successBanner}
            </div>
          )}

          {/* Barra de progresso segmentada */}
          <div className="bg-[#080b14]/90 border-2 border-[#2b3c5c] rounded-[5px] px-3.5 py-2.5 flex flex-col gap-2">
            <div className="flex items-center justify-between gap-2 text-[12px]">
              <span className="truncate text-[#e6f0ff]">{statusMessage}</span>
              <strong className="font-mono-code text-[#f6c33b] shrink-0">
                {progressPct}%
              </strong>
            </div>
            <div className="grid grid-cols-20 gap-[3.5px] h-[12px]">
              {Array.from({ length: TOTAL_SEGMENTS }).map((_, i) => {
                const filled = i < activeSegments;
                const isLead = filled && i >= activeSegments - 3;
                return (
                  <span
                    key={i}
                    className="seg-skew rounded-[1px]"
                    style={{
                      backgroundColor: !filled
                        ? "rgba(255,255,255,0.09)"
                        : isLead
                          ? "#f6c33b"
                          : "#3cc6ff",
                    }}
                  />
                );
              })}
            </div>
          </div>

          {/* Ações principais */}
          <div className="flex gap-2.5 mt-auto">
            <Button
              variant="hero"
              className="flex-1 font-pixel"
              disabled={busy || !inspection?.valid}
              onClick={handleInstall}
            >
              <span className="material-symbols-outlined !text-[24px]">
                {hasUpdateAvailable ? "system_update_alt" : "download"}
              </span>
              {primaryButtonLabel}
            </Button>

            <Button
              variant="side"
              disabled={busy || !inspection?.backup_exists}
              onClick={() => setRestoreConfirmOpen(true)}
              title="Restaurar o jogo para o inglês original a partir de _ptbr_backup/"
            >
              <span className="material-symbols-outlined !text-[21px] text-[#f6c33b]">
                history
              </span>
              Restaurar
            </Button>

            <Button
              variant="side"
              disabled={busy || !inspection?.valid}
              onClick={handleVerifyIntegrity}
              title="Verificar SHA-256 e estrutura rUGP dos arquivos instalados"
            >
              <span className="material-symbols-outlined !text-[21px] text-[#38e294]">
                fact_check
              </span>
              Integridade
            </Button>
          </div>

          {/* Rodapé */}
          <div className="flex items-center justify-between text-[11.5px] text-[#b0bed8]">
            <span>
              {inspection?.free_space_bytes != null
                ? `Espaço livre no drive: ${formatBytes(inspection.free_space_bytes)}`
                : "Backup original sempre preservado em _ptbr_backup/"}
            </span>
            <button
              type="button"
              onClick={() => setLogDialogOpen(true)}
              className="inline-flex items-center gap-1 text-[#3cc6ff] hover:text-[#8ee0ff] font-semibold cursor-pointer bg-transparent border-0 p-0"
            >
              <span className="material-symbols-outlined !text-[18px]">
                terminal
              </span>
              Log técnico ({logs.length})
            </button>
          </div>
        </section>
      </main>

      {/* Modal: Pacote Offline (.zip ou pasta local) */}
      <Dialog open={localModalOpen} onOpenChange={setLocalModalOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>USAR PACOTE LOCAL (MODO OFFLINE)</DialogTitle>
            <DialogDescription>
              Escolha um arquivo <code>muvluv-ptbr-translation.zip</code>{" "}
              baixado manualmente ou uma pasta contendo{" "}
              <code>metadata.json</code> e <code>translation/*.json</code>.
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-2.5">
            <Button
              variant="side"
              className="w-full justify-start"
              onClick={handlePickLocalZip}
            >
              <span className="material-symbols-outlined !text-[21px] text-[#3cc6ff]">
                folder_zip
              </span>
              Selecionar arquivo .zip da tradução
            </Button>
            <Button
              variant="side"
              className="w-full justify-start"
              onClick={handlePickLocalDir}
            >
              <span className="material-symbols-outlined !text-[21px] text-[#f6c33b]">
                folder
              </span>
              Selecionar pasta local (metadata.json + translation/)
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Modal: Confirmação de Restauração */}
      <Dialog open={restoreConfirmOpen} onOpenChange={setRestoreConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>RESTAURAR INGLÊS ORIGINAL</DialogTitle>
            <DialogDescription>
              Isso restaurará <code>muvluv16.rio.drcruo1</code> (e{" "}
              <code>muvluv16.exe</code> caso o patch opcional <code>.5RF</code>{" "}
              tenha sido aplicado) usando o backup intacto salvo em{" "}
              <code>_ptbr_backup/</code>. Seus saves não são afetados.
            </DialogDescription>
          </DialogHeader>
          <div className="flex justify-end gap-2.5 mt-2">
            <Button
              variant="side"
              className="h-10"
              onClick={() => setRestoreConfirmOpen(false)}
            >
              Cancelar
            </Button>
            <Button
              variant="hero"
              className="h-10 px-5 font-pixel text-[12.5px]"
              onClick={handleRestore}
            >
              CONFIRMAR RESTAURAÇÃO
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Modal: Relatório de Integridade */}
      <Dialog
        open={integrityReport !== null}
        onOpenChange={(open) => {
          if (!open) setIntegrityReport(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>RELATÓRIO DE INTEGRIDADE</DialogTitle>
            <DialogDescription>
              Verificação criptográfica SHA-256 e estrutura do overlay rUGP.
            </DialogDescription>
          </DialogHeader>
          {integrityReport && (
            <div className="space-y-2.5 text-[12.5px]">
              <div
                className={`p-3 rounded border ${
                  integrityReport.ok
                    ? "bg-emerald-950/60 border-emerald-400 text-emerald-100"
                    : "bg-amber-950/60 border-amber-400 text-amber-100"
                }`}
              >
                {integrityReport.summary}
              </div>
              <div className="font-mono-code text-[11px] bg-[#060911] border border-[#263859] rounded p-3 space-y-1 text-[#b0bed8]">
                <div>
                  SHA-256 atual:{" "}
                  <span className="text-white break-all">
                    {integrityReport.current_ruo_sha256}
                  </span>
                </div>
                <div>
                  Tamanho:{" "}
                  <span className="text-white">
                    {integrityReport.current_ruo_size.toLocaleString("pt-BR")}{" "}
                    bytes
                  </span>
                </div>
                <div>
                  Backup _ptbr_backup:{" "}
                  <span
                    className={
                      integrityReport.backup_valid
                        ? "text-[#38e294]"
                        : "text-amber-300"
                    }
                  >
                    {integrityReport.backup_exists
                      ? integrityReport.backup_valid
                        ? "Íntegro (SHA-256 original validado)"
                        : "Presente, mas SHA-256 diverge"
                      : "Ainda não criado"}
                  </span>
                </div>
                <div>
                  Fallback GDI (.5RF):{" "}
                  <span className="text-white">
                    {integrityReport.exe_5rf_patched ? "Ativo" : "Original"}
                  </span>
                </div>
              </div>
              <div className="flex justify-end">
                <Button
                  variant="flat"
                  onClick={() => setIntegrityReport(null)}
                >
                  Fechar
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Modal: Log Técnico Detalhado */}
      <Dialog open={logDialogOpen} onOpenChange={setLogDialogOpen}>
        <DialogContent className="max-w-[640px]">
          <DialogHeader>
            <DialogTitle>LOG TÉCNICO DETALHADO</DialogTitle>
            <DialogDescription>
              Histórico completo de validações, checksums e etapas do motor
              rUGP.
            </DialogDescription>
          </DialogHeader>
          <div className="h-[260px] overflow-y-auto font-mono-code text-[11px] leading-relaxed bg-[#060911] border border-[#263859] rounded p-3 text-[#b4c6e4] select-text">
            {logs.map((line, idx) => (
              <div
                key={idx}
                className={
                  line.startsWith("[OK]")
                    ? "text-[#38e294]"
                    : line.startsWith("[ERRO]")
                      ? "text-rose-300"
                      : line.startsWith("[AVISO]")
                        ? "text-amber-300"
                        : "text-[#9fb4d8]"
                }
              >
                {line}
              </div>
            ))}
          </div>
          <div className="flex justify-between items-center mt-2">
            <Button
              variant="flat"
              onClick={() => {
                void navigator.clipboard.writeText(logs.join("\n"));
              }}
            >
              <span className="material-symbols-outlined !text-[16px]">
                content_copy
              </span>
              Copiar log
            </Button>
            <Button variant="side" className="h-9" onClick={() => setLogDialogOpen(false)}>
              Fechar
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
