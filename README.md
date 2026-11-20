# Muv-Luv PT-BR Patcher (`muvluv-ptbr-instalador`)

Instalador gráfico leve e em **1 clique** feito em **Tauri v2 + Rust puro + React** para aplicar a tradução **PT-BR** de **Muv-Luv (Extra & Unlimited — Steam 2016 + Director's Cut 18+)** diretamente na máquina do jogador no Windows, sem precisar de Python, Go ou terminal.

## Recursos

- **Motor rUGP em Rust puro (`crates/muvluv-core`)**: lê `muvluv16.rio.ici`, `muvluv16.rio` e `muvluv16.rio.drcruo1`, reconstrói todos os registros `CRsa` traduzidos com recálculo completo dos checksums rUGP e executa readback byte a byte antes da troca atômica do arquivo final.
- **Autodetecção da pasta do jogo**: lê o Registro do Windows (Steam / App `449830` / AGES3), `libraryfolders.vdf` e caminhos comuns, além de permitir seleção manual.
- **Backup seguro e restauração em 1 clique**: preserva permanentemente o overlay original em `<gameDir>/_ptbr_backup/muvluv16.rio.drcruo1.orig` (nunca sobrescreve `.orig` existente) e sempre compila atualizações a partir do arquivo limpo.
- **Download automático + Modo Offline**: baixa automaticamente `muvluv-ptbr-translation.zip` da Release mais recente de [`gabriexlss/muvluv-ptbr-traducao`](https://github.com/gabriexlss/muvluv-ptbr-traducao) e valida o SHA-256 de todos os 102 JSONs (`63.242` entradas) antes de tocar no jogo — ou permite selecionar um `.zip` / pasta local.
- **Patch opcional `.5RF` (fallback GDI)**: checkbox opcional para corrigir acentos raros na fonte bitmap embutida em `muvluv16.exe`, com validação rigorosa de SHA-256 + contexto de bytes e backup automático em `_ptbr_backup/muvluv16.exe.orig`.

## Estrutura do Projeto

- `crates/muvluv-core/`: motor rUGP (`crypto`, `ici`, `ruo`, `crsa`), pipeline de extração/validação/compilação, backup seguro e patch `.5RF`.
- `src-tauri/`: aplicação Tauri v2, comandos IPC, autodetecção Steam/Win32 e download de releases (`src-tauri/src/config.rs`).
- `src/`: interface React + TypeScript + Tailwind CSS + shadcn/ui.
- `.github/workflows/build-windows.yml`: build automático no `windows-latest` gerando instalador NSIS (`.exe`), executável portátil e `SHA256SUMS.txt`.

## Desenvolvimento (Linux / WSL)

```bash
pnpm install
pnpm build
cargo test -p muvluv-core
cargo check --workspace
```

## Publicar Nova Release Windows

```bash
git tag v1.0.0
git push origin main --tags
```

O workflow `.github/workflows/build-windows.yml` compila automaticamente no Windows e anexa o instalador NSIS e o binário portátil na GitHub Release.
