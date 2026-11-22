# FrameAssembly Shell Tab Completions

This directory provides context-aware Tab completion scripts for the `frameassembly` CLI across **Bash**, **Zsh**, **Fish**, and **PowerShell**:

- **Position 1 (`frameassembly <TAB>`)**: Completes `.frasm` files and directories alongside `show`, `reverse`, `update`, `version`, and `help`.
- **`frameassembly <input.frasm> [output.pcap]`**: Completes `.frasm` files and directories on argument 1, and `.pcap` / `.pcapng` files and directories on argument 2.
- **`frameassembly show <input.frasm>`**: Completes `.frasm` files and directories on argument 1.
- **`frameassembly reverse <input.pcap> [output.frasm]`**: Completes `.pcap` / `.pcapng` files and directories on argument 1, and `.frasm` files and directories on argument 2.
- **`frameassembly update`**: Takes zero flags or positional arguments, updates the installed CLI via Cargo/`rustup` or a SHA-256-verified GitHub Release binary, and automatically refreshes any already-installed Bash, Zsh, Fish, or PowerShell completion files on disk.
- **`frameassembly help [subcommand]`**: Completes `show`, `reverse`, `update`, `version`, and `help`.

Debian `.deb` packages and the `install.sh` bootstrap installer install Bash, Zsh, and Fish completions automatically, `install.ps1` installs PowerShell completions on Windows, and `frameassembly update` (zero flags or positional arguments) automatically refreshes any already-installed Bash, Zsh, Fish, or PowerShell completion files on disk when updating via Cargo/`rustup` or verified GitHub Release binaries. For manual setup, use the commands below.

## Manual Installation

### Bash

```bash
mkdir -p "${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions"
cp contrib/completions/frameassembly.bash "${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/frameassembly"
```

### Zsh

```zsh
mkdir -p "${ZDOTDIR:-$HOME}/.zfunc"
cp contrib/completions/_frameassembly "${ZDOTDIR:-$HOME}/.zfunc/_frameassembly"
# Ensure ~/.zfunc is registered before compinit in ~/.zshrc:
# fpath=("$HOME/.zfunc" $fpath)
# autoload -Uz compinit && compinit
```

### Fish

```fish
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions"
cp contrib/completions/frameassembly.fish "${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/frameassembly.fish"
```

### PowerShell

```powershell
# Append or dot-source from your PowerShell $PROFILE:
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $PROFILE) | Out-Null
Copy-Item contrib/completions/frameassembly.ps1 (Join-Path (Split-Path -Parent $PROFILE) "frameassembly.ps1")
Add-Content -Path $PROFILE -Value '. (Join-Path (Split-Path -Parent $PROFILE) "frameassembly.ps1")'
```
