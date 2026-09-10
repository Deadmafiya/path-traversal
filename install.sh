#!/usr/bin/env bash
#
# exploit-path-traversal — installer
#
# Installs the `exploit-path-traversal` command into your PATH.
# Strategy, in order of preference:
#   1. pipx        (isolated, cleanest)
#   2. project venv + symlink into ~/.local/bin   (fallback, always works)
#
# Usage:
#   ./install.sh                  # auto-detect and install
#   ./install.sh --prefix ~/.bin  # symlink target dir for the venv fallback
#   ./install.sh --venv-only      # skip pipx, force the venv approach
#   ./install.sh --print          # print what it would do, make no changes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMAND_NAME="exploit-path-traversal"
PREFIX="${HOME}/.local/bin"
VENV_ONLY=0
PRINT_ONLY=0

if [ -t 1 ]; then
    C_GREEN=$'\033[92m'; C_YELLOW=$'\033[93m'; C_CYAN=$'\033[96m'
    C_RED=$'\033[91m'; C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
    C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_RED=""; C_BOLD=""; C_RESET=""
fi
info() { printf '%s[*]%s %s\n' "$C_CYAN"   "$C_RESET" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
warn() { printf '%s[w]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)    PREFIX="${2:?}"; shift 2 ;;
        --venv-only) VENV_ONLY=1; shift ;;
        --print)     PRINT_ONLY=1; shift ;;
        -h|--help)   sed -n '2,14p' "$0"; exit 0 ;;
        *) err "unknown option: $1"; exit 1 ;;
    esac
done

command -v python3 >/dev/null 2>&1 || { err "python3 is required"; exit 1; }
info "python3 $(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"

if [ "$PRINT_ONLY" -eq 1 ]; then
    if [ "$VENV_ONLY" -eq 0 ] && command -v pipx >/dev/null 2>&1; then
        echo "would run: pipx install --force '${SCRIPT_DIR}'"
    else
        echo "would create venv at ${SCRIPT_DIR}/.venv and symlink ${PREFIX}/${COMMAND_NAME}"
    fi
    exit 0
fi

# --- 1. pipx ---------------------------------------------------------------
if [ "$VENV_ONLY" -eq 0 ] && command -v pipx >/dev/null 2>&1; then
    info "installing with pipx"
    pipx install --force "$SCRIPT_DIR"
    ok "installed. run: ${C_GREEN}${COMMAND_NAME} stage1 --help${C_RESET}"
    exit 0
fi

# --- 2. project venv + symlink ------------------------------------------
info "pipx not found — using a project virtualenv"
VENV="${SCRIPT_DIR}/.venv"
if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
fi
"${VENV}/bin/pip" install --upgrade pip >/dev/null
"${VENV}/bin/pip" install "${SCRIPT_DIR}[yaml]"

mkdir -p "$PREFIX"
ln -sf "${VENV}/bin/${COMMAND_NAME}" "${PREFIX}/${COMMAND_NAME}"
ok "symlinked ${PREFIX}/${COMMAND_NAME} -> ${VENV}/bin/${COMMAND_NAME}"

if ! printf '%s' "$PATH" | tr ':' '\n' | grep -qx "$PREFIX"; then
    warn "${PREFIX} is not in your PATH. Add it:"
    warn "  echo 'export PATH=\"\$PATH:${PREFIX}\"' >> ~/.bashrc && source ~/.bashrc"
fi

if "${PREFIX}/${COMMAND_NAME}" --version >/dev/null 2>&1; then
    ok "smoke test passed. run: ${C_GREEN}${COMMAND_NAME} stage1 --help${C_RESET}"
else
    err "smoke test failed"
    exit 1
fi
