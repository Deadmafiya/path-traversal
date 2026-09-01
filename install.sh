#!/usr/bin/env bash
#
# path-traversal — installer
# Installs the path-traversal tool as a command available in your PATH.
#
# Works on any Linux with Python 3 (no external dependencies).
# By default installs to ~/.local/bin (no sudo needed).
# With sudo / root, installs to /usr/local/bin.
#
# Usage:
#   ./install.sh                 # auto-detect, install
#   ./install.sh --prefix ~/.bin # custom directory
#   ./install.sh --print         # just print where it WOULD install
#   ./install.sh --no-verify     # skip the post-install smoke test

set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────────────
PREFIX=""
DO_VERIFY=1
INSTALL_DIR=""
VERSION="1.8.0"

# The directory this script lives in (the project root).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_SRC="${SCRIPT_DIR}/path-traversal.py"
COMMAND_NAME="path-traversal"

# ── Colors (best effort, safe when not a tty) ───────────────────────────────
if [ -t 1 ]; then
    C_GREEN=$'\033[92m'; C_YELLOW=$'\033[93m'; C_CYAN=$'\033[96m'
    C_RED=$'\033[91m'; C_GRAY=$'\033[90m'; C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
    C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_RED=""; C_GRAY=""; C_BOLD=""; C_RESET=""
fi

info()  { printf '%s[*]%s %s\n'   "$C_CYAN" "$C_RESET" "$*"; }
ok()    { printf '%s[+]%s %s\n'   "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '%s[w]%s %s\n'   "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()   { printf '%s[x]%s %s\n'   "$C_RED" "$C_RESET" "$*" >&2; }

# ── Args ────────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: $0 [options]

Installs the '${COMMAND_NAME}' command.

Options:
  --prefix DIR       Install into DIR instead of auto-detecting
  --print            Print the install location and exit (no changes)
  --no-verify        Skip the post-install smoke test
  -h, --help         Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="${2:-}"; shift 2 ;;
        --print)  INSTALL_DIR="print"; shift ;;
        --no-verify) DO_VERIFY=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# ── Prereqs ─────────────────────────────────────────────────────────────────
check_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        err "python3 is required but was not found on PATH."
        err "Install it first, e.g.:  sudo pacman -S python  (Arch),"
        err "                          sudo apt install python3 (Debian/Ubuntu),"
        err "                          sudo dnf install python3 (Fedora)"
        exit 1
    fi
    local pyver
    pyver="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    info "Found python3 ${pyver}"
    # We use zero third-party deps, so any 3.x is fine.
}

# ── Resolve install dir ─────────────────────────────────────────────────────
resolve_install_dir() {
    if [ -n "$PREFIX" ]; then
        INSTALL_DIR="$PREFIX"
    elif [ "$(id -u)" -eq 0 ]; then
        INSTALL_DIR="/usr/local/bin"
    else
        # Prefer ~/.local/bin (systemd, most distros include it in PATH).
        if [ -d "$HOME/.local/bin" ] || printf '%s' "$PATH" | tr ':' '\n' | grep -qx "$HOME/.local/bin"; then
            INSTALL_DIR="$HOME/.local/bin"
        else
            INSTALL_DIR="$HOME/.local/bin"
            warn "$HOME/.local/bin not in PATH — creating it. Add it to PATH if needed:"
            warn "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
        fi
    fi
    mkdir -p "$INSTALL_DIR"
}

# ── Install ─────────────────────────────────────────────────────────────────
do_install() {
    if [ ! -f "$TOOL_SRC" ]; then
        err "Could not find ${TOOL_SRC}."
        err "Run this script from inside the project directory (where path-traversal.py lives)."
        exit 1
    fi

    local dest="${INSTALL_DIR}/${COMMAND_NAME}"

    info "Installing ${COMMAND_NAME} → ${dest}"
    # Symlink so the tool updates when the repo does; fall back to a copy.
    if ln -sf "$TOOL_SRC" "$dest" 2>/dev/null; then
        ok "Created symlink: ${dest} -> ${TOOL_SRC}"
    else
        cp "$TOOL_SRC" "$dest"
        chmod +x "$dest"
        ok "Copied tool to: ${dest}"
    fi
    chmod +x "$TOOL_SRC"

    # Remove any stale pycache so a moved file never shadows the source.
    if [ -d "${SCRIPT_DIR}/__pycache__" ]; then
        rm -rf "${SCRIPT_DIR}/__pycache__"
    fi
}

# ── Verify ──────────────────────────────────────────────────────────────────
do_verify() {
    info "Verifying installation..."
    if ! command -v "${INSTALL_DIR}/${COMMAND_NAME}" >/dev/null 2>&1 && \
       ! "${INSTALL_DIR}/${COMMAND_NAME}" --help >/dev/null 2>&1; then
        # --help check above is the real gate; just ensure exec works
        :
    fi

    if "${INSTALL_DIR}/${COMMAND_NAME}" --help >/dev/null 2>&1; then
        ok "Smoke test passed: '${COMMAND_NAME} --help' works."
    else
        err "Smoke test failed. Check that '${INSTALL_DIR}' is in your PATH."
        exit 1
    fi
}

# ── Main ────────────────────────────────────────────────────────────────────
main() {
    echo
    info "${C_BOLD}path-traversal v${VERSION}${C_RESET} — installer"

    if [ "$INSTALL_DIR" = "print" ]; then
        resolve_install_dir
        printf '%s\n' "$INSTALL_DIR"
        exit 0
    fi

    check_python
    resolve_install_dir
    do_install

    if [ "$DO_VERIFY" -eq 1 ]; then
        do_verify
    fi

    echo
    ok "Done. Run it:"
    echo "    ${C_GREEN}${COMMAND_NAME} -u 'http://example.com/file?file='${C_RESET}"
    echo
    if ! printf '%s' "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
        warn "NOTE: ${INSTALL_DIR} is not in your PATH yet."
        warn "Add it with:  echo 'export PATH=\"\${PATH}:${INSTALL_DIR}\"' >> ~/.bashrc && source ~/.bashrc"
    fi
}

main "$@"
