#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

compile_flags=()
require_oqs=0
check_only=0
for argument in "$@"; do
    case "$argument" in
        --check) check_only=1 ;;
        --require-oqs) require_oqs=1 ;;
        *)
            printf '未対応の引数です: %s\n' "$argument" >&2
            exit 2
            ;;
    esac
done
case "$(uname -s)" in
    Darwin)
        if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists ncurses; then
            read -r -a compile_flags <<<"$(pkg-config --cflags --libs ncurses)"
        else
            compile_flags=(-lncurses)
        fi
        ;;
    Linux)
        if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists ncursesw; then
            read -r -a compile_flags <<<"$(pkg-config --cflags --libs ncursesw)"
        elif command -v pkg-config >/dev/null 2>&1 && pkg-config --exists ncurses; then
            read -r -a compile_flags <<<"$(pkg-config --cflags --libs ncurses)"
        else
            printf 'ncurses開発パッケージが必要です。\n' >&2
            exit 1
        fi
        ;;
    *)
        printf 'この起動スクリプトはLinux/ChromeOS Linux環境とmacOSに対応します。Windowsではmk1-gui.cmdからWSLを使用してください。\n' >&2
        exit 1
        ;;
esac

if ! command -v cc >/dev/null 2>&1; then
    printf 'Cコンパイラが必要です。\n' >&2
    exit 1
fi
if ! command -v pkg-config >/dev/null 2>&1 || ! pkg-config --exists openssl; then
    printf 'OpenSSL開発パッケージとpkg-configが必要です。\n' >&2
    exit 1
fi
read -r -a openssl_flags <<<"$(pkg-config --cflags --libs openssl)"
oqs_flags=()
oqs_sources=()
if pkg-config --exists liboqs; then
    read -r -a oqs_flags <<<"$(pkg-config --cflags --libs liboqs)"
    oqs_sources=(mk1_tunnel_oqs.c)
else
    printf '警告: liboqs が未検出です。PQC provider なしでビルドします。\n' >&2
    if ((require_oqs)); then
        printf 'liboqs が必要です (--require-oqs)。\n' >&2
        exit 1
    fi
fi

temporary_binary="$(mktemp "${TMPDIR:-/tmp}/mk1-panel.XXXXXX")"
trap 'rm -f "$temporary_binary"' EXIT
cc -std=c11 -O2 -Wall -Wextra -Werror -pthread \
    mk1_panel.c mk1_memory_guard.c mk1_path_trust.c mk1_tunnel.c \
    ${oqs_sources[@]+"${oqs_sources[@]}"} \
    ${compile_flags[@]+"${compile_flags[@]}"} \
    ${openssl_flags[@]+"${openssl_flags[@]}"} \
    ${oqs_flags[@]+"${oqs_flags[@]}"} -o "$temporary_binary"
chmod 700 "$temporary_binary"

if ((check_only)); then
    printf 'C操作パネルのコンパイルに成功しました (%s)。\n' "$(uname -s)"
    exit 0
fi

if [[ -x "$SCRIPT_DIR/.venv-mk1/bin/python" ]]; then
    export MK1_PYTHON_BIN="$SCRIPT_DIR/.venv-mk1/bin/python"
else
    export MK1_PYTHON_BIN="${MK1_PYTHON_BIN:-python3}"
fi

export MK1_PANEL_LAUNCHER=explicit-command
"$temporary_binary"
