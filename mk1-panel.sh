#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

compile_flags=()
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

temporary_binary="$(mktemp "${TMPDIR:-/tmp}/mk1-panel.XXXXXX")"
trap 'rm -f "$temporary_binary"' EXIT
cc -std=c11 -O2 -Wall -Wextra -Werror mk1_panel.c "${compile_flags[@]}" -o "$temporary_binary"
chmod 700 "$temporary_binary"

if [[ "${1:-}" == "--check" ]]; then
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
