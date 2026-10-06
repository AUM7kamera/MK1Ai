#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1
chmod +x "$0" 2>/dev/null || true

mkdir -p ai_data
CONFIG_PATH="ai_data/config.json"
python3 - "$CONFIG_PATH" <<'PY'
import json
import os
import sys
import tempfile
from pathlib import Path

config_path = Path(sys.argv[1])
try:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        config = {}
except (OSError, json.JSONDecodeError):
    config = {}

saved_endpoint = str(config.get("colab_endpoint", "") or "").strip()
if saved_endpoint:
    prompt = f"Colab受信用URL [Enterで前回値を使用: {saved_endpoint}]: "
else:
    prompt = "Colab受信用URL: "

try:
    with open("/dev/tty", "w", encoding="utf-8") as terminal_output, \
         open("/dev/tty", "r", encoding="utf-8") as terminal_input:
        terminal_output.write(prompt)
        terminal_output.flush()
        endpoint_line = terminal_input.readline()
        if not endpoint_line:
            raise EOFError
        endpoint_input = endpoint_line.strip()
except (KeyboardInterrupt, EOFError):
    print("\n入力がキャンセルされました。設定は変更せず終了します。", file=sys.stderr)
    raise SystemExit(1)
except OSError as exc:
    print(f"対話端末を利用できません。設定は変更せず終了します ({exc})", file=sys.stderr)
    raise SystemExit(1)

config.update({
    "ram_limit": 1500,
    "mode": "RSI",
    "compact_log": True,
    "colab_endpoint": endpoint_input or saved_endpoint,
})

temporary_path = None
try:
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{config_path.name}.", suffix=".tmp", dir=config_path.parent,
    )
    temporary_path = Path(temporary_name)
    os.fchmod(file_descriptor, 0o600)
    with os.fdopen(file_descriptor, "w", encoding="utf-8") as config_file:
        config_file.write(json.dumps(config, ensure_ascii=False, indent=2) + "\n")
        config_file.flush()
        os.fsync(config_file.fileno())
    os.replace(temporary_path, config_path)
except OSError as exc:
    if temporary_path is not None:
        temporary_path.unlink(missing_ok=True)
    print(f"設定を保存できませんでした: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY

exec python3 airgap_ai_defender.py --mode RSI --ram-limit 1500 --compact-log