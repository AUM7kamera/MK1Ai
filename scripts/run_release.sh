#!/usr/bin/env bash
# Verify before launching a command from a signed release bundle.
set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "Usage: run_release.sh BUNDLE_DIR TRUSTED_PUBLIC_KEY COMMAND [ARG ...]" >&2
    exit 2
fi

BUNDLE_DIR="$1"
TRUSTED_PUBLIC_KEY="$2"
shift 2
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
python3 "$SCRIPT_DIR/verify_release.py" \
    --bundle "$BUNDLE_DIR" --public-key "$TRUSTED_PUBLIC_KEY"
exec "$@"
