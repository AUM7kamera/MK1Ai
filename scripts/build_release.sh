#!/usr/bin/env bash
# Release packaging automation. Contact: 山田 悠 (Yu Yamada).
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
PRIVATE_KEY="${1:-${MK1AI_ED25519_PRIVATE_KEY_FILE:-}}"
OUTPUT_DIR="${2:-${MK1AI_RELEASE_DIR:-$ROOT_DIR/dist/mk1ai-release}}"

if [[ -z "$PRIVATE_KEY" || ! -f "$PRIVATE_KEY" ]]; then
    echo "Provide an Ed25519 private key file as the first argument or MK1AI_ED25519_PRIVATE_KEY_FILE." >&2
    exit 2
fi
if [[ -e "$OUTPUT_DIR" ]]; then
    echo "Refusing to overwrite existing release directory: $OUTPUT_DIR" >&2
    exit 2
fi
for tool in python3 openssl strip make stat; do
    command -v "$tool" >/dev/null || { echo "Required tool not found: $tool" >&2; exit 2; }
done
python3 -c 'import os, stat, sys; sys.exit(bool(os.stat(sys.argv[1]).st_mode & (stat.S_IRWXG | stat.S_IRWXO)))' "$PRIVATE_KEY" || {
    echo "The signing private key must not be accessible to group or other users." >&2
    exit 2
}
python3 -c 'import Cython' || {
    echo "Cython is required only for release builds; install it in the selected build environment." >&2
    exit 2
}

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mk1ai-release.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT
STAGE="$WORK_DIR/package"
mkdir -p "$STAGE/runtime"

openssl pkey -in "$PRIVATE_KEY" -passin pass: -check -noout >/dev/null
openssl pkey -in "$PRIVATE_KEY" -pubout -out "$STAGE/release-signing.pub"

cat > "$WORK_DIR/setup.py" <<'PY'
import os
from Cython.Build import cythonize
from setuptools import Extension, setup

modules = ("airgap_ai_defender", "mk1_usb_guard")
setup(
    name="mk1ai-release",
    ext_modules=cythonize(
        [Extension(name, [f"{name}.py"]) for name in modules],
        build_dir=os.path.join(os.environ["MK1AI_RELEASE_WORK"], "cython-generated"),
        compiler_directives={"language_level": "3"},
    ),
)
PY
(cd "$ROOT_DIR" && MK1AI_RELEASE_WORK="$WORK_DIR" python3 "$WORK_DIR/setup.py" build_ext \
    --build-lib "$STAGE/runtime" --build-temp "$WORK_DIR/objects")

for source in mk1_map.py mk1_memory_guard.py mk1_secure_transport.py; do
    cp -- "$ROOT_DIR/$source" "$STAGE/runtime/$source"
done

make -C "$ROOT_DIR" panel BUILD_DIR="$WORK_DIR/native-build"
cp -- "$WORK_DIR/native-build/mk1-panel" "$STAGE/mk1-panel"
strip --strip-unneeded "$STAGE/mk1-panel"
find "$STAGE/runtime" -maxdepth 1 -type f -name '*.so' -exec strip --strip-unneeded {} +

while IFS= read -r model_path; do
    [[ -z "$model_path" ]] && continue
    case "$model_path" in
        /*|../*|*/../*|*/..)
            echo "Model paths must be repository-relative and must not traverse directories: $model_path" >&2
            exit 2
            ;;
    esac
    [[ -f "$ROOT_DIR/$model_path" ]] || {
        echo "Model checkpoint not found: $model_path" >&2
        exit 2
    }
    [[ ! -L "$ROOT_DIR/$model_path" ]] || {
        echo "Symbolic-link model paths are not accepted: $model_path" >&2
        exit 2
    }
    install -D -m 0644 -- "$ROOT_DIR/$model_path" "$STAGE/runtime/$model_path"
done <<< "${MK1AI_MODEL_FILES:-}"

python3 "$ROOT_DIR/scripts/sign_release.py" "$STAGE" "$PRIVATE_KEY"
mkdir -p -- "$(dirname -- "$OUTPUT_DIR")"
mv -- "$STAGE" "$OUTPUT_DIR"
echo "Signed release bundle created at $OUTPUT_DIR"
