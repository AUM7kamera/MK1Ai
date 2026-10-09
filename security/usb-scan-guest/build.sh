#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'Usage: %s --base-image alpine:TAG@sha256:DIGEST --apk-repository SNAPSHOT_URL --clamav-db DIR --output DIR\n' "$0" >&2
}

base_image=""
apk_repository=""
clamav_db=""
output_dir=""
while (($#)); do
    case "$1" in
        --base-image) base_image="${2:-}"; shift 2 ;;
        --apk-repository) apk_repository="${2:-}"; shift 2 ;;
        --clamav-db) clamav_db="${2:-}"; shift 2 ;;
        --output) output_dir="${2:-}"; shift 2 ;;
        *) usage; exit 2 ;;
    esac
done

if [[ ! "$base_image" =~ ^.+@sha256:[a-fA-F0-9]{64}$ \
    || "$apk_repository" != https://* \
    || -z "$clamav_db" || -z "$output_dir" ]]; then
    usage
    exit 2
fi
apk_repository="${apk_repository%/}"
if [[ ! -d "$clamav_db" || -L "$clamav_db" ]]; then
    printf 'ClamAV database must be a directory containing a pinned CVD/CLD database.\n' >&2
    exit 2
fi
shopt -s nullglob
database_files=("$clamav_db"/*.cvd "$clamav_db"/*.cld)
if ((${#database_files[@]} < 2)); then
    printf 'At least two pinned ClamAV CVD/CLD database files are required.\n' >&2
    exit 2
fi
for database_file in "${database_files[@]}"; do
    if [[ ! -f "$database_file" || -L "$database_file" ]]; then
        printf 'ClamAV database entries must be regular, non-symlink files.\n' >&2
        exit 2
    fi
done
has_main_db=0
has_daily_db=0
for database_file in "${database_files[@]}"; do
    [[ "${database_file##*/}" == main.cvd || "${database_file##*/}" == main.cld ]] && has_main_db=1
    [[ "${database_file##*/}" == daily.cvd || "${database_file##*/}" == daily.cld ]] && has_daily_db=1
done
if (( !has_main_db || !has_daily_db )); then
    printf 'ClamAV database must include both main and daily CVD/CLD files.\n' >&2
    exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
    printf 'docker is required.\n' >&2
    exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
image_tag="mk1-usb-scan-guest:build"
mkdir -p "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd)"
build_context="$(mktemp -d)"
temporary_dir=""
trap 'if [[ -n "$temporary_dir" ]]; then rm -rf "$temporary_dir"; fi; rm -rf "$build_context"' EXIT
mkdir -p "$build_context/clamav-db"
cp -- "$script_dir/usb-scan-init" "$build_context/usb-scan-init"
cp -- "${database_files[@]}" "$build_context/clamav-db/"
docker build \
    --pull \
    --build-arg "ALPINE_IMAGE=$base_image" \
    --build-arg "APK_REPOSITORY=$apk_repository" \
    --tag "$image_tag" \
    --file "$script_dir/Dockerfile" \
    "$build_context"

temporary_dir="$(mktemp -d)"
docker run --rm \
    --network none \
    --read-only \
    --mount "type=bind,src=$temporary_dir,dst=/out" \
    "$image_tag" \
    /bin/sh -ec '
        cp /boot/vmlinuz-lts /out/vmlinuz
        mkdir -p /out/dev
        mknod /out/dev/console c 5 1
        mknod /out/dev/null c 1 3
        chmod 0600 /out/dev/console
        chmod 0666 /out/dev/null
        cd /
        find . -xdev \( -path ./out -o -path ./dev \) -prune -o -print0 |
            LC_ALL=C sort -z |
            cpio --null --reproducible -o -H newc --quiet > /out/rootfs.cpio
        cd /out
        find dev -print0 |
            LC_ALL=C sort -z |
            cpio --null --reproducible -o -H newc --quiet >> /out/rootfs.cpio
        gzip -n -9 -c /out/rootfs.cpio > /out/initramfs.cpio.gz
        rm /out/rootfs.cpio
    '

install -m 0644 "$temporary_dir/vmlinuz" "$output_dir/vmlinuz"
install -m 0644 "$temporary_dir/initramfs.cpio.gz" "$output_dir/initramfs.cpio.gz"
kernel_hash="$(sha256sum "$output_dir/vmlinuz" | cut -d ' ' -f 1)"
initramfs_hash="$(sha256sum "$output_dir/initramfs.cpio.gz" | cut -d ' ' -f 1)"
manifest_path="$output_dir/manifest.json"
printf '{\n  "format": 1,\n  "kernel": {"file": "vmlinuz", "sha256": "%s"},\n  "initramfs": {"file": "initramfs.cpio.gz", "sha256": "%s"}\n}\n' \
    "$kernel_hash" "$initramfs_hash" > "$manifest_path"
chmod 0644 "$manifest_path"
printf 'Unsigned USB scan guest written to %s; transfer it to the offline signer.\n' "$output_dir"
