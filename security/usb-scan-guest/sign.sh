#!/usr/bin/env bash
set -euo pipefail

if (($# != 2)); then
    printf 'Usage: %s SIGNING_PRIVATE_KEY GUEST_IMAGE_DIRECTORY\n' "$0" >&2
    exit 2
fi

signing_key="$1"
image_dir="$2"
if [[ ! -f "$signing_key" || -L "$signing_key" || ! -d "$image_dir" || -L "$image_dir" ]]; then
    printf 'Signing key and guest directory must be regular, non-symlink paths.\n' >&2
    exit 2
fi
key_mode="$(stat -c '%a' "$signing_key")"
if (( (8#$key_mode & 077) != 0 )); then
    printf 'Signing key must not be accessible by group or other users (chmod 600).\n' >&2
    exit 2
fi
command -v openssl >/dev/null 2>&1 || {
    printf 'openssl is required.\n' >&2
    exit 2
}

for asset in vmlinuz initramfs.cpio.gz manifest.json; do
    if [[ ! -f "$image_dir/$asset" || -L "$image_dir/$asset" ]]; then
        printf 'Guest asset is missing or not a regular file: %s\n' "$asset" >&2
        exit 2
    fi
done
kernel_hash="$(sha256sum "$image_dir/vmlinuz" | cut -d ' ' -f 1)"
initramfs_hash="$(sha256sum "$image_dir/initramfs.cpio.gz" | cut -d ' ' -f 1)"
expected_manifest="$(printf '{\n  "format": 1,\n  "kernel": {"file": "vmlinuz", "sha256": "%s"},\n  "initramfs": {"file": "initramfs.cpio.gz", "sha256": "%s"}\n}\n' \
    "$kernel_hash" "$initramfs_hash")"
if [[ "$(cat "$image_dir/manifest.json")" != "$expected_manifest" ]]; then
    printf 'Manifest does not exactly describe the guest image files.\n' >&2
    exit 1
fi

openssl pkeyutl -sign -rawin -inkey "$signing_key" \
    -in "$image_dir/manifest.json" -out "$image_dir/manifest.sig"
chmod 0644 "$image_dir/manifest.sig"
openssl pkey -in "$signing_key" -pubout -out "$image_dir/mk1-usb-scan-signing.pub"
chmod 0644 "$image_dir/mk1-usb-scan-signing.pub"
printf 'Manifest signed. Provision the public key out-of-band as /etc/mk1ai/usb-scan-signing.pub.\n'
