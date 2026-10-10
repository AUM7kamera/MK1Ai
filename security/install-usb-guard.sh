#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run this installer as root.\n' >&2
    exit 77
fi
command -v usbguard >/dev/null 2>&1 || {
    printf 'USBGuard must be installed from the approved OS repository first.\n' >&2
    exit 69
}
command -v update-grub >/dev/null 2>&1 || {
    printf 'This installer requires a Debian/Ubuntu update-grub environment.\n' >&2
    exit 69
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install -d -o root -g root -m 0755 /etc/usbguard /etc/default/grub.d
install -o root -g root -m 0600 \
    "$script_dir/usbguard/usbguard-daemon.conf" /etc/usbguard/usbguard-daemon.conf
install -o root -g root -m 0600 \
    "$script_dir/usbguard/rules.conf" /etc/usbguard/rules.conf

kernel_args=/etc/default/grub.d/99-mk1ai-usb.cfg
if [[ -L $kernel_args ]]; then
    printf 'Refusing symlinked kernel argument file: %s\n' "$kernel_args" >&2
    exit 1
fi
temporary_args=$(mktemp /etc/default/grub.d/.mk1ai-usb.XXXXXX)
trap 'rm -f -- "$temporary_args"' EXIT
cat >"$temporary_args" <<'EOF'
GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX:+$GRUB_CMDLINE_LINUX }usbcore.authorized_default=0"
EOF
chown root:root "$temporary_args"
chmod 0644 "$temporary_args"
mv -f -- "$temporary_args" "$kernel_args"
trap - EXIT

update-grub

authorized_default=/sys/module/usbcore/parameters/authorized_default
if [[ ! -w $authorized_default ]]; then
    printf 'Cannot set usbcore.authorized_default at runtime; do not treat USB as default-deny until reboot verification.\n' >&2
    exit 1
fi
printf '0\n' >"$authorized_default"
[[ $(<"$authorized_default") == 0 ]] || {
    printf 'usbcore.authorized_default did not verify as 0.\n' >&2
    exit 1
}

systemctl enable --now usbguard.service
systemctl is-active --quiet usbguard.service || {
    printf 'USBGuard did not become active.\n' >&2
    exit 1
}
printf 'USBGuard policy is active. Reboot and verify /proc/cmdline and usbcore.authorized_default before claiming boot-time USB default-deny.\n'
