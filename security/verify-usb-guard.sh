#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run this verifier as root.\n' >&2
    exit 77
fi

cmdline=$(</proc/cmdline)
case " $cmdline " in
    *" usbcore.authorized_default=0 "*) ;;
    *)
        printf 'usbcore.authorized_default=0 is absent from the running kernel command line.\n' >&2
        exit 1
        ;;
esac

authorized_default=/sys/module/usbcore/parameters/authorized_default
if [[ ! -r $authorized_default || $(<"$authorized_default") != 0 ]]; then
    printf 'usbcore.authorized_default is not verified as 0.\n' >&2
    exit 1
fi
systemctl is-active --quiet usbguard.service || {
    printf 'USBGuard is not active.\n' >&2
    exit 1
}
for file in /etc/usbguard/usbguard-daemon.conf /etc/usbguard/rules.conf; do
    if [[ ! -f $file || -L $file || $(stat -c '%u:%a' "$file") != 0:600 ]]; then
        printf 'USBGuard policy ownership or mode is invalid: %s\n' "$file" >&2
        exit 1
    fi
done
printf 'Kernel USB default-deny and USBGuard service/policy are verified for this boot.\n'
