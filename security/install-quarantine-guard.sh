#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    printf 'Run this installer as root.\n' >&2
    exit 77
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_dir/.." && pwd)
install -d -o root -g root -m 0755 /opt/mk1ai
install -o root -g root -m 0755 "$repository_root/mk1_firewall.py" /opt/mk1ai/mk1_firewall.py
install -o root -g root -m 0755 "$repository_root/mk1_airgap.py" /opt/mk1ai/mk1_airgap.py
install -o root -g root -m 0755 "$repository_root/mk1_quarantine.py" /opt/mk1ai/mk1_quarantine.py

install -o root -g root -m 0644 \
    "$script_dir/systemd/mk1ai-quarantine.service" \
    /etc/systemd/system/mk1ai-quarantine.service

for unit in NetworkManager.service systemd-networkd.service networking.service 'wg-quick@.service'; do
    install -d -o root -g root -m 0755 "/etc/systemd/system/${unit}.d"
    install -o root -g root -m 0644 \
        "$script_dir/systemd/${unit}.d/10-mk1ai-quarantine.conf" \
        "/etc/systemd/system/${unit}.d/10-mk1ai-quarantine.conf"
done

install -d -o root -g root -m 0700 /var/lib/mk1ai-security
systemctl daemon-reload
systemctl start mk1ai-quarantine.service
systemctl enable mk1ai-quarantine.service
printf 'Quarantine guard installed. Initial state is quarantined; provision two distinct approver public keys out of band.\n'
