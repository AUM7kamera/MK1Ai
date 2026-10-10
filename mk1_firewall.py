"""Transactional nftables policy construction for MK1Ai quarantine."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import shutil
import stat
import subprocess


def is_valid_ip_address(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def validate_nft_policy(
    mode: object,
    management_ips: object,
    management_ports: object,
) -> tuple[str, list[str], list[int]]:
    if mode not in ("full_isolation", "management_safe_harbor"):
        raise ValueError("Unknown containment mode")
    if not isinstance(management_ips, (list, tuple)) or not isinstance(
        management_ports, (list, tuple),
    ):
        raise ValueError("Management addresses and ports must be lists")
    if len(management_ips) > 64 or len(management_ports) > 64:
        raise ValueError("Safe-harbor route exceeds its address/port limit")
    if any(not is_valid_ip_address(value) for value in management_ips):
        raise ValueError("Safe-harbor addresses must be valid IPv4 or IPv6 literals")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in management_ports):
        raise ValueError("Safe-harbor ports must be integers between 1 and 65535")
    if len(management_ips) * len(management_ports) > 256:
        raise ValueError("Safe-harbor route exceeds its rule limit")
    if mode == "full_isolation" and (management_ips or management_ports):
        raise ValueError("Full-isolation policy cannot include management exceptions")
    return (
        mode,
        [str(ipaddress.ip_address(value)) for value in management_ips],
        list(management_ports),
    )


def apply_nft_policy(
    *,
    mode: str = "full_isolation",
    management_ips: list[str] | tuple[str, ...] = (),
    management_ports: list[int] | tuple[int, ...] = (),
    nft_binary: str | None = None,
) -> bool:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return False
    script = render_nft_transaction(
        mode=mode,
        management_ips=management_ips,
        management_ports=management_ports,
    )
    try:
        path = _trusted_nft_binary(nft_binary)
    except OSError:
        return False
    if path is None:
        return False
    try:
        result = subprocess.run(
            [path, "-f", "-"],
            input=script,
            text=True,
            check=False,
            capture_output=True,
            timeout=10,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/"},
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _trusted_nft_binary(binary: str | None) -> str | None:
    if binary is None:
        binary = shutil.which("nft", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if binary is None:
        return None
    path = str(Path(binary).resolve(strict=True))
    executable = os.stat(path)
    if (
        not stat.S_ISREG(executable.st_mode)
        or executable.st_uid != 0
        or executable.st_mode & 0o022
    ):
        raise OSError("nft must be a root-owned, non-writable system executable")
    for parent in Path(path).parents:
        parent_stat = parent.stat()
        if parent_stat.st_uid != 0 or parent_stat.st_mode & 0o022:
            raise OSError("nft is located in an untrusted directory")
    return path


def render_nft_transaction(
    *,
    mode: str = "full_isolation",
    management_ips: list[str] | tuple[str, ...] = (),
    management_ports: list[int] | tuple[int, ...] = (),
) -> str:
    """Build one nft batch that atomically replaces only the MK1Ai table."""
    mode, addresses, ports = validate_nft_policy(
        mode, management_ips, management_ports,
    )
    lines = [
        "destroy table inet mk1ai_quarantine",
        "add table inet mk1ai_quarantine",
        (
            "add chain inet mk1ai_quarantine input "
            "{ type filter hook input priority -10; policy drop; }"
        ),
        (
            "add chain inet mk1ai_quarantine output "
            "{ type filter hook output priority -10; policy drop; }"
        ),
        (
            "add chain inet mk1ai_quarantine forward "
            "{ type filter hook forward priority -10; policy drop; }"
        ),
    ]
    if mode == "management_safe_harbor":
        for address in addresses:
            family = "ip" if ipaddress.ip_address(address).version == 4 else "ip6"
            for port in ports:
                lines.extend((
                    (
                        "add rule inet mk1ai_quarantine input "
                        f"{family} saddr {address} tcp dport {port} accept"
                    ),
                    (
                        "add rule inet mk1ai_quarantine input "
                        f"{family} saddr {address} tcp sport {port} "
                        "ct state established,related accept"
                    ),
                    (
                        "add rule inet mk1ai_quarantine output "
                        f"{family} daddr {address} tcp dport {port} accept"
                    ),
                    (
                        "add rule inet mk1ai_quarantine output "
                        f"{family} daddr {address} tcp sport {port} "
                        "ct state established,related accept"
                    ),
                ))
    return "\n".join(lines) + "\n"
