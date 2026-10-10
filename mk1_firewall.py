"""Transactional nftables policy construction for MK1Ai quarantine."""

from __future__ import annotations

import ipaddress
 codespace-probable-dollop-pj64p66j94jv29wg6
import os
from pathlib import Path

import logging
import os
from pathlib import Path
import re
 main
import shutil
import stat
import subprocess


 codespace-probable-dollop-pj64p66j94jv29wg6

MIN_NFT_VERSION = (0, 9, 0)
NFT_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/"}
_NFT_VERSION_RE = re.compile(r"nftables v(\d+)\.(\d+)\.(\d+)")
_log = logging.getLogger(__name__)
last_nft_failure: str | None = None


def render_nft_removal() -> str:
    """Batch that removes only the MK1Ai quarantine table (no ``destroy``)."""
    return (
        "add table inet mk1ai_quarantine\n"
        "delete table inet mk1ai_quarantine\n"
    )


def _fail(reason: str) -> bool:
    global last_nft_failure
    last_nft_failure = reason
    _log.error("[NFT] %s", reason)
    return False


def check_nft_support(path: str) -> str | None:
    """Return None if nft is usable, else a human-readable reason (fail-closed)."""
    try:
        version = subprocess.run(
            [path, "--version"], text=True, check=False, capture_output=True,
            timeout=10, env=NFT_ENV,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"nft のバージョンを取得できません: {exc}"
    match = _NFT_VERSION_RE.search(version.stdout or "")
    if version.returncode != 0 or match is None:
        return "nft のバージョンを判定できません"
    found = tuple(int(part) for part in match.groups())
    if found < MIN_NFT_VERSION:
        return (
            "nft %s は非対応です (必要: %s 以上)"
            % (".".join(map(str, found)), ".".join(map(str, MIN_NFT_VERSION)))
        )
    return None


 main
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
 codespace-probable-dollop-pj64p66j94jv29wg6
    except OSError:
        return False
    if path is None:
        return False

    except OSError as exc:
        return _fail(f"nft バイナリを信頼できません: {exc}")
    if path is None:
        return _fail("nft が見つかりません")
    unsupported = check_nft_support(path)
    if unsupported is not None:
        return _fail(unsupported)
 main
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
 codespace-probable-dollop-pj64p66j94jv29wg6
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0

    except (OSError, subprocess.SubprocessError) as exc:
        return _fail(f"nft の実行に失敗しました: {exc}")
    if result.returncode != 0:
        return _fail("nft バッチが拒否されました (旧ルールは保持): " + (result.stderr or "").strip()[:200])
    return True


def remove_nft_policy(nft_binary: str | None = None) -> bool:
    """Remove only the quarantine table in one batch; mk1ai_egress is untouched."""
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return False
    try:
        path = _trusted_nft_binary(nft_binary)
    except OSError as exc:
        return _fail(f"nft バイナリを信頼できません: {exc}")
    if path is None:
        return _fail("nft が見つかりません")
    unsupported = check_nft_support(path)
    if unsupported is not None:
        return _fail(unsupported)
    try:
        result = subprocess.run(
            [path, "-f", "-"], input=render_nft_removal(), text=True,
            check=False, capture_output=True, timeout=10, env=NFT_ENV,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return _fail(f"nft の実行に失敗しました: {exc}")
    return result.returncode == 0 or _fail("nft 解除バッチが失敗しました")
 main


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
 codespace-probable-dollop-pj64p66j94jv29wg6
        "destroy table inet mk1ai_quarantine",

        # "add" first makes "delete" succeed on tables that do not exist yet;
        # "destroy" is avoided because older nft releases reject it.
        "add table inet mk1ai_quarantine",
        "delete table inet mk1ai_quarantine",
 main
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
