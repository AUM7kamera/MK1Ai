"""Render the WireGuard egress nftables template for a concrete peer endpoint."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
from pathlib import Path


INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")


def render_nft_template(
    template: str,
    *,
    interface: str,
    endpoint: str,
    port: int,
    allow_dhcp: bool,
) -> str:
    if not INTERFACE_PATTERN.fullmatch(interface):
        raise ValueError("WireGuard interface name is invalid")
    if not 1 <= port <= 65535:
        raise ValueError("WireGuard endpoint port must be between 1 and 65535")
    address = ipaddress.ip_address(endpoint)

    if address.version == 4:
        endpoint_rules = f"ip daddr {address} udp dport {port} accept"
    else:
        endpoint_rules = f"ip6 daddr {address} udp dport {port} accept"

    dhcp_rules = ""
    if allow_dhcp:
        dhcp_rules = "\n".join((
            "        udp sport 68 udp dport 67 accept",
            "        udp sport 546 udp dport 547 accept",
            "        ip6 nexthdr icmpv6 icmpv6 type { nd-router-solicit, "
            "nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept",
        ))

    rendered = (
        template.replace("WG_INTERFACE", interface)
        .replace("WG_ENDPOINT_RULES", endpoint_rules)
        .replace("MK1_DHCP_RULES", dhcp_rules)
    )
    if re.search(r"\b(?:WG_[A-Z0-9_]+|MK1_[A-Z0-9_]+)\b", rendered):
        raise ValueError("nftables template contains an unresolved placeholder")
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, default=Path(__file__).with_name(
        "mk1-wireguard-egress.nft.template",
    ))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--interface", default="wg0")
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()
    try:
        rendered = render_nft_template(
            args.template.read_text(encoding="utf-8"),
            interface=args.interface,
            endpoint=args.endpoint,
            port=args.port,
            allow_dhcp=os.environ.get("MK1_ALLOW_DHCP") == "1",
        )
        args.output.write_text(rendered, encoding="utf-8")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
