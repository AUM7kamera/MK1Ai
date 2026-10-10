import pathlib
import unittest

from mk1_render_nft import render_nft_template


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ConfigTemplateTest(unittest.TestCase):
    def setUp(self):
        self.template = (ROOT / "mk1-wireguard-egress.nft.template").read_text(
            encoding="utf-8",
        )

    def test_nft_renderer_handles_ipv4_and_ipv6_only_endpoints(self):
        ipv4 = render_nft_template(
            self.template,
            interface="wg0",
            endpoint="192.0.2.1",
            port=51820,
            allow_dhcp=False,
        )
        ipv6 = render_nft_template(
            self.template,
            interface="wg0",
            endpoint="2001:db8::1",
            port=51820,
            allow_dhcp=False,
        )

        self.assertIn("ip daddr 192.0.2.1 udp dport 51820 accept", ipv4)
        self.assertNotIn("ip6 daddr", ipv4)
        self.assertIn("ip6 daddr 2001:db8::1 udp dport 51820 accept", ipv6)
        self.assertNotIn("ip daddr 192.0.2.1", ipv6)
        self.assertNotIn("WG_", ipv4 + ipv6)

    def test_nft_renderer_gates_dhcp_and_ndp_rules(self):
        rendered = render_nft_template(
            self.template,
            interface="wg0",
            endpoint="192.0.2.1",
            port=51820,
            allow_dhcp=True,
        )

        self.assertIn("udp sport 68 udp dport 67 accept", rendered)
        self.assertIn("udp sport 546 udp dport 547 accept", rendered)
        self.assertIn("nd-neighbor-solicit", rendered)
        self.assertIn("table arp mk1_egress_arp", rendered)

    def test_dashboard_service_has_requested_sandboxing(self):
        service = (ROOT / "mk1-remote-dashboard.service").read_text(encoding="utf-8")

        for directive in (
            "Requires=wg-quick@wg0.service",
            "After=wg-quick@wg0.service",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "LockPersonality=yes",
            "RestrictNamespaces=yes",
            "ProtectKernelLogs=true",
            "PrivateDevices=true",
            "SystemCallFilter=@system-service",
            "LimitMEMLOCK=",
            "Environment=MK1_DATA_DIR=/var/lib/mk1ai/dashboard",
        ):
            with self.subTest(directive=directive):
                self.assertIn(directive, service)


if __name__ == "__main__":
    unittest.main()
