from __future__ import annotations

import unittest
from unittest import mock

import mk1_firewall


class NftRenderTest(unittest.TestCase):
    def test_no_destroy_and_replace_sequence(self):
        for mode, ips, ports in (
            ("full_isolation", (), ()),
            ("management_safe_harbor", ("198.18.0.2",), (18080,)),
        ):
            text = mk1_firewall.render_nft_transaction(
                mode=mode, management_ips=ips, management_ports=ports,
            )
            self.assertNotIn("destroy", text)
            self.assertEqual(text.splitlines()[:3], [
                "add table inet mk1ai_quarantine",
                "delete table inet mk1ai_quarantine",
                "add table inet mk1ai_quarantine",
            ])
            self.assertNotIn("mk1ai_egress", text)

    def test_removal_batch(self):
        text = mk1_firewall.render_nft_removal()
        self.assertNotIn("destroy", text)
        self.assertEqual(text.splitlines(), [
            "add table inet mk1ai_quarantine",
            "delete table inet mk1ai_quarantine",
        ])


class NftSupportTest(unittest.TestCase):
    def _run(self, stdout, code=0):
        return mock.Mock(stdout=stdout, returncode=code)

    def test_supported_version(self):
        with mock.patch("subprocess.run", return_value=self._run("nftables v1.0.9 (x)")):
            self.assertIsNone(mk1_firewall.check_nft_support("/usr/sbin/nft"))

    def test_old_or_unparsable_version_fails_closed(self):
        for out in ("nftables v0.8.3 (x)", "garbage", ""):
            with mock.patch("subprocess.run", return_value=self._run(out)):
                self.assertIsNotNone(mk1_firewall.check_nft_support("/x"))

    def test_apply_refuses_and_records_reason_on_unsupported(self):
        with mock.patch("os.geteuid", return_value=0), \
             mock.patch.object(mk1_firewall, "_trusted_nft_binary", return_value="/x"), \
             mock.patch.object(mk1_firewall, "check_nft_support", return_value="old"), \
             mock.patch("subprocess.run") as run:
            self.assertFalse(mk1_firewall.apply_nft_policy())
            self.assertFalse(mk1_firewall.remove_nft_policy())
            run.assert_not_called()
        self.assertEqual(mk1_firewall.last_nft_failure, "old")


if __name__ == "__main__":
    unittest.main()
