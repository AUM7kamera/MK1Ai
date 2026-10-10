from __future__ import annotations

import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from mk1_quarantine import QuarantineError, QuarantineStateStore, STATE_FILE


ROOT = pathlib.Path(__file__).resolve().parents[1]


class QuarantineStateTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.state_directory = pathlib.Path(self.temporary_directory.name) / "state"
        self.state_directory.mkdir(mode=0o700)
        self.state_directory.chmod(0o700)
        self.uid = os.geteuid()
        self.nft_apply = mock.Mock(return_value=True)
        self.nft_remove = mock.Mock(return_value=True)
        self.airgap_disable = mock.Mock(return_value=True)
        self.store = QuarantineStateStore(
            self.state_directory,
            expected_uid=self.uid,
            strict_ancestors=False,
            approver_keys=(
                self.state_directory / "approver-1.pub",
                self.state_directory / "approver-2.pub",
            ),
            nft_apply=self.nft_apply,
            nft_remove=self.nft_remove,
            airgap_disable=self.airgap_disable,
        )

    def read_state(self):
        return json.loads((self.state_directory / STATE_FILE).read_text(encoding="ascii"))

    def test_missing_state_fails_closed_and_survives_new_store_instance(self):
        self.assertTrue(self.store.enforce())
        state = self.read_state()
        self.assertEqual(state["state"], "quarantined")
        state_file = self.state_directory / STATE_FILE
        self.assertEqual(state_file.stat().st_uid, self.uid)
        self.assertEqual(state_file.stat().st_mode & 0o777, 0o600)

        restarted = QuarantineStateStore(
            self.state_directory,
            expected_uid=self.uid,
            strict_ancestors=False,
            nft_apply=self.nft_apply,
            airgap_disable=self.airgap_disable,
        )
        self.assertTrue(restarted.enforce())
        self.assertEqual(self.nft_apply.call_count, 2)
        self.assertEqual(self.airgap_disable.call_count, 2)

    def test_firewall_failure_never_marks_quarantine_complete(self):
        self.nft_apply.return_value = False
        with self.assertRaisesRegex(QuarantineError, "Unable to apply"):
            self.store.enforce()
        self.assertEqual(self.read_state()["state"], "quarantined")

    def test_mark_quarantined_clears_old_release_challenge(self):
        challenge = json.loads(self.store.issue_challenge())
        self.assertEqual(self.read_state()["pending_challenge"], challenge["challenge"])

        self.store.mark_quarantined()

        self.nft_apply.assert_called_with(
            mode="full_isolation",
            management_ips=[],
            management_ports=[],
        )
        self.assertEqual(self.read_state()["state"], "quarantined")
        self.assertIsNone(self.read_state()["pending_challenge"])

    def test_release_requires_pending_challenge_and_two_verified_approvals(self):
        challenge_document = json.loads(self.store.issue_challenge())
        self.assertEqual(self.read_state()["state"], "quarantined")
        self.nft_apply.assert_called_once_with(
            mode="full_isolation",
            management_ips=[],
            management_ports=[],
        )
        signatures = []
        for name in ("sig-1", "sig-2"):
            signature = self.state_directory / name
            signature.write_bytes(b"signature")
            signatures.append(signature)

        with mock.patch.object(self.store, "_verify_approvals") as verify:
            self.assertTrue(self.store.release(
                challenge_document["challenge"],
                signatures[0],
                signatures[1],
            ))
        verify.assert_called_once()
        self.nft_remove.assert_called_once_with()
        self.assertEqual(self.read_state()["state"], "released")
        self.assertIsNone(self.read_state()["pending_challenge"])

        self.nft_apply.reset_mock()
        self.assertTrue(self.store.enforce())
        self.nft_apply.assert_not_called()

    def test_missing_stale_or_invalid_approvals_leave_state_quarantined(self):
        first = json.loads(self.store.issue_challenge())
        second = json.loads(self.store.issue_challenge())
        signature_one = self.state_directory / "one.sig"
        signature_two = self.state_directory / "two.sig"
        signature_one.write_bytes(b"one")
        signature_two.write_bytes(b"two")
        with self.assertRaisesRegex(QuarantineError, "mismatched"):
            self.store.release(first["challenge"], signature_one, signature_two)
        self.assertEqual(self.read_state()["state"], "quarantined")

        with mock.patch.object(
            self.store, "_verify_approvals",
            side_effect=QuarantineError("An operator release signature is invalid"),
        ):
            with self.assertRaisesRegex(QuarantineError, "signature is invalid"):
                self.store.release(second["challenge"], signature_one, signature_two)
        self.assertEqual(self.read_state()["state"], "quarantined")
        self.nft_remove.assert_not_called()

    def test_release_firewall_failure_rolls_state_back_to_quarantine(self):
        challenge = json.loads(self.store.issue_challenge())
        first = self.state_directory / "first.sig"
        second = self.state_directory / "second.sig"
        first.write_bytes(b"one")
        second.write_bytes(b"two")
        self.nft_remove.return_value = False
        with mock.patch.object(self.store, "_verify_approvals"):
            with self.assertRaisesRegex(QuarantineError, "remove nftables"):
                self.store.release(challenge["challenge"], first, second)
        self.assertEqual(self.read_state()["state"], "quarantined")
        self.assertEqual(self.nft_apply.call_count, 2)

    def test_invalid_state_and_symlink_state_are_rejected(self):
        state_file = self.state_directory / STATE_FILE
        state_file.write_text('{"state":"released"}', encoding="ascii")
        state_file.chmod(0o600)
        with self.assertRaisesRegex(QuarantineError, "schema"):
            self.store.enforce()

        state_file.unlink()
        target = self.state_directory / "target"
        target.write_text("{}", encoding="ascii")
        target.chmod(0o600)
        state_file.symlink_to(target)
        with self.assertRaisesRegex(QuarantineError, "ownership or mode"):
            self.store.enforce()

    def test_systemd_network_units_require_quarantine_preflight(self):
        units = (
            "NetworkManager.service.d/10-mk1ai-quarantine.conf",
            "systemd-networkd.service.d/10-mk1ai-quarantine.conf",
            "networking.service.d/10-mk1ai-quarantine.conf",
            "wg-quick@.service.d/10-mk1ai-quarantine.conf",
        )
        for relative_path in units:
            content = (ROOT / "security/systemd" / relative_path).read_text(
                encoding="utf-8",
            )
            with self.subTest(unit=relative_path):
                self.assertIn("Requires=mk1ai-quarantine.service", content)
                self.assertIn("After=mk1ai-quarantine.service", content)


if __name__ == "__main__":
    unittest.main()
