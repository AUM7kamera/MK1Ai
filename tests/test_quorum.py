from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from mk1_quorum import (
    QuorumError,
    combine_approval_records,
    create_approval_record,
    load_trusted_quorum_keys,
    verify_approval_bundle,
)


def _public_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _bundle(message: bytes, keys: dict[str, Ed25519PrivateKey]) -> bytes:
    return json.dumps({
        "version": 1,
        "approvals": [
            {
                "signer_id": signer_id,
                "signature": base64.b64encode(key.sign(message)).decode("ascii"),
            }
            for signer_id, key in keys.items()
        ],
    }, separators=(",", ":")).encode("ascii")


def _challenge_document(generation: int, challenge: str) -> bytes:
    message = f"MK1AI-QUARANTINE-RELEASE-v1\n{generation}\n{challenge}\n".encode("ascii")
    return json.dumps({
        "version": 1,
        "generation": generation,
        "challenge": challenge,
        "message_base64": base64.b64encode(message).decode("ascii"),
    }).encode("ascii")


class QuorumTest(unittest.TestCase):
    def setUp(self):
        self.message = b"MK1AI-QUARANTINE-RELEASE-v1\n7\nfresh-challenge\n"
        self.private_keys = {
            f"node-{index}": Ed25519PrivateKey.generate()
            for index in range(1, 4)
        }
        self.trusted_keys = {
            signer_id: key.public_key()
            for signer_id, key in self.private_keys.items()
        }

    def test_two_of_three_distinct_signers_meet_threshold(self):
        bundle = _bundle(
            self.message,
            {"node-1": self.private_keys["node-1"], "node-3": self.private_keys["node-3"]},
        )

        approved = verify_approval_bundle(self.message, bundle, self.trusted_keys)

        self.assertEqual(approved, ("node-1", "node-3"))

    def test_independent_records_combine_and_verify_for_exact_release_challenge(self):
        challenge_document = _challenge_document(7, "a" * 64)
        records = [
            create_approval_record(
                signer_id,
                challenge_document,
                private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
            )
            for signer_id, private_key in (
                ("node-1", self.private_keys["node-1"]),
                ("node-3", self.private_keys["node-3"]),
            )
        ]

        bundle = combine_approval_records(records)
        message = f"MK1AI-QUARANTINE-RELEASE-v1\n7\n{'a' * 64}\n".encode("ascii")

        self.assertEqual(
            verify_approval_bundle(message, bundle, self.trusted_keys),
            ("node-1", "node-3"),
        )

    def test_single_signer_is_rejected(self):
        bundle = _bundle(self.message, {"node-1": self.private_keys["node-1"]})

        with self.assertRaisesRegex(QuorumError, "quorum count"):
            verify_approval_bundle(self.message, bundle, self.trusted_keys)

    def test_wrong_message_or_signature_is_rejected(self):
        bundle = _bundle(self.message, {"node-1": self.private_keys["node-1"],
                                        "node-2": self.private_keys["node-2"]})

        with self.assertRaisesRegex(QuorumError, "invalid"):
            verify_approval_bundle(self.message + b"changed", bundle, self.trusted_keys)

    def test_duplicate_signer_and_unknown_signer_are_rejected(self):
        signature = base64.b64encode(self.private_keys["node-1"].sign(self.message)).decode("ascii")
        duplicate = json.dumps({
            "version": 1,
            "approvals": [
                {"signer_id": "node-1", "signature": signature},
                {"signer_id": "node-1", "signature": signature},
            ],
        }).encode("ascii")
        unknown = json.dumps({
            "version": 1,
            "approvals": [
                {"signer_id": "node-1", "signature": signature},
                {"signer_id": "unknown", "signature": signature},
            ],
        }).encode("ascii")

        with self.assertRaisesRegex(QuorumError, "repeats a signer"):
            verify_approval_bundle(self.message, duplicate, self.trusted_keys)
        with self.assertRaisesRegex(QuorumError, "unknown signer"):
            verify_approval_bundle(self.message, unknown, self.trusted_keys)

    def test_closed_schema_duplicate_json_keys_and_invalid_threshold_are_rejected(self):
        with self.assertRaisesRegex(QuorumError, "closed schema"):
            verify_approval_bundle(
                self.message,
                b'{"version":1,"approvals":[],"extra":true}',
                self.trusted_keys,
            )
        with self.assertRaisesRegex(QuorumError, "duplicate JSON key"):
            verify_approval_bundle(
                self.message,
                b'{"version":1,"version":1,"approvals":[]}',
                self.trusted_keys,
            )
        with self.assertRaisesRegex(QuorumError, "threshold"):
            verify_approval_bundle(
                self.message,
                _bundle(self.message, self.private_keys),
                self.trusted_keys,
                threshold=1,
            )

    def test_trusted_roster_rejects_duplicate_public_keys(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = pathlib.Path(temporary_directory)
            key_path_one = directory / "one.pub"
            key_path_two = directory / "two.pub"
            encoded = _public_pem(self.private_keys["node-1"])
            key_path_one.write_bytes(encoded)
            key_path_two.write_bytes(encoded)
            key_path_one.chmod(0o600)
            key_path_two.chmod(0o600)

            with self.assertRaisesRegex(QuorumError, "must be distinct"):
                load_trusted_quorum_keys(
                    {"node-1": key_path_one, "node-2": key_path_two},
                    expected_uid=os.geteuid(),
                    strict_ancestors=False,
                )

    def test_bundle_verifier_rejects_duplicate_public_key_aliases(self):
        duplicate_roster = {
            "node-1": self.private_keys["node-1"].public_key(),
            "node-alias": self.private_keys["node-1"].public_key(),
        }
        bundle = _bundle(
            self.message,
            {
                "node-1": self.private_keys["node-1"],
                "node-alias": self.private_keys["node-1"],
            },
        )

        with self.assertRaisesRegex(QuorumError, "public keys must be distinct"):
            verify_approval_bundle(self.message, bundle, duplicate_roster)

    def test_trusted_roster_requires_ed25519_key_files(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = pathlib.Path(temporary_directory)
            paths = {}
            for index, key in enumerate(self.private_keys.values(), start=1):
                path = directory / f"node-{index}.pub"
                path.write_bytes(_public_pem(key))
                path.chmod(0o600)
                paths[f"node-{index}"] = path

            loaded = load_trusted_quorum_keys(
                paths,
                expected_uid=os.geteuid(),
                strict_ancestors=False,
            )

            self.assertEqual(set(loaded), set(paths))
            self.assertTrue(all(isinstance(key, Ed25519PublicKey) for key in loaded.values()))

    def test_signer_refuses_modified_or_inconsistent_challenge_document(self):
        private_key = self.private_keys["node-1"].private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        invalid_challenge = _challenge_document(7, "a" * 64).replace(
            b'"generation": 7',
            b'"generation": 8',
        )

        with self.assertRaisesRegex(QuorumError, "does not match its fields"):
            create_approval_record("node-1", invalid_challenge, private_key)

    def test_signer_cli_and_combiner_cli_create_verifiable_bundle(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = pathlib.Path(temporary_directory)
            challenge_path = directory / "challenge.json"
            challenge_path.write_bytes(_challenge_document(9, "b" * 64))
            record_paths = []
            for signer_id in ("node-1", "node-2"):
                private_path = directory / f"{signer_id}.private.pem"
                private_path.write_bytes(self.private_keys[signer_id].private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ))
                private_path.chmod(0o600)
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(pathlib.Path(__file__).resolve().parents[1] / "mk1_quorum_cli.py"),
                        "approve",
                        "--signer-id",
                        signer_id,
                        "--release-challenge",
                        str(challenge_path),
                        "--private-key",
                        str(private_path),
                    ],
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr.decode())
                record_path = directory / f"{signer_id}.approval.json"
                record_path.write_bytes(completed.stdout)
                record_paths.append(record_path)

            combined = subprocess.run(
                [
                    sys.executable,
                    str(pathlib.Path(__file__).resolve().parents[1] / "mk1_quorum_cli.py"),
                    "combine",
                    "--record",
                    str(record_paths[0]),
                    "--record",
                    str(record_paths[1]),
                ],
                check=False,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(combined.returncode, 0, combined.stderr.decode())
            message = f"MK1AI-QUARANTINE-RELEASE-v1\n9\n{'b' * 64}\n".encode("ascii")

            self.assertEqual(
                verify_approval_bundle(message, combined.stdout, self.trusted_keys),
                ("node-1", "node-2"),
            )


if __name__ == "__main__":
    unittest.main()
