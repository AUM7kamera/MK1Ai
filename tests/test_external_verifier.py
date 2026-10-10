from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mk1_external_verifier import (
    ExternalVerificationError,
    create_measurement_challenge,
    measure_and_sign,
    measure_read_only_tree,
    verify_measurement_report,
)


def _canonical(document: object) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


class ExternalVerifierTest(unittest.TestCase):
    def setUp(self):
        self.builder_key = Ed25519PrivateKey.generate()
        self.verifier_key = Ed25519PrivateKey.generate()
        self.public_files = {
            "bin/sf-core": b"approved-core-image",
            "etc/mk1ai/policy.json": b'{"mode":"strict"}',
        }
        self.manifest = _canonical({
            "version": 1,
            "build_id": "build-2026-10",
            "files": [
                {
                    "path": path,
                    "sha256": hashlib.sha256(contents).hexdigest(),
                }
                for path, contents in sorted(self.public_files.items())
            ],
        })
        self.manifest_signature = self.builder_key.sign(self.manifest)
        self.challenge = create_measurement_challenge("target-a")

    def _write_target(self, root: pathlib.Path) -> None:
        for path, contents in self.public_files.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents)

    def test_fresh_external_measurement_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            self._write_target(root)

            report = measure_and_sign(
                root,
                self.challenge,
                self.manifest,
                self.manifest_signature,
                self.builder_key.public_key(),
                self.verifier_key,
                require_read_only=False,
            )
            measurements = verify_measurement_report(
                report,
                self.challenge,
                self.manifest,
                self.manifest_signature,
                self.builder_key.public_key(),
                self.verifier_key.public_key(),
            )

        self.assertEqual(
            measurements,
            {
                path: hashlib.sha256(contents).hexdigest()
                for path, contents in self.public_files.items()
            },
        )

    def test_wrong_target_bytes_fail_before_a_signed_report_is_created(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            self._write_target(root)
            (root / "bin/sf-core").write_bytes(b"modified-core-image")

            with self.assertRaisesRegex(ExternalVerificationError, "does not match"):
                measure_and_sign(
                    root,
                    self.challenge,
                    self.manifest,
                    self.manifest_signature,
                    self.builder_key.public_key(),
                    self.verifier_key,
                    require_read_only=False,
                )

    def test_replayed_or_wrong_target_challenge_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            self._write_target(root)
            report = measure_and_sign(
                root,
                self.challenge,
                self.manifest,
                self.manifest_signature,
                self.builder_key.public_key(),
                self.verifier_key,
                require_read_only=False,
            )
        fresh_challenge = create_measurement_challenge("target-a")
        wrong_target = create_measurement_challenge("target-b")
        with self.assertRaisesRegex(ExternalVerificationError, "stale or mismatched"):
            verify_measurement_report(
                report,
                fresh_challenge,
                self.manifest,
                self.manifest_signature,
                self.builder_key.public_key(),
                self.verifier_key.public_key(),
            )
        with self.assertRaisesRegex(ExternalVerificationError, "stale or mismatched"):
            verify_measurement_report(
                report,
                wrong_target,
                self.manifest,
                self.manifest_signature,
                self.builder_key.public_key(),
                self.verifier_key.public_key(),
            )

    def test_manifest_signature_and_verifier_signature_are_required(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            self._write_target(root)
            with self.assertRaisesRegex(ExternalVerificationError, "manifest signature"):
                measure_and_sign(
                    root,
                    self.challenge,
                    self.manifest,
                    bytes(64),
                    self.builder_key.public_key(),
                    self.verifier_key,
                    require_read_only=False,
                )
            report = measure_and_sign(
                root,
                self.challenge,
                self.manifest,
                self.manifest_signature,
                self.builder_key.public_key(),
                self.verifier_key,
                require_read_only=False,
            )
        altered_document = json.loads(report)
        signature = base64.b64decode(altered_document["signature"])
        altered_document["signature"] = base64.b64encode(
            bytes((signature[0] ^ 1,)) + signature[1:],
        ).decode("ascii")
        altered = _canonical(altered_document)
        with self.assertRaisesRegex(ExternalVerificationError, "signature is invalid"):
            verify_measurement_report(
                altered,
                self.challenge,
                self.manifest,
                self.manifest_signature,
                self.builder_key.public_key(),
                self.verifier_key.public_key(),
            )

    def test_signed_manifest_rejects_duplicate_paths_and_noncanonical_json(self):
        duplicated = _canonical({
            "version": 1,
            "build_id": "build-2026-10",
            "files": [
                {"path": "a", "sha256": "0" * 64},
                {"path": "a", "sha256": "1" * 64},
            ],
        })
        with self.assertRaisesRegex(ExternalVerificationError, "repeats"):
            measure_and_sign(
                pathlib.Path("."),
                self.challenge,
                duplicated,
                self.builder_key.sign(duplicated),
                self.builder_key.public_key(),
                self.verifier_key,
                require_read_only=False,
            )
        with self.assertRaisesRegex(ExternalVerificationError, "canonical"):
            measure_and_sign(
                pathlib.Path("."),
                self.challenge,
                self.manifest + b"\n",
                self.builder_key.sign(self.manifest + b"\n"),
                self.builder_key.public_key(),
                self.verifier_key,
                require_read_only=False,
            )

    def test_symlink_in_measured_tree_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            (root / "bin").mkdir()
            target = root / "secret"
            target.write_bytes(b"not the expected file")
            (root / "bin/sf-core").symlink_to(target)

            with self.assertRaisesRegex(ExternalVerificationError, "without following links"):
                measure_read_only_tree(
                    root,
                    {
                        "bin/sf-core": hashlib.sha256(
                            self.public_files["bin/sf-core"],
                        ).hexdigest(),
                    },
                    require_read_only=False,
                )

    def test_read_only_mount_is_required_by_default(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            self._write_target(root)
            fake_statvfs = mock.Mock(f_flag=0)

            with mock.patch(
                "mk1_external_verifier.os.statvfs",
                return_value=fake_statvfs,
            ), self.assertRaisesRegex(ExternalVerificationError, "read-only"):
                measure_read_only_tree(
                    root,
                    {
                        path: hashlib.sha256(contents).hexdigest()
                        for path, contents in self.public_files.items()
                    },
                )


if __name__ == "__main__":
    unittest.main()
