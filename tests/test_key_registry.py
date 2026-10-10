import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mk1_key_registry import (
    KeyRegistryError,
    derive_device_purpose_key,
    verify_revocation_manifest,
)


class KeyRegistryTest(unittest.TestCase):
    def setUp(self):
        self.authority = Ed25519PrivateKey.generate()
        self.public_key = self.authority.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw,
        )

    def test_keys_are_separated_by_device_purpose_and_generation(self):
        root = bytearray(b"r" * 32)
        device_one = "01" * 32
        device_two = "02" * 32
        encryption_key = derive_device_purpose_key(
            root,
            device_id=device_one,
            purpose="application-encryption",
            generation=7,
        )
        signing_key = derive_device_purpose_key(
            root,
            device_id=device_one,
            purpose="application-signing",
            generation=7,
        )
        other_device_key = derive_device_purpose_key(
            root,
            device_id=device_two,
            purpose="application-encryption",
            generation=7,
        )
        rotated_key = derive_device_purpose_key(
            root,
            device_id=device_one,
            purpose="application-encryption",
            generation=8,
        )
        self.addCleanup(encryption_key.__setitem__, slice(None), bytes(32))
        self.addCleanup(signing_key.__setitem__, slice(None), bytes(32))
        self.addCleanup(other_device_key.__setitem__, slice(None), bytes(32))
        self.addCleanup(rotated_key.__setitem__, slice(None), bytes(32))

        self.assertEqual(len({bytes(encryption_key), bytes(signing_key),
                              bytes(other_device_key), bytes(rotated_key)}), 4)

    def test_signed_revocation_manifest_and_device_lookup(self):
        revoked_id = "ab" * 32
        payload = json.dumps(
            {
                "version": 1,
                "generation": 4,
                "revoked_device_ids": [revoked_id],
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        manifest = verify_revocation_manifest(
            payload,
            self.authority.sign(payload),
            self.public_key,
            minimum_generation=3,
        )

        self.assertTrue(manifest.is_revoked(revoked_id))
        self.assertFalse(manifest.is_revoked("cd" * 32))

    def test_bad_signature_rollback_unknown_keys_and_duplicates_fail_closed(self):
        base = {"version": 1, "generation": 5, "revoked_device_ids": []}
        payload = json.dumps(base, separators=(",", ":"), sort_keys=True).encode("ascii")
        with self.assertRaisesRegex(KeyRegistryError, "signature"):
            verify_revocation_manifest(
                payload,
                bytes(64),
                self.public_key,
                minimum_generation=0,
            )
        with self.assertRaisesRegex(KeyRegistryError, "rollback"):
            verify_revocation_manifest(
                json.dumps(
                    {**base, "generation": 1},
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii"),
                self.authority.sign(json.dumps(
                    {**base, "generation": 1},
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")),
                self.public_key,
                minimum_generation=2,
            )

        duplicate_payload = (
            b'{"version":1,"generation":1,"generation":2,"revoked_device_ids":[]}'
        )
        with self.assertRaisesRegex(KeyRegistryError, "Duplicate"):
            verify_revocation_manifest(
                duplicate_payload,
                self.authority.sign(duplicate_payload),
                self.public_key,
                minimum_generation=0,
            )

    def test_unknown_purpose_and_malformed_device_id_are_rejected(self):
        with self.assertRaisesRegex(KeyRegistryError, "Unknown key purpose"):
            derive_device_purpose_key(
                bytearray(b"r" * 32),
                device_id="01" * 32,
                purpose="generic",
                generation=1,
            )
        with self.assertRaisesRegex(KeyRegistryError, "Device ID"):
            derive_device_purpose_key(
                bytearray(b"r" * 32),
                device_id="short",
                purpose="application-encryption",
                generation=1,
            )


if __name__ == "__main__":
    unittest.main()
