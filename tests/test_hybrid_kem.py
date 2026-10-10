import hashlib
import unittest

from pqcrypto.kem.ml_kem_1024 import keygen

from mk1_hybrid_kem import (
    HybridKEMError,
    SUITE_ID,
    decapsulate,
    encapsulate,
    generate_x25519_keypair,
    verify_hybrid_key_fingerprint,
)


class HybridKEMTest(unittest.TestCase):
    def setUp(self):
        self.kem_public_key, self.kem_secret_key = keygen()
        self.x25519_private_key, self.x25519_public_key = generate_x25519_keypair()
        self.psk = b"w" * 32
        self.transcript = b"POST /rsi"

    def test_hybrid_agreement_combines_both_kem_components_and_psk(self):
        exchange = encapsulate(
            self.kem_public_key,
            self.x25519_public_key,
            self.psk,
            self.transcript,
        )
        self.addCleanup(exchange.destroy)
        server_secret = decapsulate(
            self.kem_secret_key,
            self.x25519_private_key,
            exchange.kem_ciphertext,
            exchange.client_x25519_public_key,
            self.psk,
            self.transcript,
        )
        self.addCleanup(lambda: server_secret.__setitem__(slice(None), bytes(len(server_secret))))

        self.assertEqual(exchange.shared_secret, server_secret)
        self.assertEqual(len(exchange.shared_secret), 32)

    def test_changed_psk_or_transcript_changes_the_combined_secret(self):
        exchange = encapsulate(
            self.kem_public_key,
            self.x25519_public_key,
            self.psk,
            self.transcript,
        )
        self.addCleanup(exchange.destroy)
        wrong_psk = decapsulate(
            self.kem_secret_key,
            self.x25519_private_key,
            exchange.kem_ciphertext,
            exchange.client_x25519_public_key,
            b"x" * 32,
            self.transcript,
        )
        wrong_transcript = decapsulate(
            self.kem_secret_key,
            self.x25519_private_key,
            exchange.kem_ciphertext,
            exchange.client_x25519_public_key,
            self.psk,
            b"POST /other",
        )
        self.addCleanup(lambda: wrong_psk.__setitem__(slice(None), bytes(len(wrong_psk))))
        self.addCleanup(lambda: wrong_transcript.__setitem__(
            slice(None), bytes(len(wrong_transcript)),
        ))

        self.assertNotEqual(exchange.shared_secret, wrong_psk)
        self.assertNotEqual(exchange.shared_secret, wrong_transcript)

    def test_wireguard_psk_is_mandatory(self):
        with self.assertRaisesRegex(HybridKEMError, "WireGuard preshared key"):
            encapsulate(
                self.kem_public_key,
                self.x25519_public_key,
                b"",
                self.transcript,
            )

    def test_hybrid_public_key_fingerprint_covers_both_public_keys(self):
        expected = hashlib.sha384(
            SUITE_ID + self.kem_public_key + self.x25519_public_key,
        ).hexdigest()
        self.assertEqual(
            verify_hybrid_key_fingerprint(
                self.kem_public_key,
                self.x25519_public_key,
                expected,
            ),
            expected,
        )
        with self.assertRaisesRegex(HybridKEMError, "fingerprint"):
            verify_hybrid_key_fingerprint(
                self.kem_public_key,
                self.x25519_public_key,
                "0" * 96,
            )

    def test_invalid_kem_public_key_is_rejected(self):
        with self.assertRaisesRegex(HybridKEMError, "exactly"):
            encapsulate(b"short", self.x25519_public_key, self.psk, self.transcript)

    def test_x25519_all_zero_public_key_fails_closed(self):
        with self.assertRaises(HybridKEMError):
            decapsulate(
                self.kem_secret_key,
                self.x25519_private_key,
                b"c" * 1568,
                bytes(32),
                self.psk,
                self.transcript,
            )


if __name__ == "__main__":
    unittest.main()
