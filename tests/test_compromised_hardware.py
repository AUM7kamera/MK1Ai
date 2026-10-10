import unittest

from mk1_key_derivation import derive_user_root_key


class CompromisedHardwareBackend:
    """Test PAL that exposes every optional factor to the simulated attacker."""

    def __init__(self):
        self.hardware_factor = b"h" * 32
        self.fido2_factor = b"f" * 32

    def disclose_all_factors(self) -> tuple[bytes, bytes]:
        return self.hardware_factor, self.fido2_factor

    def derive_endpoint_key(self, passphrase: str, salt: bytes):
        return derive_user_root_key(
            passphrase,
            hardware_factor=self.hardware_factor,
            fido2_factor=self.fido2_factor,
            salt=salt,
        )


class CompromisedHardwareTest(unittest.TestCase):
    def test_extracted_hardware_and_authenticator_factors_do_not_replace_user_factor(self):
        backend = CompromisedHardwareBackend()
        hardware_factor, fido2_factor = backend.disclose_all_factors()

        # Even direct use of the derivation API requires the user factor.
        with self.assertRaises(TypeError):
            derive_user_root_key(
                hardware_factor=hardware_factor,
                fido2_factor=fido2_factor,
            )

        protected = backend.derive_endpoint_key(
            "correct horse battery staple",
            salt=b"s" * 16,
        )
        # The attacker knows all optional factors but not the user factor.
        attacker_candidate = derive_user_root_key(
            "attacker-known but incorrect passphrase",
            hardware_factor=hardware_factor,
            fido2_factor=fido2_factor,
            salt=b"s" * 16,
        )
        user_only = derive_user_root_key(
            "correct horse battery staple",
            salt=b"s" * 16,
        )
        self.addCleanup(protected.destroy)
        self.addCleanup(attacker_candidate.destroy)
        self.addCleanup(user_only.destroy)

        self.assertNotEqual(protected.key, attacker_candidate.key)
        self.assertNotEqual(protected.key, user_only.key)
        self.assertEqual(backend.disclose_all_factors(), (hardware_factor, fido2_factor))


if __name__ == "__main__":
    unittest.main()
