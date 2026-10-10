import unittest
import warnings
from unittest import mock

from mk1_key_derivation import (
    KEY_BYTES,
    MIN_MEMORY_KIB,
    MIN_SAFE_AVAILABLE_BYTES,
    MIN_TIME_COST,
    DerivedKey,
    KeyDerivationError,
    _parameters_for_memory,
    derive_user_root_key,
)


class KeyDerivationTest(unittest.TestCase):
    def setUp(self):
        self.memory = mock.patch(
            "mk1_key_derivation._available_memory_bytes",
            return_value=2 * 1024 * 1024 * 1024,
        )
        self.memory.start()
        self.addCleanup(self.memory.stop)

    def test_user_only_mode_derives_a_key_without_optional_factors(self):
        key = derive_user_root_key(
            "correct horse battery staple",
            salt=b"s" * 16,
        )
        self.addCleanup(key.destroy)

        self.assertIsInstance(key, DerivedKey)
        self.assertEqual(len(key.key), KEY_BYTES)
        self.assertGreaterEqual(key.memory_kib, MIN_MEMORY_KIB)
        self.assertFalse(key.low_memory)

    def test_optional_factors_are_bound_without_replacing_user_factor(self):
        base = derive_user_root_key(
            "correct horse battery staple",
            salt=b"s" * 16,
        )
        with_hardware = derive_user_root_key(
            "correct horse battery staple",
            hardware_factor=b"h" * 32,
            salt=b"s" * 16,
        )
        with_fido = derive_user_root_key(
            "correct horse battery staple",
            fido2_factor=b"f" * 32,
            salt=b"s" * 16,
        )
        self.addCleanup(base.destroy)
        self.addCleanup(with_hardware.destroy)
        self.addCleanup(with_fido.destroy)

        self.assertNotEqual(base.key, with_hardware.key)
        self.assertNotEqual(base.key, with_fido.key)
        self.assertNotEqual(with_hardware.key, with_fido.key)

    def test_hardware_factor_alone_cannot_derive_a_root_key(self):
        with self.assertRaises(TypeError):
            derive_user_root_key(hardware_factor=b"h" * 32)

    def test_destroy_zeros_the_derived_key(self):
        key = derive_user_root_key(
            "correct horse battery staple",
            salt=b"s" * 16,
        )
        key.destroy()

        self.assertEqual(key.key, bytearray(KEY_BYTES))

    def test_short_passphrase_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least"):
            derive_user_root_key("too short", salt=b"s" * 16)

    def test_invalid_optional_factor_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "16 to"):
            derive_user_root_key(
                "correct horse battery staple",
                hardware_factor=b"x",
                salt=b"s" * 16,
            )

    def test_low_memory_warns_and_keeps_argon2id_floor(self):
        with mock.patch(
            "mk1_key_derivation._available_memory_bytes",
            return_value=512 * 1024 * 1024,
        ), warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            key = derive_user_root_key(
                "correct horse battery staple",
                salt=b"s" * 16,
            )
        self.addCleanup(key.destroy)

        self.assertTrue(key.low_memory)
        self.assertGreaterEqual(key.memory_kib, MIN_MEMORY_KIB)
        self.assertTrue(any("Low available memory" in str(item.message) for item in caught))

    def test_insufficient_memory_fails_closed(self):
        with mock.patch(
            "mk1_key_derivation._available_memory_bytes",
            return_value=MIN_SAFE_AVAILABLE_BYTES - 1,
        ):
            with self.assertRaises(KeyDerivationError):
                derive_user_root_key(
                    "correct horse battery staple",
                    salt=b"s" * 16,
                )

    def test_memory_parameters_have_floors_and_caps(self):
        small = _parameters_for_memory(512 * 1024 * 1024)
        large = _parameters_for_memory(64 * 1024 * 1024 * 1024)

        self.assertEqual(small[0], MIN_MEMORY_KIB)
        self.assertEqual(small[1], MIN_TIME_COST)
        self.assertLessEqual(large[0], 256 * 1024)
        self.assertLessEqual(large[1], 6)


if __name__ == "__main__":
    unittest.main()
