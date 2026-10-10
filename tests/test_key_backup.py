import unittest

from mk1_key_backup import SecretBackupError, recover_secret, split_secret


class KeyBackupTest(unittest.TestCase):
    def test_threshold_shares_recover_secret_without_all_shares(self):
        secret = bytearray(b"k" * 32)
        expected = bytes(secret)
        shares = split_secret(secret, threshold=2, share_count=3)

        self.assertEqual(secret, bytearray(32))
        for selected in (shares[:2], shares[1:]):
            recovered = recover_secret(selected)
            try:
                self.assertEqual(recovered, expected)
            finally:
                recovered[:] = bytes(len(recovered))

    def test_fewer_than_threshold_shares_are_rejected_without_phrase_leak(self):
        shares = split_secret(bytearray(b"k" * 16), threshold=3, share_count=3)
        with self.assertRaisesRegex(
            SecretBackupError,
            "insufficient, inconsistent, or failed integrity checks",
        ) as raised:
            recover_secret(shares[:2])

        self.assertNotIn(shares[0], str(raised.exception))

    def test_shares_from_different_backups_are_rejected(self):
        first = split_secret(bytearray(b"a" * 16), threshold=2, share_count=3)
        second = split_secret(bytearray(b"b" * 16), threshold=2, share_count=3)

        with self.assertRaises(SecretBackupError):
            recover_secret((first[0], second[0]))

    def test_invalid_threshold_and_duplicate_shares_are_rejected(self):
        with self.assertRaises(SecretBackupError):
            split_secret(bytearray(b"k" * 16), threshold=1, share_count=3)

        shares = split_secret(bytearray(b"k" * 16), threshold=2, share_count=3)
        with self.assertRaisesRegex(SecretBackupError, "Duplicate"):
            recover_secret((shares[0], shares[0]))

    def test_invalid_secret_size_is_rejected(self):
        secret = bytearray(b"short")
        with self.assertRaisesRegex(SecretBackupError, "16 or 32 bytes"):
            split_secret(secret, threshold=2, share_count=3)
        self.assertEqual(secret, bytearray(len(secret)))


if __name__ == "__main__":
    unittest.main()
