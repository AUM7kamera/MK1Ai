import unittest

from cryptography.exceptions import InvalidTag

from mk1_session_ratchet import (
    MAX_SESSION_LIFETIME_SECONDS,
    SessionRatchet,
    SessionRatchetError,
)


class SessionRatchetTest(unittest.TestCase):
    def make_pair(self, *, clock=lambda: 100.0):
        client = SessionRatchet(
            bytearray(b"s" * 32),
            context=b"session-1",
            role="client",
            clock=clock,
        )
        server = SessionRatchet(
            bytearray(b"s" * 32),
            context=b"session-1",
            role="server",
            clock=clock,
        )
        return client, server

    def test_ratchet_round_trip_and_sequence_progression(self):
        client, server = self.make_pair()
        self.addCleanup(client.destroy)
        self.addCleanup(server.destroy)

        first = client.encrypt(b"message one", aad=b"POST /")
        second = client.encrypt(b"message two", aad=b"POST /")
        self.assertEqual(server.decrypt(first, aad=b"POST /"), b"message one")
        self.assertEqual(server.decrypt(second, aad=b"POST /"), b"message two")
        self.assertEqual(client.sequence_numbers, (2, 0))
        self.assertEqual(server.sequence_numbers, (0, 2))

    def test_replay_and_out_of_order_packets_are_rejected(self):
        client, server = self.make_pair()
        self.addCleanup(client.destroy)
        self.addCleanup(server.destroy)

        first = client.encrypt(b"first")
        second = client.encrypt(b"second")
        with self.assertRaisesRegex(SessionRatchetError, "out-of-order"):
            server.decrypt(second)
        self.assertEqual(server.decrypt(first), b"first")
        with self.assertRaisesRegex(SessionRatchetError, "out-of-order"):
            server.decrypt(first)

    def test_failed_authentication_does_not_advance_receive_chain(self):
        client, server = self.make_pair()
        self.addCleanup(client.destroy)
        self.addCleanup(server.destroy)

        packet = client.encrypt(b"message")
        tampered = packet[:-1] + bytes([packet[-1] ^ 1])
        with self.assertRaises(InvalidTag):
            server.decrypt(tampered)
        self.assertEqual(server.sequence_numbers, (0, 0))
        self.assertEqual(server.decrypt(packet), b"message")

    def test_context_mismatch_does_not_decrypt(self):
        client = SessionRatchet(
            bytearray(b"s" * 32), context=b"session-1", role="client",
        )
        server = SessionRatchet(
            bytearray(b"s" * 32), context=b"session-2", role="server",
        )
        self.addCleanup(client.destroy)
        self.addCleanup(server.destroy)

        with self.assertRaises(InvalidTag):
            server.decrypt(client.encrypt(b"message"))

    def test_expired_session_destroys_ratchet_and_rejects_new_messages(self):
        now = [100.0]
        client, server = self.make_pair(clock=lambda: now[0])
        self.addCleanup(server.destroy)
        now[0] += MAX_SESSION_LIFETIME_SECONDS

        with self.assertRaisesRegex(SessionRatchetError, "expired"):
            client.encrypt(b"late")
        self.assertTrue(client.destroyed)
        with self.assertRaisesRegex(SessionRatchetError, "destroyed"):
            client.encrypt(b"later")

    def test_destroyed_ratchet_cannot_be_reused(self):
        client, server = self.make_pair()
        client.destroy()
        server.destroy()

        with self.assertRaisesRegex(SessionRatchetError, "destroyed"):
            client.encrypt(b"message")


if __name__ == "__main__":
    unittest.main()
