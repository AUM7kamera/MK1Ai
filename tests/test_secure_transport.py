import base64
import hashlib
import json
import pathlib
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from cryptography.exceptions import InvalidTag
from pqcrypto.kem.ml_kem_768 import decaps, keygen  # type: ignore[reportMissingModuleSource]

import mk1_secure_transport as secure_transport


class SecureTransportTest(unittest.TestCase):
    def setUp(self):
        with secure_transport._TRANSPORT_STATE_LOCK:
            for envelope in tuple(secure_transport._ACTIVE_ENVELOPES):
                envelope.destroy()
            secure_transport._TRANSPORT_ENABLED = True

    def test_ml_kem_aes_gcm_request_response_round_trip(self):
        public_key, private_key = keygen()
        fingerprint = hashlib.sha256(public_key).hexdigest()
        envelope = secure_transport.create_encrypted_request(
            public_key,
            {"token": "test-token", "payload": {"task": "test"}},
            "POST",
            "/rsi",
            fingerprint,
        )
        response = secure_transport.encrypt_server_response(
            private_key,
            envelope.kem_ciphertext,
            b'{"accepted":true}',
            "POST",
            "/rsi",
            fingerprint,
        )

        self.assertEqual(
            secure_transport.decrypt_server_response(envelope, response),
            b'{"accepted":true}',
        )
        with self.assertRaises(InvalidTag):
            secure_transport.decrypt_server_response(envelope, response[:-1] + b"\x00")
        envelope.destroy()
        self.assertEqual(envelope.key, bytearray(32))

    def test_disabling_transport_wipes_active_keys_and_rejects_decryption(self):
        public_key, private_key = keygen()
        fingerprint = hashlib.sha256(public_key).hexdigest()
        envelope = secure_transport.create_encrypted_request(
            public_key, {"payload": "test"}, "POST", "/rsi", fingerprint,
        )
        response = secure_transport.encrypt_server_response(
            private_key, envelope.kem_ciphertext, b"response", "POST", "/rsi", fingerprint,
        )

        secure_transport.set_transport_enabled(False)

        self.assertFalse(secure_transport.transport_is_enabled())
        self.assertEqual(envelope.key, bytearray(32))
        with self.assertRaisesRegex(secure_transport.SecureTransportError, "key was destroyed"):
            secure_transport.decrypt_server_response(envelope, response)
        with self.assertRaisesRegex(secure_transport.SecureTransportError, "disabled"):
            secure_transport.create_encrypted_request(
                public_key, {"payload": "test"}, "POST", "/rsi", fingerprint,
            )

    def test_enabling_transport_requires_verified_wireguard_routes(self):
        with mock.patch.object(
            secure_transport, "_verify_wireguard_full_tunnel", return_value="wg0",
        ) as verify:
            secure_transport.set_transport_enabled(True)

        verify.assert_called_once_with()
        self.assertTrue(secure_transport.transport_is_enabled())

    def test_tunnel_control_socket_synchronously_disables_and_reenables_transport(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = pathlib.Path(temp_dir) / "tunnel-control.sock"
            server = secure_transport.TunnelControlServer(str(path))
            server.start()
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(str(path))
                    client.sendall(b"T0")
                    self.assertEqual(client.recv(1), b"1")
                self.assertFalse(secure_transport.transport_is_enabled())

                with mock.patch.object(
                    secure_transport, "_verify_wireguard_full_tunnel", return_value="wg0",
                ):
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.connect(str(path))
                        client.sendall(b"T1")
                        self.assertEqual(client.recv(1), b"1")
                self.assertTrue(secure_transport.transport_is_enabled())

                with mock.patch.object(
                    secure_transport, "set_memory_guard_enabled",
                ) as set_guard:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.connect(str(path))
                        client.sendall(b"M1")
                        self.assertEqual(client.recv(1), b"1")
                set_guard.assert_called_once_with(True)
                self.assertTrue(secure_transport.request_transport_state(str(path), False))
                self.assertFalse(secure_transport.transport_is_enabled())
            finally:
                server.close()

    def test_secret_buffers_are_locked_when_memory_guard_is_enabled(self):
        public_key, _ = keygen()
        fingerprint = hashlib.sha256(public_key).hexdigest()
        with mock.patch.object(
            secure_transport.mk1_memory_guard, "is_enabled", return_value=True,
        ), mock.patch.object(
            secure_transport.mk1_memory_guard, "lock_buffer",
        ) as lock_buffer:
            envelope = secure_transport.create_encrypted_request(
                public_key, {"payload": "test"}, "POST", "/rsi", fingerprint,
            )
        self.assertEqual(lock_buffer.call_count, 2)
        envelope.destroy()

    def test_memory_guard_toggle_protects_and_releases_live_session_keys(self):
        public_key, _ = keygen()
        fingerprint = hashlib.sha256(public_key).hexdigest()
        envelope = secure_transport.create_encrypted_request(
            public_key, {"payload": "test"}, "POST", "/rsi", fingerprint,
        )
        with mock.patch.object(
            secure_transport.mk1_memory_guard, "set_enabled",
        ), mock.patch.object(
            secure_transport.mk1_memory_guard, "lock_buffer",
        ) as lock_buffer, mock.patch.object(
            secure_transport.mk1_memory_guard, "unlock_buffer",
        ) as unlock_buffer:
            secure_transport.set_memory_guard_enabled(True)
            lock_buffer.assert_called_once_with(envelope.key)
            secure_transport.set_memory_guard_enabled(False)
            unlock_buffer.assert_called_once_with(envelope.key)
        envelope.destroy()

    def test_memory_guard_toggle_rolls_back_if_live_key_locking_fails(self):
        public_key, _ = keygen()
        fingerprint = hashlib.sha256(public_key).hexdigest()
        envelope = secure_transport.create_encrypted_request(
            public_key, {"payload": "test"}, "POST", "/rsi", fingerprint,
        )
        with mock.patch.object(
            secure_transport.mk1_memory_guard, "set_enabled",
        ) as set_enabled, mock.patch.object(
            secure_transport.mk1_memory_guard, "lock_buffer", side_effect=OSError("mlock failed"),
        ), mock.patch.object(
            secure_transport.mk1_memory_guard, "unlock_buffer",
        ) as unlock_buffer:
            with self.assertRaisesRegex(OSError, "mlock failed"):
                secure_transport.set_memory_guard_enabled(True)

        self.assertEqual(
            [call.args for call in set_enabled.call_args_list],
            [(True,), (False,)],
        )
        unlock_buffer.assert_called_once_with(envelope.key)
        envelope.destroy()

    def test_concurrent_disable_cannot_be_overridden_by_a_stale_enable(self):
        verification_started = threading.Event()
        finish_verification = threading.Event()
        errors = []

        def verify_routes():
            verification_started.set()
            finish_verification.wait(2)
            return "wg0"

        secure_transport.set_transport_enabled(False)
        with mock.patch.object(
            secure_transport, "_verify_wireguard_full_tunnel", side_effect=verify_routes,
        ):
            enabling = threading.Thread(
                target=lambda: self._capture_enable_error(errors),
            )
            enabling.start()
            self.assertTrue(verification_started.wait(2))
            secure_transport.set_transport_enabled(False)
            finish_verification.set()
            enabling.join(2)

        self.assertFalse(enabling.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], secure_transport.SecureTransportError)
        self.assertFalse(secure_transport.transport_is_enabled())

    @staticmethod
    def _capture_enable_error(errors):
        try:
            secure_transport.set_transport_enabled(True)
        except secure_transport.SecureTransportError as exc:
            errors.append(exc)

    def test_encrypted_request_pins_server_key_and_keeps_token_inside_ciphertext(self):
        public_key, private_key = keygen()
        fingerprint = hashlib.sha256(public_key).hexdigest()
        get_response = mock.Mock()
        get_response.json.return_value = {
            "algorithm": "ML-KEM-768",
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "sha256": fingerprint,
        }
        post_response = mock.Mock()
        post_response.content = b""
        post_response.headers = {}

        def receive_request(url, *, data, headers, timeout, stream):
            self.assertEqual(url, "https://colab.example.test/api/rsi")
            self.assertEqual(timeout, (60, 300))
            self.assertTrue(stream)
            kem_ciphertext = base64.b64decode(headers["X-MK1-KEM"], validate=True)
            aad = secure_transport._request_aad("POST", "/api/rsi", fingerprint, kem_ciphertext)
            shared_secret = decaps(private_key, kem_ciphertext)
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF

            key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=hashlib.sha256(aad).digest(),
                info=b"MK1-RSI-ML-KEM-768-AES-256-GCM-v1",
            ).derive(shared_secret)
            document = json.loads(AESGCM(key).decrypt(data[:12], data[12:], aad))
            self.assertEqual(document, {"token": "private-token", "payload": {"task": "test"}})
            post_response.content = secure_transport.encrypt_server_response(
                private_key,
                kem_ciphertext,
                b'{"accepted":true}',
                "POST",
                "/api/rsi",
                fingerprint,
            )
            post_response.iter_content.return_value = [post_response.content]
            return post_response

        fake_requests = mock.Mock()
        fake_requests.get.return_value = get_response
        fake_requests.post.side_effect = receive_request
        with mock.patch.object(secure_transport, "require_wireguard_full_tunnel", return_value="wg0"):
            response = secure_transport.encrypted_request(
                fake_requests,
                "https://colab.example.test/api/rsi",
                {"task": "test"},
                "private-token",
                fingerprint,
            )

        self.assertEqual(response, b'{"accepted":true}')
        self.assertEqual(
            fake_requests.get.call_args.args[0],
            "https://colab.example.test/api/crypto/public-key",
        )
        get_response.close.assert_called_once()
        post_response.close.assert_called_once()

    def test_pqc_key_pin_mismatch_is_rejected(self):
        public_key = keygen()[0]
        response = mock.Mock()
        response.json.return_value = {
            "algorithm": "ML-KEM-768",
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "sha256": hashlib.sha256(public_key).hexdigest(),
        }
        requests_module = mock.Mock()
        requests_module.get.return_value = response

        with self.assertRaisesRegex(secure_transport.SecureTransportError, "pin does not match"):
            secure_transport.pinned_server_public_key(
                "https://colab.example.test/rsi", "0" * 64, requests_module,
            )
        response.close.assert_called_once()

    def test_wireguard_gate_requires_both_default_routes_and_matching_interface(self):
        outputs = [
            "peer\t0.0.0.0/0, ::/0\n",
            "1.1.1.1 dev wg0 src 10.0.0.2\n",
            "2606:4700:4700::1111 dev wg0 src 2001:db8::2\n",
        ]
        completed = [
            subprocess.CompletedProcess([], 0, stdout=output, stderr="")
            for output in outputs
        ]
        with mock.patch.object(secure_transport.platform, "system", return_value="Linux"), \
             mock.patch.object(secure_transport.subprocess, "run", side_effect=completed):
            self.assertEqual(secure_transport.require_wireguard_full_tunnel("wg0"), "wg0")

    def test_wireguard_gate_rejects_missing_pqc_or_routes(self):
        outputs = [
            "peer\t10.0.0.0/24\n",
            "1.1.1.1 dev eth0 src 192.0.2.2\n",
            "2606:4700:4700::1111 dev eth0 src 2001:db8::2\n",
        ]
        completed = [
            subprocess.CompletedProcess([], 0, stdout=output, stderr="")
            for output in outputs
        ]
        with mock.patch.object(secure_transport.platform, "system", return_value="Linux"), \
             mock.patch.object(secure_transport.subprocess, "run", side_effect=completed):
            with self.assertRaisesRegex(secure_transport.SecureTransportError, "must allow"):
                secure_transport.require_wireguard_full_tunnel("wg0")

    def test_wireguard_service_address_must_be_assigned_to_interface(self):
        completed = subprocess.CompletedProcess(
            [], 0, stdout="7: wg0    inet 10.77.0.1/24 scope global wg0\n", stderr="",
        )
        with mock.patch.object(secure_transport.subprocess, "run", return_value=completed):
            self.assertEqual(
                secure_transport.require_wireguard_address("wg0", "10.77.0.1"),
                "10.77.0.1",
            )
        with mock.patch.object(secure_transport.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(
                secure_transport.SecureTransportError, "not assigned",
            ):
                secure_transport.require_wireguard_address("wg0", "10.77.0.2")


if __name__ == "__main__":
    unittest.main()
