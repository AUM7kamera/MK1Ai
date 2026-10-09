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

    def test_tunnel_control_socket_is_private_from_the_moment_it_is_bound(self):
        import os

        previous_umask = os.umask(0o022)
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                path = pathlib.Path(temp_dir) / "tunnel-control.sock"
                server = secure_transport.TunnelControlServer(str(path))
                with mock.patch.object(secure_transport.os, "chmod"):
                    server.start()
                try:
                    self.assertEqual(os.lstat(path).st_mode & 0o777, 0o600)
                    self.assertEqual(os.umask(0o022), 0o022)
                finally:
                    server.close()
        finally:
            os.umask(previous_umask)

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

    def _run_wireguard_gate(self, allowed, handshakes, route4=None, route6=None, now=1_000_000):
        outputs = {
            ("wg", "allowed-ips"): allowed,
            ("wg", "latest-handshakes"): handshakes,
            ("ip", "route4"): route4 or "1.1.1.1 dev wg0 src 10.0.0.2\n",
            ("ip", "route6"): route6 or "2606:4700:4700::1111 dev wg0 src 2001:db8::2\n",
        }
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            if command[0].endswith("/wg"):
                key = ("wg", command[3])
            else:
                key = ("ip", "route6" if "-6" in command else "route4")
            return subprocess.CompletedProcess(command, 0, stdout=outputs[key], stderr="")

        with mock.patch.object(secure_transport.platform, "system", return_value="Linux"), \
             mock.patch.object(
                 secure_transport, "_trusted_system_executable",
                 side_effect=lambda name: f"/usr/bin/{name}",
             ), \
             mock.patch.object(secure_transport.time, "time", return_value=now), \
             mock.patch.object(secure_transport.subprocess, "run", side_effect=run):
            try:
                return secure_transport.require_wireguard_full_tunnel("wg0"), calls
            except secure_transport.SecureTransportError as exc:
                return exc, calls

    def test_wireguard_gate_requires_both_default_routes_and_matching_interface(self):
        result, calls = self._run_wireguard_gate(
            "peer\t0.0.0.0/0, ::/0\n", "peer\t999900\n",
        )
        self.assertEqual(result, "wg0")
        self.assertTrue(all(command[0].startswith("/usr/") for command in calls))

    def test_wireguard_gate_rejects_missing_pqc_or_routes(self):
        result, _ = self._run_wireguard_gate(
            "peer\t10.0.0.0/24\n", "peer\t999900\n",
            "1.1.1.1 dev eth0 src 192.0.2.2\n",
        )
        self.assertIsInstance(result, secure_transport.SecureTransportError)
        self.assertIn("must allow", str(result))

    def test_wireguard_allowed_ips_must_be_exact_default_networks(self):
        for allowed in (
            "peer\t10.0.0.0/0\n",
            "peer\t0.0.0.0/1, 128.0.0.0/1, ::/0\n",
            "peer\t0.0.0.0/0\n",
            "peer\t0.0.0.0/01, ::/0\n",
            "peer\tnot-an-ip, ::/0\n",
        ):
            with self.subTest(allowed=allowed):
                result, _ = self._run_wireguard_gate(allowed, "peer\t999900\n")
                self.assertIsInstance(result, secure_transport.SecureTransportError)
        result, _ = self._run_wireguard_gate("peer\t0.0.0.0/0\t::/0\n", "peer\t999900\n")
        self.assertEqual(result, "wg0")

    def test_wireguard_gate_requires_recent_handshake_on_a_peer(self):
        full = "peer\t0.0.0.0/0 ::/0\n"
        for handshakes in (
            "peer\t0\n", "peer\t999819\n", "", "peer\tabc\n", "peer\t-5\n",
            "peer\t1000600\n",
        ):
            with self.subTest(handshakes=handshakes):
                result, _ = self._run_wireguard_gate(full, handshakes)
                self.assertIsInstance(result, secure_transport.SecureTransportError)
                self.assertIn("handshake", str(result))
        result, _ = self._run_wireguard_gate(full, "old\t1\nnew\t999820\n")
        self.assertEqual(result, "wg0")

    def test_trusted_system_executable_requires_root_owned_non_writable_chain(self):
        regular = mock.Mock(st_uid=0, st_mode=0o100755)
        self.assertTrue(secure_transport._path_entry_is_trusted(regular))
        for entry in (
            mock.Mock(st_uid=1000, st_mode=0o100755),
            mock.Mock(st_uid=0, st_mode=0o100775),
            mock.Mock(st_uid=0, st_mode=0o100757),
        ):
            self.assertFalse(secure_transport._path_entry_is_trusted(entry))

        with tempfile.TemporaryDirectory(dir=pathlib.Path(__file__).parent) as directory:
            tool = pathlib.Path(directory, "wg")
            tool.write_bytes(b"#!/bin/sh\n")
            tool.chmod(0o755)
            with mock.patch.object(secure_transport, "_SYSTEM_EXECUTABLE_DIRS", (directory,)):
                with self.assertRaisesRegex(secure_transport.SecureTransportError, "trusted"):
                    secure_transport._trusted_system_executable("wg")
                with mock.patch.object(
                    secure_transport, "_path_entry_is_trusted", return_value=True,
                ):
                    self.assertEqual(
                        secure_transport._trusted_system_executable("wg"),
                        str(tool.resolve()),
                    )
                    with self.assertRaises(secure_transport.SecureTransportError):
                        secure_transport._trusted_system_executable("missing")

    def test_wireguard_service_address_must_be_assigned_to_interface(self):
        completed = subprocess.CompletedProcess(
            [], 0, stdout="7: wg0    inet 10.77.0.1/24 scope global wg0\n", stderr="",
        )
        trusted = mock.patch.object(
            secure_transport, "_trusted_system_executable", return_value="/usr/sbin/ip",
        )
        with trusted, mock.patch.object(
            secure_transport.subprocess, "run", return_value=completed,
        ) as run:
            self.assertEqual(
                secure_transport.require_wireguard_address("wg0", "10.77.0.1"),
                "10.77.0.1",
            )
            self.assertEqual(run.call_args.args[0][0], "/usr/sbin/ip")
        with trusted, mock.patch.object(secure_transport.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(
                secure_transport.SecureTransportError, "not assigned",
            ):
                secure_transport.require_wireguard_address("wg0", "10.77.0.2")


NOTEBOOK_PATH = pathlib.Path(__file__).resolve().parents[1] / "colab_training.ipynb"
PINNED_CLOUDFLARED_VERSION = "2025.8.1"
PINNED_CLOUDFLARED_SHA256 = "a66353004197ee4c1fcb68549203824882bba62378ad4d00d234bdb8251f1114"


def _notebook_source():
    notebook = json.loads(NOTEBOOK_PATH.read_text(encoding="utf-8"))
    return "\n".join(
        "".join(cell["source"]) for cell in notebook["cells"] if cell["cell_type"] == "code"
    )


def _load_notebook_symbols(names, namespace):
    """Exec only selected top-level defs/assignments so no Colab/torch/network code runs."""
    import ast

    source = _notebook_source()
    tree = ast.parse(source)
    wanted = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names:
            wanted.append(node)
        elif isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id in names for t in node.targets
        ):
            wanted.append(node)
    found = {
        getattr(n, "name", None) or n.targets[0].id for n in wanted
    }
    missing = set(names) - found
    if missing:
        raise AssertionError(f"notebook is missing {sorted(missing)}")
    exec(compile(ast.Module(wanted, []), str(NOTEBOOK_PATH), "exec"), namespace)
    return namespace


class ColabNotebookHardeningTest(unittest.TestCase):
    def _namespace(self, names):
        import collections
        import ipaddress
        import os
        import re
        import threading
        import time

        namespace = {
            "hashlib": hashlib, "hmac": __import__("hmac"), "ipaddress": ipaddress,
            "os": os, "re": re, "subprocess": subprocess, "threading": threading,
            "stat": __import__("stat"), "time": time, "collections": collections, "Path": pathlib.Path,
            "urllib": __import__("urllib"),
        }
        return _load_notebook_symbols(names, namespace)

    def test_notebook_wireguard_gate_is_strict(self):
        ns = self._namespace({
            "_SYSTEM_EXECUTABLE_DIRS", "_TRUSTED_UID", "_DEFAULT_ROUTE_TOKENS", "_path_entry_is_trusted",
            "_trusted_system_executable", "_parse_allowed_ips", "_has_recent_handshake",
            "require_wireguard_full_tunnel",
        })
        self.assertTrue(ns["_parse_allowed_ips"]("p\t0.0.0.0/0, ::/0\n"))
        self.assertFalse(ns["_parse_allowed_ips"]("p\t10.0.0.0/0, ::/0\n"))
        self.assertFalse(ns["_parse_allowed_ips"]("p\t0.0.0.0/1, 128.0.0.0/1, ::/0\n"))
        self.assertTrue(ns["_has_recent_handshake"]("p\t999900\n", 1_000_000))
        self.assertFalse(ns["_has_recent_handshake"]("p\t0\n", 1_000_000))
        self.assertFalse(ns["_has_recent_handshake"]("p\t999819\n", 1_000_000))
        self.assertFalse(ns["_path_entry_is_trusted"](mock.Mock(st_uid=0, st_mode=0o100777)))

        def run(command, **kwargs):
            self.assertTrue(command[0].startswith("/usr/"))
            if command[0].endswith("/wg") and command[3] == "allowed-ips":
                out = "p\t0.0.0.0/0 ::/0\n"
            elif command[0].endswith("/wg"):
                out = "p\t999900\n"
            elif "-6" in command:
                out = "x dev wg0\n"
            else:
                out = "x dev wg0\n"
            return subprocess.CompletedProcess(command, 0, stdout=out, stderr="")

        ns["_trusted_system_executable"] = lambda name: f"/usr/bin/{name}"
        ns["time"] = mock.Mock(time=mock.Mock(return_value=1_000_000))
        ns["subprocess"] = mock.Mock(
            run=mock.Mock(side_effect=run), SubprocessError=subprocess.SubprocessError,
        )
        with mock.patch.dict("os.environ", {"MK1_WIREGUARD_INTERFACE": "wg0"}):
            self.assertEqual(ns["require_wireguard_full_tunnel"](), "wg0")
            ns["time"] = mock.Mock(time=mock.Mock(return_value=2_000_000))
            with self.assertRaisesRegex(RuntimeError, "handshake"):
                ns["require_wireguard_full_tunnel"]()

            def route_matches_prefix(command, **_kwargs):
                if command[0].endswith("/wg") and command[3] == "allowed-ips":
                    output = "p\t0.0.0.0/0 ::/0\n"
                elif command[0].endswith("/wg"):
                    output = "p\t999900\n"
                else:
                    output = "x dev wg0-untrusted\n"
                return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

            ns["time"] = mock.Mock(time=mock.Mock(return_value=1_000_000))
            ns["subprocess"].run.side_effect = route_matches_prefix
            with self.assertRaisesRegex(RuntimeError, "both IPv4 and IPv6"):
                ns["require_wireguard_full_tunnel"]()

    def test_submitted_at_must_be_integer_within_120_seconds(self):
        ns = self._namespace({"SUBMITTED_AT_WINDOW_SECONDS", "valid_submitted_at"})
        valid = ns["valid_submitted_at"]
        self.assertTrue(valid(1000, now=1000))
        self.assertTrue(valid(880, now=1000))
        self.assertTrue(valid(1120, now=1000))
        for bad in (879, 1121, True, 1000.0, "1000", None):
            with self.subTest(bad=bad):
                self.assertFalse(valid(bad, now=1000))

    def test_replay_cache_is_keyed_by_ciphertext_hash_with_bounded_ttl(self):
        ns = self._namespace({
            "REPLAY_TTL_SECONDS", "REPLAY_CACHE_MAX_ENTRIES", "ReplayCache",
        })
        cache = ns["ReplayCache"](ttl_seconds=10, max_entries=2)
        self.assertTrue(cache.accept(b"a", now=0))
        self.assertFalse(cache.accept(b"a", now=5))
        self.assertIn(hashlib.sha256(b"a").digest(), cache._entries)
        self.assertNotIn(b"a", cache._entries)
        self.assertTrue(cache.accept(b"a", now=11))
        self.assertTrue(cache.accept(b"b", now=11))
        self.assertFalse(cache.accept(b"c", now=11))
        self.assertTrue(cache.accept(b"c", now=22))

    def test_token_comparison_uses_bytes_compare_digest(self):
        ns = self._namespace({"tokens_match"})
        self.assertTrue(ns["tokens_match"]("secret", "secret"))
        self.assertFalse(ns["tokens_match"]("secrex", "secret"))
        self.assertFalse(ns["tokens_match"]("sécret", "secret"))
        self.assertFalse(ns["tokens_match"](None, "secret"))
        with mock.patch.object(ns["hmac"], "compare_digest", return_value=True) as compare:
            ns["tokens_match"]("a", "b")
        self.assertEqual(compare.call_args.args, (b"a", b"b"))

    def test_cloudflared_is_pinned_and_hash_checked_before_exec(self):
        source = _notebook_source()
        self.assertNotIn("releases/latest", source)
        self.assertNotIn("'install', '--quiet', 'flask']", source)
        self.assertIn("flask==", source)
        ns = self._namespace({
            "CLOUDFLARED_VERSION", "CLOUDFLARED_SHA256", "CLOUDFLARED_URL",
            "verify_cloudflared",
        })
        self.assertEqual(ns["CLOUDFLARED_VERSION"], PINNED_CLOUDFLARED_VERSION)
        self.assertEqual(ns["CLOUDFLARED_SHA256"], PINNED_CLOUDFLARED_SHA256)
        self.assertIn(f"/download/{PINNED_CLOUDFLARED_VERSION}/", ns["CLOUDFLARED_URL"])
        with tempfile.TemporaryDirectory(dir=pathlib.Path(__file__).parent) as directory:
            binary = pathlib.Path(directory, "cloudflared")
            binary.write_bytes(b"tampered")
            with self.assertRaisesRegex(RuntimeError, "SHA-256"):
                ns["verify_cloudflared"](binary)
            ns["CLOUDFLARED_SHA256"] = hashlib.sha256(b"tampered").hexdigest()
            ns["verify_cloudflared"](binary)
        popen = source.index("subprocess.Popen(")
        self.assertLess(source.rindex("verify_cloudflared(", 0, popen), popen)


if __name__ == "__main__":
    unittest.main()
