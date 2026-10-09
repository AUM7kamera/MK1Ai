"""Fail-closed helpers for the WireGuard and ML-KEM/AES-GCM RSI transport."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import re
import socket
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import mk1_memory_guard

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem.ml_kem_768 import decaps, encaps  # type: ignore[reportMissingModuleSource]


class SecureTransportError(RuntimeError):
    """Raised when the required tunnel or pinned PQC transport is unavailable."""


_TRANSPORT_STATE_LOCK = threading.RLock()
_TRANSPORT_ENABLED = True
_TRANSPORT_GENERATION = 0
_ACTIVE_ENVELOPES: set["EncryptedRequest"] = set()


class TunnelControlServer:
    """Private local IPC endpoint for synchronous key destruction requests."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._stop_event = threading.Event()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._socket_identity: tuple[int, int] | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        try:
            existing = os.lstat(self.path)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != os.geteuid():
                raise SecureTransportError("Refusing to replace an untrusted tunnel control path")
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.settimeout(0.2)
            try:
                probe.connect(self.path)
            except ConnectionRefusedError:
                pass
            else:
                raise SecureTransportError("A tunnel control server is already active")
            finally:
                probe.close()
            os.unlink(self.path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # umask makes the socket 0600 at creation, so there is no window before chmod.
            previous_umask = os.umask(0o177)
            try:
                listener.bind(self.path)
            finally:
                os.umask(previous_umask)
            sudo_uid = os.environ.get("SUDO_UID", "")
            sudo_gid = os.environ.get("SUDO_GID", "")
            if os.geteuid() == 0 and sudo_uid.isdigit() and sudo_gid.isdigit():
                os.chown(
                    self.path, int(sudo_uid), int(sudo_gid), follow_symlinks=False,
                )
            os.chmod(self.path, 0o600)
            socket_stat = os.lstat(self.path)
            self._socket_identity = (socket_stat.st_dev, socket_stat.st_ino)
            listener.listen(4)
            listener.settimeout(0.2)
        except OSError:
            listener.close()
            self._unlink_owned_socket()
            raise
        self._listener = listener
        self._thread = threading.Thread(
            target=self._serve, name="mk1-tunnel-control", daemon=True,
        )
        self._thread.start()

    def _serve(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while not self._stop_event.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop_event.is_set():
                    return
                break
            with client:
                try:
                    client.settimeout(1.0)
                    command = bytearray()
                    while len(command) < 2:
                        chunk = client.recv(2 - len(command))
                        if not chunk:
                            break
                        command.extend(chunk)
                    if len(command) != 2 or command[0:1] not in (b"T", b"M") or command[1:2] not in (b"0", b"1"):
                        client.sendall(b"0")
                        continue
                    enabled = command[1:2] == b"1"
                    if command[0:1] == b"T":
                        set_transport_enabled(enabled)
                    else:
                        set_memory_guard_enabled(enabled)
                    client.sendall(b"1")
                except (OSError, SecureTransportError, RuntimeError, ValueError):
                    try:
                        client.sendall(b"0")
                    except OSError:
                        pass

    def _unlink_owned_socket(self) -> None:
        if self._socket_identity is None:
            return
        try:
            current = os.lstat(self.path)
        except FileNotFoundError:
            return
        if (
            stat.S_ISSOCK(current.st_mode)
            and (current.st_dev, current.st_ino) == self._socket_identity
        ):
            os.unlink(self.path)
        self._socket_identity = None

    def close(self) -> None:
        self._stop_event.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            listener.close()
        thread, self._thread = self._thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
            if thread.is_alive():
                raise RuntimeError("Tunnel control server did not stop")
        self._unlink_owned_socket()


def _wipe_buffer(buffer: bytearray) -> None:
    mk1_memory_guard.wipe_buffer(buffer)


def _lock_secret_buffer(buffer: bytearray) -> None:
    if mk1_memory_guard.is_enabled():
        mk1_memory_guard.lock_buffer(buffer)


def _protect_secret_buffers(*buffers: bytearray) -> None:
    if not mk1_memory_guard.is_enabled():
        return
    for buffer in buffers:
        _lock_secret_buffer(buffer)


def set_memory_guard_enabled(enabled: bool) -> None:
    """Toggle process hardening and protect every live transport key atomically."""
    if not isinstance(enabled, bool):
        raise ValueError("Memory guard state must be a boolean")
    with _TRANSPORT_STATE_LOCK:
        mk1_memory_guard.set_enabled(enabled)
        envelopes = tuple(_ACTIVE_ENVELOPES)
        if not enabled:
            for envelope in envelopes:
                mk1_memory_guard.unlock_buffer(envelope.key)
            return
        try:
            for envelope in envelopes:
                mk1_memory_guard.lock_buffer(envelope.key)
        except OSError:
            for envelope in envelopes:
                mk1_memory_guard.unlock_buffer(envelope.key)
            mk1_memory_guard.set_enabled(False)
            raise


@dataclass(eq=False)
class EncryptedRequest:
    kem_ciphertext: bytes
    body: bytes
    key: bytearray
    aad: bytes
    _key_lock: threading.Lock
    _destroyed: bool = False

    def destroy(self) -> None:
        with _TRANSPORT_STATE_LOCK:
            with self._key_lock:
                if self._destroyed:
                    return
                _wipe_buffer(self.key)
                self._destroyed = True
            _ACTIVE_ENVELOPES.discard(self)


def transport_is_enabled() -> bool:
    with _TRANSPORT_STATE_LOCK:
        return _TRANSPORT_ENABLED


def set_transport_enabled(enabled: bool) -> None:
    """Gate PQC transport; disabling also wipes every registered session key."""
    if not isinstance(enabled, bool):
        raise ValueError("Transport state must be a boolean")
    global _TRANSPORT_ENABLED, _TRANSPORT_GENERATION
    if enabled:
        with _TRANSPORT_STATE_LOCK:
            generation = _TRANSPORT_GENERATION
        _verify_wireguard_full_tunnel()
        with _TRANSPORT_STATE_LOCK:
            if generation != _TRANSPORT_GENERATION:
                raise SecureTransportError("Transport state changed during WireGuard verification")
            _TRANSPORT_ENABLED = True
        return
    with _TRANSPORT_STATE_LOCK:
        _TRANSPORT_GENERATION += 1
        _TRANSPORT_ENABLED = False
        for envelope in tuple(_ACTIVE_ENVELOPES):
            envelope.destroy()


def request_transport_state(path: str, enabled: bool) -> bool:
    """Request a synchronous local gate/key update from the active monitor."""
    if not isinstance(enabled, bool):
        raise ValueError("Transport state must be a boolean")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2.0)
            client.connect(path)
            client.sendall(b"T1" if enabled else b"T0")
            return client.recv(1) == b"1"
    except OSError:
        return False


def _require_transport_enabled() -> None:
    if not transport_is_enabled():
        raise SecureTransportError("Encrypted transport is disabled")


def require_wireguard_full_tunnel(interface: str | None = None) -> str:
    """Require an active WireGuard peer and IPv4/IPv6 default routes through it."""
    _require_transport_enabled()
    return _verify_wireguard_full_tunnel(interface)


_SYSTEM_EXECUTABLE_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
_TRUSTED_UID = 0
_MAX_HANDSHAKE_AGE_SECONDS = 180
_HANDSHAKE_FUTURE_SKEW_SECONDS = 5
_DEFAULT_ROUTE_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/0"),
    ipaddress.ip_network("::/0"),
)


def _path_entry_is_trusted(entry_stat: os.stat_result) -> bool:
    return entry_stat.st_uid == _TRUSTED_UID and not (
        entry_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


def _trusted_system_executable(name: str) -> str:
    """Resolve a system tool to an absolute path whose whole chain is root-owned."""
    for directory in _SYSTEM_EXECUTABLE_DIRS:
        candidate = os.path.join(directory, name)
        try:
            resolved = os.path.realpath(candidate, strict=True)
            if not stat.S_ISREG(os.stat(resolved).st_mode) or not os.access(resolved, os.X_OK):
                continue
            chain = [resolved]
            while chain[-1] != os.path.dirname(chain[-1]):
                chain.append(os.path.dirname(chain[-1]))
            if all(_path_entry_is_trusted(os.stat(entry)) for entry in chain):
                return resolved
        except OSError:
            continue
    raise SecureTransportError(f"No trusted system executable found for {name}")


def _parse_allowed_ips(output: str) -> bool:
    """True only when exact IPv4 and IPv6 default networks are allowed."""
    found: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    for row in output.splitlines():
        fields = row.split("\t", 1)
        if len(fields) != 2:
            continue
        for token in re.split(r"[\s,]+", fields[1].strip()):
            if not token or token == "(none)":
                continue
            try:
                network = ipaddress.ip_network(token, strict=True)
            except ValueError:
                continue
            if network in _DEFAULT_ROUTE_NETWORKS and token in ("0.0.0.0/0", "::/0"):
                found.add(network)
    return found == set(_DEFAULT_ROUTE_NETWORKS)


def _has_recent_handshake(output: str, now: float) -> bool:
    for row in output.splitlines():
        fields = row.split()
        if len(fields) != 2 or not fields[1].isascii() or not fields[1].isdigit():
            continue
        handshake = int(fields[1])
        if handshake == 0:
            continue
        age = now - handshake
        if -_HANDSHAKE_FUTURE_SKEW_SECONDS <= age <= _MAX_HANDSHAKE_AGE_SECONDS:
            return True
    return False


def _verify_wireguard_full_tunnel(interface: str | None = None) -> str:
    interface = (interface or os.environ.get("MK1_WIREGUARD_INTERFACE", "wg0")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
        raise SecureTransportError("MK1_WIREGUARD_INTERFACE is invalid")
    if platform.system() != "Linux":
        raise SecureTransportError(
            "Fail-closed WireGuard route verification currently supports Linux only"
        )

    def run(command: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            command, check=True, capture_output=True, text=True, timeout=3,
        )

    try:
        wg = _trusted_system_executable("wg")
        ip = _trusted_system_executable("ip")
        peer = run([wg, "show", interface, "allowed-ips"])
        handshakes = run([wg, "show", interface, "latest-handshakes"])
        ipv4_route = run([ip, "route", "get", "1.1.1.1"])
        ipv6_route = run([ip, "-6", "route", "get", "2606:4700:4700::1111"])
    except (OSError, subprocess.SubprocessError) as exc:
        raise SecureTransportError(
            "Unable to verify an active WireGuard full-tunnel route"
        ) from exc

    if not _parse_allowed_ips(peer.stdout):
        raise SecureTransportError(
            f"WireGuard interface {interface} must allow IPv4 and IPv6 default routes"
        )
    if not _has_recent_handshake(handshakes.stdout, time.time()):
        raise SecureTransportError(
            f"WireGuard interface {interface} has no peer handshake in the last "
            f"{_MAX_HANDSHAKE_AGE_SECONDS} seconds"
        )
    if not re.search(rf"\bdev\s+{re.escape(interface)}\b", ipv4_route.stdout):
        raise SecureTransportError("IPv4 default route is not using WireGuard")
    if not re.search(rf"\bdev\s+{re.escape(interface)}\b", ipv6_route.stdout):
        raise SecureTransportError("IPv6 default route is not using WireGuard")
    return interface


def require_wireguard_address(interface: str, address: str) -> str:
    """Require the configured service address to be assigned to the WireGuard link."""
    try:
        expected = ipaddress.ip_address(address)
        result = subprocess.run(
            [_trusted_system_executable("ip"), "-o", "address", "show", "dev", interface],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        raise SecureTransportError(
            "Unable to verify the WireGuard service bind address"
        ) from exc
    for line in result.stdout.splitlines():
        fields = line.split()
        for index, field in enumerate(fields[:-1]):
            if field in ("inet", "inet6"):
                try:
                    assigned = ipaddress.ip_interface(fields[index + 1]).ip
                except ValueError:
                    continue
                if assigned == expected:
                    return str(expected)
    raise SecureTransportError(
        "The remote service bind address is not assigned to the WireGuard interface"
    )


def _public_key_url(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname:
        raise SecureTransportError("The RSI endpoint must use HTTPS")
    base_path = parsed.path.rstrip("/").rsplit("/", 1)[0]
    return urlunsplit((parsed.scheme, parsed.netloc, f"{base_path}/crypto/public-key", "", ""))


def _request_aad(method: str, path: str, fingerprint: str, kem_ciphertext: bytes) -> bytes:
    return b"MK1-RSI-v1\0" + b"\0".join((
        method.upper().encode("ascii"),
        path.encode("utf-8"),
        fingerprint.encode("ascii"),
        kem_ciphertext,
    ))


def create_encrypted_request(
    public_key: bytes,
    payload: dict[str, Any],
    method: str,
    path: str,
    fingerprint: str,
) -> EncryptedRequest:
    with _TRANSPORT_STATE_LOCK:
        _require_transport_enabled()
        kem_ciphertext, shared_secret_bytes = encaps(public_key)
        shared_secret = bytearray(shared_secret_bytes)
        del shared_secret_bytes
        key = bytearray()
        cipher = None
        try:
            _protect_secret_buffers(shared_secret)
            aad = _request_aad(method, path, fingerprint, kem_ciphertext)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=hashlib.sha256(aad).digest(),
                info=b"MK1-RSI-ML-KEM-768-AES-256-GCM-v1",
            ).derive(shared_secret)
            key.extend(derived_key)
            del derived_key
            _protect_secret_buffers(key)
            nonce = os.urandom(12)
            plaintext = json.dumps(
                payload, separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")
            cipher = AESGCM(key)
            body = nonce + cipher.encrypt(nonce, plaintext, aad)
            del cipher
            cipher = None
            envelope = EncryptedRequest(
                kem_ciphertext=kem_ciphertext,
                body=body,
                key=key,
                aad=aad,
                _key_lock=threading.Lock(),
            )
            _ACTIVE_ENVELOPES.add(envelope)
            return envelope
        except Exception:
            if cipher is not None:
                del cipher
            _wipe_buffer(key)
            raise
        finally:
            _wipe_buffer(shared_secret)


def encrypt_server_response(
    private_key: bytes,
    kem_ciphertext: bytes,
    plaintext: bytes,
    method: str,
    path: str,
    fingerprint: str,
) -> bytes:
    aad = _request_aad(method, path, fingerprint, kem_ciphertext)
    shared_secret_bytes = decaps(private_key, kem_ciphertext)
    shared_secret = bytearray(shared_secret_bytes)
    del shared_secret_bytes
    key = bytearray()
    cipher = None
    try:
        _protect_secret_buffers(shared_secret)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(aad).digest(),
            info=b"MK1-RSI-ML-KEM-768-AES-256-GCM-v1",
        ).derive(shared_secret)
        key.extend(derived_key)
        del derived_key
        _protect_secret_buffers(key)
        nonce = os.urandom(12)
        cipher = AESGCM(key)
        encrypted = nonce + cipher.encrypt(
            nonce, plaintext, aad + b"\0response",
        )
        del cipher
        cipher = None
        return encrypted
    finally:
        if cipher is not None:
            del cipher
        _wipe_buffer(key)
        _wipe_buffer(shared_secret)


def decrypt_server_response(encrypted_request: EncryptedRequest, body: bytes) -> bytes:
    if len(body) < 12 + 16:
        raise SecureTransportError("Encrypted server response is truncated")
    with encrypted_request._key_lock:
        if encrypted_request._destroyed:
            raise SecureTransportError("Encrypted transport session key was destroyed")
        cipher = AESGCM(encrypted_request.key)
        try:
            return cipher.decrypt(
                body[:12], body[12:], encrypted_request.aad + b"\0response",
            )
        finally:
            del cipher


def pinned_server_public_key(
    endpoint: str,
    expected_fingerprint: str,
    requests_module: Any,
) -> tuple[bytes, str]:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_fingerprint):
        raise SecureTransportError(
            "COLAB_RSI_PQ_PUBLIC_KEY_SHA256 must contain the 64-hex SHA-256 pin"
        )
    response = requests_module.get(_public_key_url(endpoint), timeout=(10, 30))
    try:
        response.raise_for_status()
        document = response.json()
        public_key = base64.b64decode(document["public_key"], validate=True)
        fingerprint = hashlib.sha256(public_key).hexdigest()
        if document.get("algorithm") != "ML-KEM-768":
            raise SecureTransportError("Colab server uses an unsupported PQC algorithm")
        if not hmac.compare_digest(fingerprint, expected_fingerprint.lower()):
            raise SecureTransportError("Colab ML-KEM public-key pin does not match")
        if document.get("sha256") != fingerprint:
            raise SecureTransportError("Colab ML-KEM public-key fingerprint is inconsistent")
        return public_key, fingerprint
    finally:
        response.close()


def encrypted_request(
    requests_module: Any,
    endpoint: str,
    payload: dict[str, Any],
    token: str,
    expected_fingerprint: str,
    *,
    method: str = "POST",
    max_response_bytes: int = 2 * 1024 * 1024,
) -> bytes:
    _require_transport_enabled()
    if not token:
        raise SecureTransportError("An API token is required for encrypted Colab requests")
    require_wireguard_full_tunnel()
    public_key, fingerprint = pinned_server_public_key(
        endpoint, expected_fingerprint, requests_module,
    )
    parsed = urlsplit(endpoint)
    envelope = create_encrypted_request(
        public_key,
        {"token": token, "payload": payload},
        method,
        parsed.path or "/",
        fingerprint,
    )
    response = None
    try:
        response = requests_module.post(
            endpoint,
            data=envelope.body,
            headers={
                "Content-Type": "application/octet-stream",
                "X-MK1-KEM": base64.b64encode(envelope.kem_ciphertext).decode("ascii"),
            },
            timeout=(60, 300),
            stream=True,
        )
        response.raise_for_status()
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > max_response_bytes:
            raise SecureTransportError("Encrypted Colab response exceeds its configured size limit")
        chunks = []
        total_bytes = 0
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            total_bytes += len(chunk)
            if total_bytes > max_response_bytes:
                raise SecureTransportError("Encrypted Colab response exceeds its configured size limit")
            chunks.append(chunk)
        return decrypt_server_response(envelope, b"".join(chunks))
    finally:
        try:
            if response is not None:
                response.close()
        finally:
            envelope.destroy()


def validate_public_key_pin(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()))
