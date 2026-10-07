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
import subprocess
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem.ml_kem_768 import decaps, encaps  # type: ignore[reportMissingModuleSource]


class SecureTransportError(RuntimeError):
    """Raised when the required tunnel or pinned PQC transport is unavailable."""


@dataclass(frozen=True)
class EncryptedRequest:
    kem_ciphertext: bytes
    body: bytes
    key: bytes
    aad: bytes


def require_wireguard_full_tunnel(interface: str | None = None) -> str:
    """Require an active WireGuard peer and IPv4/IPv6 default routes through it."""
    interface = (interface or os.environ.get("MK1_WIREGUARD_INTERFACE", "wg0")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
        raise SecureTransportError("MK1_WIREGUARD_INTERFACE is invalid")
    if platform.system() != "Linux":
        raise SecureTransportError(
            "Fail-closed WireGuard route verification currently supports Linux only"
        )

    try:
        peer = subprocess.run(
            ["wg", "show", interface, "allowed-ips"],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
        ipv4_route = subprocess.run(
            ["ip", "route", "get", "1.1.1.1"],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
        ipv6_route = subprocess.run(
            ["ip", "-6", "route", "get", "2606:4700:4700::1111"],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SecureTransportError(
            "Unable to verify an active WireGuard full-tunnel route"
        ) from exc

    allowed_ips = peer.stdout
    if "0.0.0.0/0" not in allowed_ips or "::/0" not in allowed_ips:
        raise SecureTransportError(
            f"WireGuard interface {interface} must allow IPv4 and IPv6 default routes"
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
            ["ip", "-o", "address", "show", "dev", interface],
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
    kem_ciphertext, shared_secret = encaps(public_key)
    aad = _request_aad(method, path, fingerprint, kem_ciphertext)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(aad).digest(),
        info=b"MK1-RSI-ML-KEM-768-AES-256-GCM-v1",
    ).derive(shared_secret)
    nonce = os.urandom(12)
    plaintext = json.dumps(
        payload, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return EncryptedRequest(
        kem_ciphertext=kem_ciphertext,
        body=nonce + AESGCM(key).encrypt(nonce, plaintext, aad),
        key=key,
        aad=aad,
    )


def encrypt_server_response(
    private_key: bytes,
    kem_ciphertext: bytes,
    plaintext: bytes,
    method: str,
    path: str,
    fingerprint: str,
) -> bytes:
    aad = _request_aad(method, path, fingerprint, kem_ciphertext)
    shared_secret = decaps(private_key, kem_ciphertext)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(aad).digest(),
        info=b"MK1-RSI-ML-KEM-768-AES-256-GCM-v1",
    ).derive(shared_secret)
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(
        nonce, plaintext, aad + b"\0response",
    )


def decrypt_server_response(encrypted_request: EncryptedRequest, body: bytes) -> bytes:
    if len(body) < 12 + 16:
        raise SecureTransportError("Encrypted server response is truncated")
    return AESGCM(encrypted_request.key).decrypt(
        body[:12], body[12:], encrypted_request.aad + b"\0response",
    )


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
    try:
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
        response.close()


def validate_public_key_pin(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()))
