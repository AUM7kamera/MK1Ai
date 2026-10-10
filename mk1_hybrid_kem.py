"""Hybrid ML-KEM-1024 and X25519 agreement with WireGuard-PSK binding."""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pqcrypto.kem.ml_kem_1024 import decaps, encaps

import mk1_memory_guard


class HybridKEMError(ValueError):
    """Raised when hybrid key material or protocol context is invalid."""


SUITE_ID = b"MK1-HYBRID-ML-KEM-1024-X25519-WG-PSK-v1"
ML_KEM_1024_PUBLIC_KEY_BYTES = 1568
ML_KEM_1024_SECRET_KEY_BYTES = 3168
ML_KEM_1024_CIPHERTEXT_BYTES = 1568
SHARED_SECRET_BYTES = 32
WIREGUARD_PSK_BYTES = 32
MAX_TRANSCRIPT_BYTES = 64 * 1024


@dataclass
class HybridEncapsulation:
    kem_ciphertext: bytes
    client_x25519_public_key: bytes
    shared_secret: bytearray = field(repr=False)

    def destroy(self) -> None:
        mk1_memory_guard.wipe_buffer(self.shared_secret)


def generate_x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw,
    )


def _validate_transcript(transcript: bytes) -> None:
    if not isinstance(transcript, bytes):
        raise TypeError("Transcript context must be bytes")
    if not transcript or len(transcript) > MAX_TRANSCRIPT_BYTES:
        raise HybridKEMError(
            f"Transcript context must contain 1 to {MAX_TRANSCRIPT_BYTES} bytes",
        )


def _validate_wireguard_psk(psk: bytes | bytearray) -> None:
    if not isinstance(psk, (bytes, bytearray)):
        raise TypeError("WireGuard preshared key must be bytes")
    if len(psk) != WIREGUARD_PSK_BYTES:
        raise HybridKEMError("A 32-byte WireGuard preshared key is required")


def _validate_public_key(key: bytes, size: int, name: str) -> None:
    if not isinstance(key, bytes) or len(key) != size:
        raise HybridKEMError(f"{name} must contain exactly {size} bytes")


def _combine(
    mlkem_secret: bytearray,
    x25519_secret: bytearray,
    wireguard_psk: bytes | bytearray,
    transcript: bytes,
    *,
    kem_ciphertext: bytes,
    client_public_key: bytes,
    server_public_key: bytes,
) -> bytearray:
    _validate_transcript(transcript)
    _validate_wireguard_psk(wireguard_psk)
    if len(mlkem_secret) != SHARED_SECRET_BYTES:
        raise HybridKEMError("ML-KEM-1024 returned an invalid shared-secret length")
    if len(x25519_secret) != SHARED_SECRET_BYTES:
        raise HybridKEMError("X25519 returned an invalid shared-secret length")

    transcript_hash = hashlib.sha384(b"".join((
        SUITE_ID,
        struct.pack(">I", len(transcript)),
        transcript,
        struct.pack(">I", len(kem_ciphertext)),
        kem_ciphertext,
        client_public_key,
        server_public_key,
    ))).digest()
    material = bytearray(
        mlkem_secret + x25519_secret + bytearray(wireguard_psk),
    )
    try:
        derived = HKDF(
            algorithm=hashes.SHA384(),
            length=SHARED_SECRET_BYTES,
            salt=transcript_hash,
            info=SUITE_ID,
        ).derive(material)
        result = bytearray(derived)
        del derived
        try:
            mk1_memory_guard.lock_buffer(result)
        except OSError:
            mk1_memory_guard.wipe_buffer(result)
            raise
        return result
    finally:
        mk1_memory_guard.wipe_buffer(material)


def encapsulate(
    kem_public_key: bytes,
    server_x25519_public_key: bytes,
    wireguard_psk: bytes | bytearray,
    transcript: bytes,
) -> HybridEncapsulation:
    _validate_public_key(
        kem_public_key, ML_KEM_1024_PUBLIC_KEY_BYTES, "ML-KEM-1024 public key",
    )
    _validate_public_key(server_x25519_public_key, 32, "X25519 public key")
    _validate_transcript(transcript)
    _validate_wireguard_psk(wireguard_psk)
    try:
        server_public = X25519PublicKey.from_public_bytes(server_x25519_public_key)
        kem_ciphertext, kem_secret_bytes = encaps(kem_public_key)
        kem_secret = bytearray(kem_secret_bytes)
        del kem_secret_bytes
        ephemeral_private = X25519PrivateKey.generate()
        x25519_secret = bytearray(ephemeral_private.exchange(server_public))
        client_public = ephemeral_private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw,
        )
        try:
            combined = _combine(
                kem_secret,
                x25519_secret,
                wireguard_psk,
                transcript,
                kem_ciphertext=kem_ciphertext,
                client_public_key=client_public,
                server_public_key=server_x25519_public_key,
            )
            return HybridEncapsulation(
                kem_ciphertext=kem_ciphertext,
                client_x25519_public_key=client_public,
                shared_secret=combined,
            )
        finally:
            mk1_memory_guard.wipe_buffer(kem_secret)
            mk1_memory_guard.wipe_buffer(x25519_secret)
    except (ValueError, TypeError) as exc:
        if isinstance(exc, HybridKEMError):
            raise
        raise HybridKEMError("Hybrid encapsulation failed") from exc


def decapsulate(
    kem_secret_key: bytes,
    server_x25519_private_key: X25519PrivateKey,
    kem_ciphertext: bytes,
    client_x25519_public_key: bytes,
    wireguard_psk: bytes | bytearray,
    transcript: bytes,
) -> bytearray:
    _validate_public_key(
        kem_secret_key, ML_KEM_1024_SECRET_KEY_BYTES, "ML-KEM-1024 secret key",
    )
    _validate_public_key(
        kem_ciphertext, ML_KEM_1024_CIPHERTEXT_BYTES, "ML-KEM-1024 ciphertext",
    )
    _validate_public_key(client_x25519_public_key, 32, "client X25519 public key")
    if not isinstance(server_x25519_private_key, X25519PrivateKey):
        raise TypeError("Server X25519 private key must be an X25519PrivateKey")
    _validate_transcript(transcript)
    _validate_wireguard_psk(wireguard_psk)
    server_public = server_x25519_private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw,
    )
    try:
        client_public = X25519PublicKey.from_public_bytes(client_x25519_public_key)
        kem_secret = bytearray(decaps(kem_secret_key, kem_ciphertext))
        x25519_secret = bytearray(server_x25519_private_key.exchange(client_public))
        try:
            return _combine(
                kem_secret,
                x25519_secret,
                wireguard_psk,
                transcript,
                kem_ciphertext=kem_ciphertext,
                client_public_key=client_x25519_public_key,
                server_public_key=server_public,
            )
        finally:
            mk1_memory_guard.wipe_buffer(kem_secret)
            mk1_memory_guard.wipe_buffer(x25519_secret)
    except (ValueError, TypeError) as exc:
        if isinstance(exc, HybridKEMError):
            raise
        raise HybridKEMError("Hybrid decapsulation failed") from exc


def verify_hybrid_key_fingerprint(
    kem_public_key: bytes,
    x25519_public_key: bytes,
    expected_fingerprint: str,
) -> str:
    _validate_public_key(
        kem_public_key, ML_KEM_1024_PUBLIC_KEY_BYTES, "ML-KEM-1024 public key",
    )
    _validate_public_key(x25519_public_key, 32, "X25519 public key")
    if not isinstance(expected_fingerprint, str) or not hmac.compare_digest(
        hashlib.sha384(SUITE_ID + kem_public_key + x25519_public_key).hexdigest(),
        expected_fingerprint.lower(),
    ):
        raise HybridKEMError("Hybrid key fingerprint does not match")
    return hashlib.sha384(SUITE_ID + kem_public_key + x25519_public_key).hexdigest()
