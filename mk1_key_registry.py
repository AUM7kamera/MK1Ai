"""Purpose/device key separation and signed revocation-manifest validation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import mk1_memory_guard


class KeyRegistryError(ValueError):
    """Raised when key scope or a revocation manifest is invalid."""


MAX_MANIFEST_BYTES = 64 * 1024
MAX_REVOKED_DEVICES = 4096
DEVICE_ID_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
ALLOWED_PURPOSES = frozenset({
    "application-encryption",
    "application-signing",
    "audit-signing",
    "configuration-signing",
    "update-verification",
    "wireguard-binding",
})


@dataclass(frozen=True)
class RevocationManifest:
    generation: int
    revoked_device_ids: frozenset[str]

    def is_revoked(self, device_id: str) -> bool:
        return device_id in self.revoked_device_ids


def derive_device_purpose_key(
    root_key: bytearray,
    *,
    device_id: str,
    purpose: str,
    generation: int,
) -> bytearray:
    if not isinstance(root_key, bytearray) or len(root_key) < 32:
        raise TypeError("Root key must be a mutable buffer of at least 32 bytes")
    if not isinstance(device_id, str) or DEVICE_ID_PATTERN.fullmatch(device_id) is None:
        raise KeyRegistryError("Device ID must be a 32-byte lowercase hex identifier")
    if purpose not in ALLOWED_PURPOSES:
        raise KeyRegistryError("Unknown key purpose")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        raise KeyRegistryError("Key generation must be a non-negative integer")

    salt = hashlib.sha384(
        bytes.fromhex(device_id) + generation.to_bytes(8, "big"),
    ).digest()
    derived = HKDF(
        algorithm=hashes.SHA384(),
        length=32,
        salt=salt,
        info=b"MK1-device-purpose-key-v1\0" + purpose.encode("ascii"),
    ).derive(root_key)
    key = bytearray(derived)
    del derived
    try:
        mk1_memory_guard.lock_buffer(key)
    except OSError:
        mk1_memory_guard.wipe_buffer(key)
        raise
    return key


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise KeyRegistryError("Duplicate manifest fields are rejected")
        result[key] = value
    return result


def verify_revocation_manifest(
    payload: bytes,
    signature: bytes,
    authority_public_key: bytes,
    *,
    minimum_generation: int,
) -> RevocationManifest:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_MANIFEST_BYTES:
        raise KeyRegistryError("Revocation manifest exceeds its size bounds")
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise KeyRegistryError("Ed25519 manifest signature must be 64 bytes")
    if not isinstance(authority_public_key, bytes) or len(authority_public_key) != 32:
        raise KeyRegistryError("Ed25519 authority key must be 32 bytes")
    if (
        isinstance(minimum_generation, bool)
        or not isinstance(minimum_generation, int)
        or minimum_generation < 0
    ):
        raise KeyRegistryError("Minimum manifest generation must be non-negative")
    try:
        Ed25519PublicKey.from_public_bytes(authority_public_key).verify(
            signature, payload,
        )
    except (InvalidSignature, ValueError) as exc:
        raise KeyRegistryError("Revocation manifest signature verification failed") from exc

    try:
        document = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                KeyRegistryError(f"Invalid JSON number: {value}"),
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KeyRegistryError("Revocation manifest is not valid JSON") from exc
    if not isinstance(document, dict) or set(document) != {
        "version", "generation", "revoked_device_ids",
    }:
        raise KeyRegistryError("Revocation manifest schema is not exact")
    generation = document["generation"]
    revoked = document["revoked_device_ids"]
    if document["version"] != 1 or type(generation) is not int or generation < 0:
        raise KeyRegistryError("Revocation manifest version or generation is invalid")
    if generation < minimum_generation:
        raise KeyRegistryError("Revocation manifest rollback rejected")
    if (
        not isinstance(revoked, list)
        or len(revoked) > MAX_REVOKED_DEVICES
        or any(
            not isinstance(device_id, str)
            or DEVICE_ID_PATTERN.fullmatch(device_id) is None
            for device_id in revoked
        )
        or len(set(revoked)) != len(revoked)
    ):
        raise KeyRegistryError("Revoked device identifiers are invalid")
    return RevocationManifest(generation, frozenset(revoked))
