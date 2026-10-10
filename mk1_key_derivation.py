"""User-rooted key derivation with optional, non-authoritative factors."""

from __future__ import annotations

import hashlib
import os
import struct
import warnings
from dataclasses import dataclass, field

from argon2 import Type
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import mk1_memory_guard


class KeyDerivationError(RuntimeError):
    """Raised when key derivation cannot safely meet its minimum policy."""


MIN_PASSPHRASE_BYTES = 20
SALT_BYTES = 16
KEY_BYTES = 32
MIN_MEMORY_KIB = 64 * 1024
MAX_MEMORY_KIB = 256 * 1024
MIN_TIME_COST = 3
MAX_TIME_COST = 6
PARALLELISM = 1
LOW_MEMORY_WARNING_BYTES = 1024 * 1024 * 1024
MIN_SAFE_AVAILABLE_BYTES = 2 * MIN_MEMORY_KIB * 1024
MIN_OPTIONAL_FACTOR_BYTES = 16
MAX_FACTOR_BYTES = 4096


@dataclass
class DerivedKey:
    salt: bytes
    key: bytearray = field(repr=False)
    memory_kib: int
    time_cost: int
    low_memory: bool

    def destroy(self) -> None:
        mk1_memory_guard.wipe_buffer(self.key)


def _available_memory_bytes() -> int:
    available_kib: int | None = None
    with open("/proc/meminfo", "r", encoding="ascii") as meminfo:
        for line in meminfo:
            if line.startswith("MemAvailable:"):
                value = line.split()
                if len(value) != 3 or value[2] != "kB":
                    break
                available_kib = int(value[1])
                break
    if available_kib is None or available_kib <= 0:
        raise KeyDerivationError("Cannot determine available memory for Argon2id")
    return available_kib * 1024


def _parameters_for_memory(available_bytes: int) -> tuple[int, int, bool]:
    if isinstance(available_bytes, bool) or not isinstance(available_bytes, int):
        raise TypeError("Available memory must be an integer byte count")
    if available_bytes < MIN_SAFE_AVAILABLE_BYTES:
        raise KeyDerivationError(
            "Insufficient available memory for the minimum Argon2id policy",
        )
    memory_kib = min(
        MAX_MEMORY_KIB,
        max(MIN_MEMORY_KIB, available_bytes // (8 * 1024)),
    )
    memory_steps = (memory_kib - MIN_MEMORY_KIB) // (64 * 1024)
    time_cost = min(MAX_TIME_COST, MIN_TIME_COST + memory_steps)
    return (
        memory_kib,
        time_cost,
        available_bytes < LOW_MEMORY_WARNING_BYTES,
    )


def _validated_factor(value: bytes | bytearray | None, name: str) -> bytes:
    if value is None:
        return b""
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes, bytearray, or None")
    if not MIN_OPTIONAL_FACTOR_BYTES <= len(value) <= MAX_FACTOR_BYTES:
        raise ValueError(
            f"{name} must contain {MIN_OPTIONAL_FACTOR_BYTES} "
            f"to {MAX_FACTOR_BYTES} bytes",
        )
    return bytes(value)


def derive_user_root_key(
    passphrase: str,
    *,
    hardware_factor: bytes | bytearray | None = None,
    fido2_factor: bytes | bytearray | None = None,
    salt: bytes | None = None,
) -> DerivedKey:
    """Derive a user-rooted key; optional factors can never replace the user factor."""
    if not isinstance(passphrase, str):
        raise TypeError("Passphrase must be text")
    password = passphrase.encode("utf-8")
    if len(password) < MIN_PASSPHRASE_BYTES:
        raise ValueError(
            f"Passphrase must contain at least {MIN_PASSPHRASE_BYTES} UTF-8 bytes",
        )
    if len(password) > MAX_FACTOR_BYTES:
        raise ValueError("Passphrase exceeds the maximum supported length")
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    elif not isinstance(salt, bytes) or len(salt) != SALT_BYTES:
        raise ValueError(f"Salt must be exactly {SALT_BYTES} bytes")

    hardware = _validated_factor(hardware_factor, "hardware_factor")
    authenticator = _validated_factor(fido2_factor, "fido2_factor")
    memory_kib, time_cost, low_memory = _parameters_for_memory(
        _available_memory_bytes(),
    )
    if low_memory:
        warnings.warn(
            "Low available memory: Argon2id parameters are constrained by the low-memory policy",
            RuntimeWarning,
            stacklevel=2,
        )

    password_buffer = bytearray(password)
    user_key = bytearray()
    try:
        user_key.extend(hash_secret_raw(
            secret=bytes(password_buffer),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_kib,
            parallelism=PARALLELISM,
            hash_len=KEY_BYTES,
            type=Type.ID,
        ))
        mk1_memory_guard.lock_buffer(user_key)
        factor_material = (
            b"MK1-optional-factors-v1\0"
            + struct.pack(">I", len(hardware))
            + hardware
            + struct.pack(">I", len(authenticator))
            + authenticator
        )
        factor_salt = hashlib.sha384(factor_material).digest()
        derived = HKDF(
            algorithm=hashes.SHA384(),
            length=KEY_BYTES,
            salt=factor_salt,
            info=b"MK1-user-root-key-v1",
        ).derive(user_key)
        result_key = bytearray(derived)
        del derived
        try:
            mk1_memory_guard.lock_buffer(result_key)
        except OSError:
            mk1_memory_guard.wipe_buffer(result_key)
            raise
        result = DerivedKey(
            salt=salt,
            key=result_key,
            memory_kib=memory_kib,
            time_cost=time_cost,
            low_memory=low_memory,
        )
        return result
    finally:
        mk1_memory_guard.wipe_buffer(password_buffer)
        mk1_memory_guard.wipe_buffer(user_key)
