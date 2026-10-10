"""SLIP-39 Shamir backup helpers; shares are returned for external custody."""

from __future__ import annotations

from shamir_mnemonic import combine_mnemonics, generate_mnemonics
from shamir_mnemonic.utils import MnemonicError

import mk1_memory_guard


class SecretBackupError(ValueError):
    """Raised when a Shamir backup request or recovery set is invalid."""


MIN_SECRET_BYTES = 16
MAX_SECRET_BYTES = 32
MAX_SHARES = 16
MAX_MNEMONIC_CHARS = 2048


def split_secret(
    secret: bytearray,
    *,
    threshold: int,
    share_count: int,
) -> tuple[str, ...]:
    """Split and destroy a mutable secret buffer into externally held shares."""
    if not isinstance(secret, bytearray):
        raise TypeError("Secret must be a mutable bytearray that can be destroyed")
    try:
        if len(secret) not in (MIN_SECRET_BYTES, MAX_SECRET_BYTES):
            raise SecretBackupError("SLIP-39 backup secret must be 16 or 32 bytes")
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, int)
            or isinstance(share_count, bool)
            or not isinstance(share_count, int)
            or not 2 <= threshold <= share_count <= MAX_SHARES
        ):
            raise SecretBackupError(
                f"Require 2 <= threshold <= share_count <= {MAX_SHARES}",
            )
        try:
            groups = generate_mnemonics(
                1,
                [(threshold, share_count)],
                bytes(secret),
            )
        except MnemonicError:
            raise SecretBackupError("Unable to create SLIP-39 shares") from None
        return tuple(groups[0])
    finally:
        mk1_memory_guard.wipe_buffer(secret)


def recover_secret(
    shares: tuple[str, ...] | list[str],
) -> bytearray:
    if not isinstance(shares, (tuple, list)):
        raise TypeError("Shares must be a tuple or list of mnemonic strings")
    if not 2 <= len(shares) <= MAX_SHARES:
        raise SecretBackupError(f"Provide 2 to {MAX_SHARES} shares")
    if any(
        not isinstance(share, str)
        or not share
        or len(share) > MAX_MNEMONIC_CHARS
        for share in shares
    ):
        raise SecretBackupError("A share is empty, invalid, or too long")
    if len(set(shares)) != len(shares):
        raise SecretBackupError("Duplicate shares are not accepted")
    try:
        recovered = bytearray(combine_mnemonics(shares))
    except MnemonicError:
        raise SecretBackupError(
            "Shares are insufficient, inconsistent, or failed integrity checks",
        ) from None
    try:
        mk1_memory_guard.lock_buffer(recovered)
    except OSError:
        mk1_memory_guard.wipe_buffer(recovered)
        raise
    return recovered
