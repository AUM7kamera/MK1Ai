"""Bounded per-session message-key ratchet with strict replay rejection."""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import threading
import time
from collections.abc import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import mk1_memory_guard


class SessionRatchetError(RuntimeError):
    """Raised when a ratchet session is invalid, expired, or exhausted."""


SESSION_KEY_BYTES = 32
NONCE_BYTES = 12
SEQUENCE_BYTES = 8
MAX_CONTEXT_BYTES = 4096
MAX_MESSAGE_BYTES = 2 * 1024 * 1024
MAX_SESSION_LIFETIME_SECONDS = 60 * 60
MAX_SESSION_MESSAGES = 1 << 20
PACKET_OVERHEAD = SEQUENCE_BYTES + NONCE_BYTES + 16


def _message_key(chain_key: bytearray, sequence: int) -> bytearray:
    return bytearray(hmac.digest(
        chain_key,
        b"MK1-message-key-v1\0" + sequence.to_bytes(SEQUENCE_BYTES, "big"),
        "sha384",
    )[:SESSION_KEY_BYTES])


def _next_chain_key(chain_key: bytearray, sequence: int) -> bytearray:
    return bytearray(hmac.digest(
        chain_key,
        b"MK1-next-chain-v1\0" + sequence.to_bytes(SEQUENCE_BYTES, "big"),
        "sha384",
    )[:SESSION_KEY_BYTES])


class SessionRatchet:
    """One-direction-at-a-time AEAD ratchet; packets must arrive in sequence."""

    def __init__(
        self,
        session_secret: bytearray,
        *,
        context: bytes,
        role: str,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(session_secret, bytearray):
            raise TypeError("Session secret must be a mutable bytearray")
        if len(session_secret) < SESSION_KEY_BYTES:
            mk1_memory_guard.wipe_buffer(session_secret)
            raise SessionRatchetError("Session secret is too short")
        if not isinstance(context, bytes) or not 1 <= len(context) <= MAX_CONTEXT_BYTES:
            mk1_memory_guard.wipe_buffer(session_secret)
            raise SessionRatchetError("Session context has an invalid size")
        if role not in ("client", "server"):
            mk1_memory_guard.wipe_buffer(session_secret)
            raise SessionRatchetError("Session role must be client or server")

        self._context = b"MK1-ratchet-v1\0" + context
        self._clock = clock
        self._created_at = clock()
        self._send_sequence = 0
        self._receive_sequence = 0
        self._destroyed = False
        self._lock = threading.RLock()
        try:
            self._send_chain = bytearray(HKDF(
                algorithm=hashes.SHA384(),
                length=SESSION_KEY_BYTES,
                salt=hashlib.sha384(self._context).digest(),
                info=b"MK1-ratchet-client-to-server-v1"
                if role == "client"
                else b"MK1-ratchet-server-to-client-v1",
            ).derive(session_secret))
            self._receive_chain = bytearray(HKDF(
                algorithm=hashes.SHA384(),
                length=SESSION_KEY_BYTES,
                salt=hashlib.sha384(self._context).digest(),
                info=b"MK1-ratchet-server-to-client-v1"
                if role == "client"
                else b"MK1-ratchet-client-to-server-v1",
            ).derive(session_secret))
            mk1_memory_guard.lock_buffer(self._send_chain)
            mk1_memory_guard.lock_buffer(self._receive_chain)
        except Exception:
            if hasattr(self, "_send_chain"):
                mk1_memory_guard.wipe_buffer(self._send_chain)
            if hasattr(self, "_receive_chain"):
                mk1_memory_guard.wipe_buffer(self._receive_chain)
            raise
        finally:
            mk1_memory_guard.wipe_buffer(session_secret)

    def _check_live(self, *, sending: bool) -> None:
        if self._destroyed:
            raise SessionRatchetError("Session ratchet was destroyed")
        if self._clock() - self._created_at >= MAX_SESSION_LIFETIME_SECONDS:
            self._destroy_locked()
            raise SessionRatchetError("Session ratchet lifetime expired")
        sequence = self._send_sequence if sending else self._receive_sequence
        if sequence >= MAX_SESSION_MESSAGES:
            self._destroy_locked()
            raise SessionRatchetError("Session ratchet message limit exhausted")

    def encrypt(self, plaintext: bytes, *, aad: bytes = b"") -> bytes:
        if not isinstance(plaintext, bytes) or not isinstance(aad, bytes):
            raise TypeError("Plaintext and associated data must be bytes")
        if len(plaintext) > MAX_MESSAGE_BYTES or len(aad) > MAX_CONTEXT_BYTES:
            raise SessionRatchetError("Plaintext or associated data exceeds its size limit")
        with self._lock:
            self._check_live(sending=True)
            sequence = self._send_sequence
            key = _message_key(self._send_chain, sequence)
            next_chain = _next_chain_key(self._send_chain, sequence)
            nonce = os.urandom(NONCE_BYTES)
            packet_aad = self._context + struct.pack(">Q", sequence) + aad
            try:
                ciphertext = AESGCM(key).encrypt(nonce, plaintext, packet_aad)
            except Exception:
                mk1_memory_guard.wipe_buffer(next_chain)
                raise
            finally:
                mk1_memory_guard.wipe_buffer(key)
            self._send_chain[:] = next_chain
            mk1_memory_guard.wipe_buffer(next_chain)
            self._send_sequence += 1
            return struct.pack(">Q", sequence) + nonce + ciphertext

    def decrypt(self, packet: bytes, *, aad: bytes = b"") -> bytes:
        if not isinstance(packet, bytes) or not isinstance(aad, bytes):
            raise TypeError("Packet and associated data must be bytes")
        if len(aad) > MAX_CONTEXT_BYTES or len(packet) < PACKET_OVERHEAD:
            raise SessionRatchetError("Encrypted packet is truncated")
        if len(packet) > MAX_MESSAGE_BYTES + PACKET_OVERHEAD:
            raise SessionRatchetError("Encrypted packet exceeds its size limit")
        sequence = struct.unpack(">Q", packet[:SEQUENCE_BYTES])[0]
        with self._lock:
            self._check_live(sending=False)
            if sequence != self._receive_sequence:
                raise SessionRatchetError("Replayed or out-of-order packet rejected")
            key = _message_key(self._receive_chain, sequence)
            next_chain = _next_chain_key(self._receive_chain, sequence)
            nonce = packet[SEQUENCE_BYTES:PACKET_OVERHEAD - 16]
            ciphertext = packet[PACKET_OVERHEAD - 16:]
            packet_aad = self._context + struct.pack(">Q", sequence) + aad
            try:
                plaintext = AESGCM(key).decrypt(nonce, ciphertext, packet_aad)
            except Exception:
                mk1_memory_guard.wipe_buffer(next_chain)
                raise
            finally:
                mk1_memory_guard.wipe_buffer(key)
            self._receive_chain[:] = next_chain
            mk1_memory_guard.wipe_buffer(next_chain)
            self._receive_sequence += 1
            return plaintext

    def _destroy_locked(self) -> None:
        if self._destroyed:
            return
        mk1_memory_guard.wipe_buffer(self._send_chain)
        mk1_memory_guard.wipe_buffer(self._receive_chain)
        self._destroyed = True

    def destroy(self) -> None:
        with self._lock:
            self._destroy_locked()

    @property
    def destroyed(self) -> bool:
        with self._lock:
            return self._destroyed

    @property
    def sequence_numbers(self) -> tuple[int, int]:
        with self._lock:
            return self._send_sequence, self._receive_sequence
