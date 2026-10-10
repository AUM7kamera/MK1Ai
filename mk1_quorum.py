"""Strict multi-signer Ed25519 approval verification for sensitive operations."""

from __future__ import annotations

import base64
import binascii
import json
import os
import stat
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


MAX_APPROVAL_BUNDLE_BYTES = 32 * 1024
MAX_APPROVALS = 3
SIGNATURE_BYTES = 64
PUBLIC_KEY_BYTES = 32
MAX_CHALLENGE_BYTES = 4096


class QuorumError(RuntimeError):
    """Raised when trusted quorum approval cannot be established."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise QuorumError("Approval bundle contains a duplicate JSON key")
        result[key] = value
    return result


def _validate_signer_id(signer_id: object) -> str:
    if (
        not isinstance(signer_id, str)
        or not signer_id
        or len(signer_id) > 64
        or not signer_id.isascii()
        or not signer_id.replace("-", "").replace("_", "").isalnum()
    ):
        raise QuorumError("Quorum roster contains an invalid signer identity")
    return signer_id


def _parse_challenge(raw: bytes) -> tuple[dict[str, object], bytes]:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_CHALLENGE_BYTES:
        raise QuorumError("Release challenge is invalid or exceeds its size limit")
    try:
        document = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError, QuorumError) as exc:
        if isinstance(exc, QuorumError):
            raise
        raise QuorumError("Release challenge is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != {
        "version", "generation", "challenge", "message_base64",
    }:
        raise QuorumError("Release challenge does not match the closed schema")
    generation = document["generation"]
    challenge = document["challenge"]
    if (
        isinstance(document["version"], bool)
        or document["version"] != 1
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= 2**63 - 1
        or not isinstance(challenge, str)
        or len(challenge) != 64
        or any(character not in "0123456789abcdef" for character in challenge)
    ):
        raise QuorumError("Release challenge fields are invalid")
    message = (
        f"MK1AI-QUARANTINE-RELEASE-v1\n{generation}\n{challenge}\n"
    ).encode("ascii")
    try:
        provided_message = base64.b64decode(
            document["message_base64"],
            validate=True,
        )
    except (binascii.Error, TypeError, ValueError) as exc:
        raise QuorumError("Release challenge message is invalid base64") from exc
    if provided_message != message:
        raise QuorumError("Release challenge message does not match its fields")
    if base64.b64encode(provided_message).decode("ascii") != document["message_base64"]:
        raise QuorumError("Release challenge message encoding is not canonical")
    return document, message


def _read_bounded_file(
    path: Path,
    *,
    maximum_bytes: int,
    require_private_owner: bool = False,
) -> bytes:
    try:
        file_descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise QuorumError("Input file could not be opened safely") from exc
    try:
        file_stat = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_size <= 0
            or file_stat.st_size > maximum_bytes
        ):
            raise QuorumError("Input file is invalid or exceeds its size limit")
        if require_private_owner and (
            file_stat.st_uid != os.geteuid() or file_stat.st_mode & 0o077
        ):
            raise QuorumError("Private signing key ownership or mode is invalid")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(file_descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        contents = b"".join(chunks)
        if len(contents) > maximum_bytes:
            raise QuorumError("Input file exceeds its size limit")
        return contents
    finally:
        os.close(file_descriptor)


def create_approval_record(
    signer_id: str,
    challenge_document: bytes,
    private_key_pem: bytes,
) -> bytes:
    """Sign only a well-formed, fresh release challenge using an Ed25519 key."""
    signer_id = _validate_signer_id(signer_id)
    _, message = _parse_challenge(challenge_document)
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (ValueError, TypeError) as exc:
        raise QuorumError("Approver private key is not valid unencrypted PEM") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise QuorumError("Approver private key must use Ed25519")
    signature = private_key.sign(message)
    record = {
        "version": 1,
        "signer_id": signer_id,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")


def create_approval_record_from_files(
    signer_id: str,
    challenge_path: Path,
    private_key_path: Path,
) -> bytes:
    challenge = _read_bounded_file(
        challenge_path,
        maximum_bytes=MAX_CHALLENGE_BYTES,
    )
    private_key = _read_bounded_file(
        private_key_path,
        maximum_bytes=16_384,
        require_private_owner=True,
    )
    return create_approval_record(signer_id, challenge, private_key)


def combine_approval_records(records: list[bytes]) -> bytes:
    """Combine independent signer records; cryptographic checks occur at target."""
    if not 2 <= len(records) <= MAX_APPROVALS:
        raise QuorumError("At least two and at most three approval records are required")
    approvals: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in records:
        if not isinstance(raw, bytes) or len(raw) > 2048:
            raise QuorumError("Approval record is invalid or exceeds its size limit")
        try:
            record = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, UnicodeDecodeError, QuorumError) as exc:
            if isinstance(exc, QuorumError):
                raise
            raise QuorumError("Approval record is not valid UTF-8 JSON") from exc
        if not isinstance(record, dict) or set(record) != {
            "version", "signer_id", "signature",
        }:
            raise QuorumError("Approval record does not match the closed schema")
        if isinstance(record["version"], bool) or record["version"] != 1:
            raise QuorumError("Approval record version is unsupported")
        signer_id = _validate_signer_id(record["signer_id"])
        if signer_id in seen:
            raise QuorumError("Approval records repeat a signer")
        if not isinstance(record["signature"], str):
            raise QuorumError("Approval record signature must be base64 text")
        try:
            signature = base64.b64decode(record["signature"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise QuorumError("Approval record signature is not valid base64") from exc
        if len(signature) != SIGNATURE_BYTES:
            raise QuorumError("Approval signature has an invalid length")
        seen.add(signer_id)
        approvals.append({
            "signer_id": signer_id,
            "signature": record["signature"],
        })
    return json.dumps(
        {"version": 1, "approvals": approvals},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _read_trusted_key(
    path: Path,
    *,
    expected_uid: int,
    strict_ancestors: bool,
) -> Ed25519PublicKey:
    try:
        file_descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise QuorumError("A trusted quorum public key could not be opened") from exc
    try:
        key_stat = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(key_stat.st_mode)
            or key_stat.st_uid != expected_uid
            or key_stat.st_mode & 0o022
            or key_stat.st_size <= 0
            or key_stat.st_size > 16_384
        ):
            raise QuorumError("Quorum public key ownership, mode, or size is invalid")
        if strict_ancestors:
            for parent in path.parents:
                parent_stat = parent.stat()
                if parent_stat.st_uid != expected_uid or parent_stat.st_mode & 0o022:
                    raise QuorumError("Quorum public key has an untrusted parent directory")
        chunks: list[bytes] = []
        remaining = 16_385
        while remaining:
            chunk = os.read(file_descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded_key = b"".join(chunks)
        if len(encoded_key) > 16_384:
            raise QuorumError("Quorum public key exceeds its size limit")
    finally:
        os.close(file_descriptor)

    try:
        public_key = serialization.load_pem_public_key(encoded_key)
    except (ValueError, TypeError) as exc:
        raise QuorumError("Quorum public key is not valid PEM") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise QuorumError("Quorum public key must use Ed25519")
    return public_key


def load_trusted_quorum_keys(
    key_paths: Mapping[str, Path],
    *,
    expected_uid: int,
    strict_ancestors: bool = True,
) -> dict[str, Ed25519PublicKey]:
    """Load a closed roster of two or three independently enrolled signers."""
    if not 2 <= len(key_paths) <= MAX_APPROVALS:
        raise QuorumError("Quorum roster must contain two or three signers")
    for signer_id in key_paths:
        _validate_signer_id(signer_id)

    loaded = {
        signer_id: _read_trusted_key(
            Path(key_path),
            expected_uid=expected_uid,
            strict_ancestors=strict_ancestors,
        )
        for signer_id, key_path in key_paths.items()
    }
    fingerprints = {
        key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        for key in loaded.values()
    }
    if len(fingerprints) != len(loaded):
        raise QuorumError("Quorum public keys must be distinct")
    return loaded


def verify_approval_bundle(
    message: bytes,
    bundle: bytes,
    trusted_keys: Mapping[str, Ed25519PublicKey],
    *,
    threshold: int = 2,
) -> tuple[str, ...]:
    """Require distinct, known signer IDs and valid signatures over one message."""
    if not isinstance(message, bytes) or not message:
        raise QuorumError("Quorum message must be non-empty bytes")
    if not isinstance(bundle, bytes) or len(bundle) > MAX_APPROVAL_BUNDLE_BYTES:
        raise QuorumError("Approval bundle is invalid or exceeds its size limit")
    if (
        not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or threshold < 2
        or threshold > len(trusted_keys)
    ):
        raise QuorumError("Quorum threshold must be at least two and fit the roster")
    if not 2 <= len(trusted_keys) <= MAX_APPROVALS:
        raise QuorumError("Quorum roster must contain two or three signers")
    encoded_keys: set[bytes] = set()
    for signer_id, key in trusted_keys.items():
        _validate_signer_id(signer_id)
        if not isinstance(key, Ed25519PublicKey):
            raise QuorumError("Quorum roster contains a non-Ed25519 key")
        encoded_keys.add(key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ))
    if len(encoded_keys) != len(trusted_keys):
        raise QuorumError("Quorum public keys must be distinct")

    try:
        document = json.loads(
            bundle,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, QuorumError) as exc:
        if isinstance(exc, QuorumError):
            raise
        raise QuorumError("Approval bundle is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != {"version", "approvals"}:
        raise QuorumError("Approval bundle does not match the closed schema")
    if (
        isinstance(document["version"], bool)
        or document["version"] != 1
        or not isinstance(document["approvals"], list)
    ):
        raise QuorumError("Approval bundle schema version or approvals field is invalid")
    if not threshold <= len(document["approvals"]) <= len(trusted_keys):
        raise QuorumError("Approval bundle quorum count is invalid")

    accepted: list[str] = []
    seen: set[str] = set()
    for approval in document["approvals"]:
        if (
            not isinstance(approval, dict)
            or set(approval) != {"signer_id", "signature"}
            or not isinstance(approval["signer_id"], str)
            or not isinstance(approval["signature"], str)
        ):
            raise QuorumError("Approval entry does not match the closed schema")
        signer_id = approval["signer_id"]
        if signer_id in seen:
            raise QuorumError("Approval bundle repeats a signer")
        key = trusted_keys.get(signer_id)
        if key is None:
            raise QuorumError("Approval bundle contains an unknown signer")
        try:
            signature = base64.b64decode(approval["signature"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise QuorumError("Approval signature is not valid base64") from exc
        if base64.b64encode(signature).decode("ascii") != approval["signature"]:
            raise QuorumError("Approval signature encoding is not canonical")
        if len(signature) != SIGNATURE_BYTES:
            raise QuorumError("Approval signature has an invalid length")
        try:
            key.verify(signature, message)
        except InvalidSignature as exc:
            raise QuorumError("An approval signature is invalid") from exc
        seen.add(signer_id)
        accepted.append(signer_id)
    return tuple(accepted)
