"""Independent, nonce-bound measurement helpers for a read-only target image."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import stat
from pathlib import Path, PurePosixPath
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


MAX_MANIFEST_BYTES = 128 * 1024
MAX_SIGNATURE_BYTES = 64
MAX_MANIFEST_FILES = 512
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MEASUREMENT_DOMAIN = b"MK1AI-EXTERNAL-MEASUREMENT-v1\n"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class ExternalVerificationError(RuntimeError):
    """Raised when an external measurement cannot be safely established."""


def _canonical_json(document: object) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ExternalVerificationError("Document contains a duplicate JSON key")
        document[key] = value
    return document


def _parse_json(raw: bytes, maximum_bytes: int, name: str) -> dict[str, object]:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= maximum_bytes:
        raise ExternalVerificationError(f"{name} is empty or exceeds its size limit")
    try:
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError, ExternalVerificationError) as exc:
        if isinstance(exc, ExternalVerificationError):
            raise
        raise ExternalVerificationError(f"{name} is not valid UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise ExternalVerificationError(f"{name} must be a JSON object")
    return parsed


def _validate_relative_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 512
        or not value.isascii()
        or "\\" in value
    ):
        raise ExternalVerificationError("Manifest contains an invalid file path")
    parsed = PurePosixPath(value)
    if (
        parsed.is_absolute()
        or parsed.as_posix() != value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ExternalVerificationError("Manifest paths must be normalized and relative")
    return value


def _manifest_files(document: Mapping[str, object]) -> dict[str, str]:
    if set(document) != {"version", "build_id", "files"}:
        raise ExternalVerificationError("Build manifest does not match its closed schema")
    if (
        isinstance(document["version"], bool)
        or document["version"] != 1
        or not isinstance(document["build_id"], str)
        or not _ID_RE.fullmatch(document["build_id"])
        or not isinstance(document["files"], list)
        or not 1 <= len(document["files"]) <= MAX_MANIFEST_FILES
    ):
        raise ExternalVerificationError("Build manifest fields are invalid")

    files: dict[str, str] = {}
    for entry in document["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise ExternalVerificationError("Manifest file entry does not match its schema")
        path = _validate_relative_path(entry["path"])
        digest = entry["sha256"]
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise ExternalVerificationError("Manifest contains an invalid SHA-256 digest")
        if path in files:
            raise ExternalVerificationError("Build manifest repeats a file path")
        files[path] = digest
    if list(files) != sorted(files):
        raise ExternalVerificationError("Build manifest file entries must be sorted")
    return files


def verify_signed_build_manifest(
    manifest_bytes: bytes,
    signature: bytes,
    trusted_builder_key: Ed25519PublicKey,
) -> tuple[str, dict[str, str]]:
    document = _parse_json(manifest_bytes, MAX_MANIFEST_BYTES, "Build manifest")
    if _canonical_json(document) != manifest_bytes:
        raise ExternalVerificationError("Build manifest encoding is not canonical")
    files = _manifest_files(document)
    if len(signature) != MAX_SIGNATURE_BYTES:
        raise ExternalVerificationError("Build manifest signature has an invalid length")
    if not isinstance(trusted_builder_key, Ed25519PublicKey):
        raise ExternalVerificationError("Trusted build key must use Ed25519")
    try:
        trusted_builder_key.verify(signature, manifest_bytes)
    except InvalidSignature as exc:
        raise ExternalVerificationError("Build manifest signature is invalid") from exc
    return str(document["build_id"]), files


def create_measurement_challenge(target_id: str) -> bytes:
    if not isinstance(target_id, str) or not _ID_RE.fullmatch(target_id):
        raise ExternalVerificationError("Target identity is invalid")
    return _canonical_json({
        "version": 1,
        "target_id": target_id,
        "nonce": secrets.token_hex(32),
    })


def _parse_challenge(challenge_bytes: bytes) -> tuple[str, str]:
    document = _parse_json(challenge_bytes, 2048, "Measurement challenge")
    if (
        set(document) != {"version", "target_id", "nonce"}
        or isinstance(document["version"], bool)
        or document["version"] != 1
        or not isinstance(document["target_id"], str)
        or not _ID_RE.fullmatch(document["target_id"])
        or not isinstance(document["nonce"], str)
        or not _SHA256_RE.fullmatch(document["nonce"])
        or _canonical_json(document) != challenge_bytes
    ):
        raise ExternalVerificationError("Measurement challenge schema or encoding is invalid")
    return document["target_id"], document["nonce"]


def _open_measured_file(root_descriptor: int, relative_path: str) -> int:
    components = relative_path.split("/")
    directory_descriptor = os.dup(root_descriptor)
    try:
        for component in components[:-1]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_DIRECTORY", 0),
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        return os.open(
            components[-1],
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
    finally:
        os.close(directory_descriptor)


def _measure_one_file(root_descriptor: int, path: str) -> tuple[str, int]:
    try:
        file_descriptor = _open_measured_file(root_descriptor, path)
    except OSError as exc:
        raise ExternalVerificationError(
            f"Unable to open manifest path without following links: {path}",
        ) from exc
    try:
        before = os.fstat(file_descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
            raise ExternalVerificationError(
                f"Measured path is not a bounded regular file: {path}",
            )
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(file_descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise ExternalVerificationError(f"Measured file exceeds its limit: {path}")
            digest.update(chunk)
        after = os.fstat(file_descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or total != before.st_size
        ):
            raise ExternalVerificationError(f"Measured file changed while reading: {path}")
        return digest.hexdigest(), total
    finally:
        os.close(file_descriptor)


def measure_read_only_tree(
    target_root: str | Path,
    expected_files: Mapping[str, str],
    *,
    require_read_only: bool = True,
) -> dict[str, str]:
    if not expected_files or len(expected_files) > MAX_MANIFEST_FILES:
        raise ExternalVerificationError("Expected measurement set is invalid")
    validated = {
        _validate_relative_path(path): digest
        for path, digest in expected_files.items()
    }
    if set(validated) != set(expected_files):
        raise ExternalVerificationError("Expected measurement paths are not unique")
    for digest in validated.values():
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise ExternalVerificationError("Expected measurement digest is invalid")

    root_path = Path(target_root).resolve(strict=True)
    root_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    root_descriptor = os.open(root_path, root_flags)
    try:
        if not stat.S_ISDIR(os.fstat(root_descriptor).st_mode):
            raise ExternalVerificationError("Target root is not a directory")
        if require_read_only and not (os.statvfs(root_path).f_flag & os.ST_RDONLY):
            raise ExternalVerificationError("Target tree must be mounted read-only")
        measured: dict[str, str] = {}
        total_bytes = 0
        for path in sorted(validated):
            digest, file_size = _measure_one_file(root_descriptor, path)
            total_bytes += file_size
            if total_bytes > MAX_TOTAL_BYTES:
                raise ExternalVerificationError("Total measured data exceeds its limit")
            measured[path] = digest
        return measured
    finally:
        os.close(root_descriptor)


def _measurement_statement(
    target_id: str,
    nonce: str,
    manifest_hash: str,
    measurements: Mapping[str, str],
) -> dict[str, object]:
    ordered_measurements = [
        {"path": path, "sha256": measurements[path]}
        for path in sorted(measurements)
    ]
    return {
        "version": 1,
        "target_id": target_id,
        "nonce": nonce,
        "manifest_sha256": manifest_hash,
        "measurements": ordered_measurements,
    }


def measure_and_sign(
    target_root: str | Path,
    challenge_bytes: bytes,
    manifest_bytes: bytes,
    manifest_signature: bytes,
    trusted_builder_key: Ed25519PublicKey,
    verifier_private_key: Ed25519PrivateKey,
    *,
    require_read_only: bool = True,
) -> bytes:
    target_id, nonce = _parse_challenge(challenge_bytes)
    _, expected_files = verify_signed_build_manifest(
        manifest_bytes,
        manifest_signature,
        trusted_builder_key,
    )
    measured = measure_read_only_tree(
        target_root,
        expected_files,
        require_read_only=require_read_only,
    )
    if measured != expected_files:
        raise ExternalVerificationError("Target measurement does not match the signed build")
    if not isinstance(verifier_private_key, Ed25519PrivateKey):
        raise ExternalVerificationError("External verifier signing key must use Ed25519")
    statement = _measurement_statement(
        target_id,
        nonce,
        hashlib.sha256(manifest_bytes).hexdigest(),
        measured,
    )
    statement_bytes = _canonical_json(statement)
    signature = verifier_private_key.sign(MEASUREMENT_DOMAIN + statement_bytes)
    return _canonical_json({
        **statement,
        "signature": base64.b64encode(signature).decode("ascii"),
    })


def verify_measurement_report(
    report_bytes: bytes,
    challenge_bytes: bytes,
    manifest_bytes: bytes,
    manifest_signature: bytes,
    trusted_builder_key: Ed25519PublicKey,
    trusted_verifier_key: Ed25519PublicKey,
) -> dict[str, str]:
    target_id, nonce = _parse_challenge(challenge_bytes)
    _, expected_files = verify_signed_build_manifest(
        manifest_bytes,
        manifest_signature,
        trusted_builder_key,
    )
    report = _parse_json(report_bytes, MAX_MANIFEST_BYTES, "Measurement report")
    required = {
        "version",
        "target_id",
        "nonce",
        "manifest_sha256",
        "measurements",
        "signature",
    }
    if set(report) != required or _canonical_json(report) != report_bytes:
        raise ExternalVerificationError("Measurement report schema or encoding is invalid")
    if (
        isinstance(report["version"], bool)
        or report["version"] != 1
        or report["target_id"] != target_id
        or report["nonce"] != nonce
        or report["manifest_sha256"] != hashlib.sha256(manifest_bytes).hexdigest()
        or not isinstance(report["measurements"], list)
        or not isinstance(report["signature"], str)
    ):
        raise ExternalVerificationError("Measurement report is stale or mismatched")

    actual: dict[str, str] = {}
    for entry in report["measurements"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise ExternalVerificationError("Measurement entry does not match its schema")
        path = _validate_relative_path(entry["path"])
        digest = entry["sha256"]
        if (
            path in actual
            or not isinstance(digest, str)
            or not _SHA256_RE.fullmatch(digest)
        ):
            raise ExternalVerificationError("Measurement entry is duplicated or invalid")
        actual[path] = digest
    if actual != expected_files:
        raise ExternalVerificationError("Signed measurement does not match the build manifest")
    try:
        signature = base64.b64decode(report["signature"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ExternalVerificationError("Measurement signature is not valid base64") from exc
    if len(signature) != MAX_SIGNATURE_BYTES:
        raise ExternalVerificationError("Measurement signature has an invalid length")
    if base64.b64encode(signature).decode("ascii") != report["signature"]:
        raise ExternalVerificationError("Measurement signature encoding is not canonical")
    statement = _measurement_statement(
        target_id,
        nonce,
        hashlib.sha256(manifest_bytes).hexdigest(),
        actual,
    )
    if not isinstance(trusted_verifier_key, Ed25519PublicKey):
        raise ExternalVerificationError("Trusted verifier key must use Ed25519")
    try:
        trusted_verifier_key.verify(
            signature,
            MEASUREMENT_DOMAIN + _canonical_json(statement),
        )
    except InvalidSignature as exc:
        raise ExternalVerificationError("Measurement report signature is invalid") from exc
    return actual
