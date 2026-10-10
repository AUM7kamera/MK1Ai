"""Create fresh external measurement challenges and sign offline measurements."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from mk1_external_verifier import (
    MAX_MANIFEST_BYTES,
    ExternalVerificationError,
    create_measurement_challenge,
    measure_and_sign,
    verify_measurement_report,
)


def _read_file(
    path: Path,
    maximum_bytes: int,
    *,
    private: bool = False,
) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise ExternalVerificationError("Verifier input file could not be opened safely") from exc
    try:
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_size <= 0
            or file_stat.st_size > maximum_bytes
        ):
            raise ExternalVerificationError("Verifier input file is invalid or too large")
        if private and (
            file_stat.st_uid != os.geteuid()
            or file_stat.st_mode & 0o077
        ):
            raise ExternalVerificationError("Verifier private key ownership or mode is invalid")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        result = b"".join(chunks)
        if len(result) > maximum_bytes:
            raise ExternalVerificationError("Verifier input exceeds its size limit")
        return result
    finally:
        os.close(descriptor)


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    challenge = commands.add_parser("challenge")
    challenge.add_argument("--target-id", required=True)
    measure = commands.add_parser("measure")
    measure.add_argument("--target-root", required=True, type=Path)
    measure.add_argument("--challenge", required=True, type=Path)
    measure.add_argument("--manifest", required=True, type=Path)
    measure.add_argument("--manifest-signature", required=True, type=Path)
    measure.add_argument("--builder-public-key", required=True, type=Path)
    measure.add_argument("--verifier-private-key", required=True, type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("--report", required=True, type=Path)
    verify.add_argument("--challenge", required=True, type=Path)
    verify.add_argument("--manifest", required=True, type=Path)
    verify.add_argument("--manifest-signature", required=True, type=Path)
    verify.add_argument("--builder-public-key", required=True, type=Path)
    verify.add_argument("--verifier-public-key", required=True, type=Path)
    args = parser.parse_args()

    try:
        if args.command == "challenge":
            result = create_measurement_challenge(args.target_id)
        elif args.command == "measure":
            manifest_bytes = _read_file(args.manifest, MAX_MANIFEST_BYTES)
            challenge_bytes = _read_file(args.challenge, 2048)
            signature = _read_file(args.manifest_signature, 64)
            builder_bytes = _read_file(args.builder_public_key, 16_384)
            verifier_bytes = _read_file(
                args.verifier_private_key,
                16_384,
                private=True,
            )
            try:
                builder_key = serialization.load_pem_public_key(builder_bytes)
                verifier_key = serialization.load_pem_private_key(
                    verifier_bytes,
                    password=None,
                )
            except (ValueError, TypeError) as exc:
                raise ExternalVerificationError("Verifier key file is invalid PEM") from exc
            if not isinstance(builder_key, Ed25519PublicKey):
                raise ExternalVerificationError("Builder key must use Ed25519")
            if not isinstance(verifier_key, Ed25519PrivateKey):
                raise ExternalVerificationError("Verifier key must use Ed25519")
            result = measure_and_sign(
                args.target_root,
                challenge_bytes,
                manifest_bytes,
                signature,
                builder_key,
                verifier_key,
            )
        else:
            manifest_bytes = _read_file(args.manifest, MAX_MANIFEST_BYTES)
            challenge_bytes = _read_file(args.challenge, 2048)
            manifest_signature = _read_file(args.manifest_signature, 64)
            report_bytes = _read_file(args.report, MAX_MANIFEST_BYTES)
            builder_bytes = _read_file(args.builder_public_key, 16_384)
            verifier_bytes = _read_file(args.verifier_public_key, 16_384)
            try:
                builder_key = serialization.load_pem_public_key(builder_bytes)
                verifier_key = serialization.load_pem_public_key(verifier_bytes)
            except (ValueError, TypeError) as exc:
                raise ExternalVerificationError("Verifier key file is invalid PEM") from exc
            if not isinstance(builder_key, Ed25519PublicKey):
                raise ExternalVerificationError("Builder key must use Ed25519")
            if not isinstance(verifier_key, Ed25519PublicKey):
                raise ExternalVerificationError("Verifier key must use Ed25519")
            measurements = verify_measurement_report(
                report_bytes,
                challenge_bytes,
                manifest_bytes,
                manifest_signature,
                builder_key,
                verifier_key,
            )
            result = json.dumps({
                "verified": True,
                "file_count": len(measurements),
                "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            }, sort_keys=True, separators=(",", ":")).encode("ascii")
        os.write(1, result + b"\n")
    except (OSError, ExternalVerificationError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
