#!/usr/bin/env python3
"""Verify a release bundle against an independently trusted Ed25519 key."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

MANIFEST_NAME = "release-manifest.json"
PUBLIC_KEY_NAME = "release-signing.pub"


def verify_signature(path: Path, public_key: Path) -> None:
    signature = path.with_name(path.name + ".sig")
    if not path.is_file() or path.is_symlink() or not signature.is_file() or signature.is_symlink():
        raise ValueError(f"Missing or unsafe signed file: {path.name}")
    subprocess.run(
        [
            "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
            "-rawin", "-in", str(path), "-sigfile", str(signature),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def verify_hash(path: Path, expected: str) -> None:
    sidecar = path.with_name(path.name + ".sha256")
    if not sidecar.is_file() or sidecar.is_symlink():
        raise ValueError(f"Missing or unsafe SHA-256 sidecar: {path.name}")
    sidecar_digest = sidecar.read_text(encoding="ascii").strip()
    digest_builder = hashlib.sha256()
    with path.open("rb") as artifact:
        for block in iter(lambda: artifact.read(1024 * 1024), b""):
            digest_builder.update(block)
    actual = digest_builder.hexdigest()
    if sidecar_digest != expected or actual != expected:
        raise ValueError(f"SHA-256 mismatch: {path.name}")


def load_manifest(bundle: Path, public_key: Path) -> list[object]:
    manifest = bundle / MANIFEST_NAME
    if manifest.is_symlink():
        raise ValueError("Missing or unsafe release manifest")
    verify_signature(manifest, public_key)
    digest_builder = hashlib.sha256()
    with manifest.open("rb") as manifest_file:
        for block in iter(lambda: manifest_file.read(1024 * 1024), b""):
            digest_builder.update(block)
    verify_hash(manifest, digest_builder.hexdigest())

    document = json.loads(manifest.read_text(encoding="utf-8"))
    if (
        not isinstance(document, dict)
        or document.get("format") != 1
        or not isinstance(document.get("artifacts"), list)
    ):
        raise ValueError("Unsupported release manifest")
    return document["artifacts"]


def resolve_artifact(
    bundle: Path, entry: object, seen: set[str]
) -> tuple[Path, str, str]:
    if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
        raise ValueError("Malformed release manifest entry")
    artifact_name = entry["path"]
    digest = entry.get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Malformed artifact SHA-256 in release manifest")
    relative = PurePosixPath(artifact_name)
    if (
        relative.is_absolute()
        or not relative.parts
        or ".." in relative.parts
        or artifact_name in seen
        or artifact_name == MANIFEST_NAME
        or artifact_name.endswith((".sig", ".sha256"))
    ):
        raise ValueError("Unsafe or duplicate artifact path in release manifest")
    artifact = bundle.joinpath(*relative.parts)
    try:
        artifact.resolve(strict=True).relative_to(bundle.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise ValueError(f"Artifact escapes the release bundle: {relative}") from error
    if not artifact.is_file() or artifact.is_symlink():
        raise ValueError(f"Missing or unsafe release artifact: {relative}")
    return artifact, artifact_name, digest


def verify_artifacts(
    bundle: Path, public_key: Path, entries: list[object]
) -> set[str]:
    seen: set[str] = set()
    for entry in entries:
        artifact, artifact_name, digest = resolve_artifact(bundle, entry, seen)
        verify_hash(artifact, digest)
        verify_signature(artifact, public_key)
        seen.add(artifact_name)
    if not seen:
        raise ValueError("Release manifest contains no artifacts")
    return seen


def verify_inventory(bundle: Path, seen: set[str]) -> None:
    expected_files = {
        MANIFEST_NAME,
        f"{MANIFEST_NAME}.sig",
        f"{MANIFEST_NAME}.sha256",
        PUBLIC_KEY_NAME,
    }
    for artifact_name in seen:
        expected_files.update(
            {artifact_name, f"{artifact_name}.sig", f"{artifact_name}.sha256"}
        )
    actual_files = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual_files != expected_files:
        raise ValueError("Release bundle contains missing or unsigned files")


def verify_bundle(bundle: Path, public_key: Path) -> None:
    entries = load_manifest(bundle, public_key)
    seen = verify_artifacts(bundle, public_key, entries)
    verify_inventory(bundle, seen)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    args = parser.parse_args()
    try:
        verify_bundle(args.bundle.resolve(strict=True), args.public_key.resolve(strict=True))
    except (
        OSError, ValueError, TypeError, KeyError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"Release verification failed: {error}", file=sys.stderr)
        return 1
    print("Release signature and SHA-256 verification succeeded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
