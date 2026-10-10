#!/usr/bin/env python3
"""Create a signed manifest and Ed25519 signatures for release payloads."""

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import sys
from pathlib import Path


def run_openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL)


def write_hash(path: Path) -> str:
    digest_builder = hashlib.sha256()
    with path.open("rb") as artifact:
        for block in iter(lambda: artifact.read(1024 * 1024), b""):
            digest_builder.update(block)
    digest = digest_builder.hexdigest()
    path.with_name(path.name + ".sha256").write_text(f"{digest}\n", encoding="ascii")
    return digest


def sign(path: Path, private_key: Path) -> None:
    run_openssl(
        "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key),
        "-in", str(path), "-out", str(path.with_name(path.name + ".sig")),
    )


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: sign_release.py BUNDLE_DIR ED25519_PRIVATE_KEY", file=sys.stderr)
        return 2

    bundle = Path(sys.argv[1]).resolve(strict=True)
    private_key = Path(sys.argv[2]).resolve(strict=True)
    if private_key.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError("Ed25519 private key must not be accessible to group or other users")
    payloads = sorted(
        path for path in bundle.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and path.name != "release-signing.pub"
        and not path.name.endswith((".sig", ".sha256"))
        and path.name != "release-manifest.json"
    )
    if not payloads:
        raise RuntimeError("No release payloads found")

    entries = []
    for path in payloads:
        relative_path = path.relative_to(bundle).as_posix()
        digest = write_hash(path)
        sign(path, private_key)
        entries.append({"path": relative_path, "sha256": digest})

    manifest = bundle / "release-manifest.json"
    manifest.write_text(
        json.dumps({"format": 1, "artifacts": entries}, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_hash(manifest)
    sign(manifest, private_key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
