"""Persistent fail-closed network quarantine and two-key release."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import shutil
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from mk1_airgap import disable_all_network_paths
from mk1_firewall import apply_nft_policy


STATE_DIRECTORY = Path("/var/lib/mk1ai-security")
STATE_FILE = "quarantine-state.json"
LOCK_FILE = "quarantine-state.lock"
APPROVER_KEYS = (
    Path("/etc/mk1ai/quarantine-approver-1.pub"),
    Path("/etc/mk1ai/quarantine-approver-2.pub"),
)
OPENSSL_PATHS = ("/usr/bin/openssl", "/usr/local/bin/openssl", "/bin/openssl")
MAX_STATE_BYTES = 4096
MAX_SIGNATURE_BYTES = 4096


class QuarantineError(RuntimeError):
    pass


class QuarantineStateStore:
    def __init__(
        self,
        directory: str | Path = STATE_DIRECTORY,
        *,
        expected_uid: int = 0,
        strict_ancestors: bool = True,
        approver_keys: tuple[Path, Path] = APPROVER_KEYS,
        openssl_path: str | None = None,
        nft_apply=apply_nft_policy,
        nft_remove=None,
        airgap_disable=disable_all_network_paths,
    ):
        self.directory = Path(directory)
        self.state_path = self.directory / STATE_FILE
        self.lock_path = self.directory / LOCK_FILE
        self.expected_uid = expected_uid
        self.strict_ancestors = strict_ancestors
        self.approver_keys = approver_keys
        self.openssl_path = openssl_path
        self.nft_apply = nft_apply
        self.nft_remove = nft_remove or _remove_nft_policy
        self.airgap_disable = airgap_disable

    def mark_quarantined(self) -> bool:
        with self._locked():
            state = self._load_or_initialize()
            state["state"] = "quarantined"
            state["generation"] += 1
            state["pending_challenge"] = None
            self._write_state(state)
            return True

    def enforce(self) -> bool:
        with self._locked():
            state = self._load_or_initialize()
            if state["state"] == "released":
                return True
            if not self.nft_apply(
                mode="full_isolation",
                management_ips=[],
                management_ports=[],
            ):
                raise QuarantineError("Unable to apply nftables quarantine policy")
            if not self.airgap_disable():
                raise QuarantineError("Unable to verify all logical air-gap paths")
            return True

    def issue_challenge(self) -> bytes:
        with self._locked():
            state = self._load_or_initialize()
            if state["state"] != "quarantined":
                raise QuarantineError("Release challenge requires active quarantine")
            if not self.nft_apply(
                mode="full_isolation",
                management_ips=[],
                management_ports=[],
            ):
                raise QuarantineError("Cannot issue a release challenge without active quarantine")
            challenge = secrets.token_hex(32)
            state["generation"] += 1
            state["pending_challenge"] = challenge
            self._write_state(state)
            message = _release_message(state["generation"], challenge)
            return (
                json.dumps({
                    "version": 1,
                    "generation": state["generation"],
                    "challenge": challenge,
                    "message_base64": base64.b64encode(message).decode("ascii"),
                }, sort_keys=True) + "\n"
            ).encode("ascii")

    def release(
        self,
        challenge: str,
        signature_one: str | Path,
        signature_two: str | Path,
    ) -> bool:
        with self._locked():
            state = self._load_or_initialize()
            pending = state["pending_challenge"]
            if (
                state["state"] != "quarantined"
                or not isinstance(pending, str)
                or not hmac.compare_digest(challenge, pending)
            ):
                raise QuarantineError("Release challenge is absent, stale, or mismatched")
            message = _release_message(state["generation"], pending)
            signatures = (
                _read_untrusted_signature(signature_one),
                _read_untrusted_signature(signature_two),
            )
            self._verify_approvals(message, signatures)
            state["state"] = "released"
            state["generation"] += 1
            state["pending_challenge"] = None
            self._write_state(state)
            if not self.nft_remove():
                state["state"] = "quarantined"
                state["generation"] += 1
                self._write_state(state)
                if not self.nft_apply(
                    mode="full_isolation",
                    management_ips=[],
                    management_ports=[],
                ):
                    raise QuarantineError(
                        "Firewall release failed and quarantine re-application failed",
                    )
                raise QuarantineError("Unable to remove nftables quarantine policy")
            return True

    def _verify_approvals(self, message: bytes, signatures: tuple[bytes, bytes]) -> None:
        openssl = _trusted_openssl(self.openssl_path, self.expected_uid)
        key_fingerprints = tuple(
            _public_key_fingerprint(
                openssl,
                path,
                self.expected_uid,
                strict_ancestors=self.strict_ancestors,
            )
            for path in self.approver_keys
        )
        if hmac.compare_digest(key_fingerprints[0], key_fingerprints[1]):
            raise QuarantineError("The two approver public keys must be distinct")
        with tempfile.TemporaryDirectory(
            prefix="mk1ai-release-", dir=self.directory,
        ) as temporary_directory:
            temp_path = Path(temporary_directory)
            message_path = temp_path / "release-message"
            signature_paths = (temp_path / "approval-1.sig", temp_path / "approval-2.sig")
            message_path.write_bytes(message)
            for path, signature in zip(signature_paths, signatures, strict=True):
                path.write_bytes(signature)
            for key_path, signature_path in zip(
                self.approver_keys, signature_paths, strict=True,
            ):
                verified = subprocess.run(
                    [
                        openssl, "pkeyutl", "-verify", "-pubin",
                        "-inkey", str(key_path), "-rawin",
                        "-in", str(message_path), "-sigfile", str(signature_path),
                    ],
                    check=False,
                    capture_output=True,
                    timeout=10,
                    env={"PATH": "/usr/bin:/bin", "HOME": "/"},
                )
                if verified.returncode != 0:
                    raise QuarantineError("An operator release signature is invalid")

    def _load_or_initialize(self) -> dict:
        self._verify_directory(create=True)
        try:
            file_stat = self.state_path.lstat()
        except FileNotFoundError:
            state = {
                "version": 1,
                "state": "quarantined",
                "generation": 1,
                "pending_challenge": None,
            }
            self._write_state(state)
            return state
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != self.expected_uid
            or file_stat.st_mode & 0o077
            or file_stat.st_size > MAX_STATE_BYTES
        ):
            raise QuarantineError("Quarantine state file ownership or mode is invalid")
        with self.state_path.open("rb") as handle:
            raw = handle.read(MAX_STATE_BYTES + 1)
        if len(raw) > MAX_STATE_BYTES:
            raise QuarantineError("Quarantine state file exceeds size limit")
        try:
            state = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise QuarantineError("Quarantine state file is invalid") from exc
        if (
            not isinstance(state, dict)
            or set(state) != {"version", "state", "generation", "pending_challenge"}
            or type(state["version"]) is not int
            or state["version"] != 1
            or not isinstance(state["state"], str)
            or state["state"] not in {"quarantined", "released"}
            or type(state["generation"]) is not int
            or state["generation"] < 1
            or (
                state["pending_challenge"] is not None
                and (
                    not isinstance(state["pending_challenge"], str)
                    or len(state["pending_challenge"]) != 64
                    or any(ch not in "0123456789abcdef" for ch in state["pending_challenge"])
                )
            )
        ):
            raise QuarantineError("Quarantine state schema is invalid")
        if state["state"] == "released" and state["pending_challenge"] is not None:
            raise QuarantineError("Released state cannot contain a pending challenge")
        return state

    def _verify_directory(self, *, create: bool) -> None:
        if create:
            try:
                self.directory.mkdir(mode=0o700)
            except FileExistsError:
                pass
        try:
            directory_stat = self.directory.lstat()
        except OSError as exc:
            raise QuarantineError("Quarantine state directory is unavailable") from exc
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != self.expected_uid
            or directory_stat.st_mode & 0o077
        ):
            raise QuarantineError("Quarantine state directory ownership or mode is invalid")
        if self.strict_ancestors:
            for parent in self.directory.parents:
                parent_stat = parent.stat()
                if parent_stat.st_uid != self.expected_uid or parent_stat.st_mode & 0o022:
                    raise QuarantineError(
                        "Quarantine state directory has an untrusted ancestor",
                    )

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._verify_directory(create=True)
        descriptor = os.open(
            self.lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | os.O_CLOEXEC,
            0o600,
        )
        try:
            lock_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(lock_stat.st_mode)
                or lock_stat.st_uid != self.expected_uid
                or lock_stat.st_mode & 0o077
            ):
                raise QuarantineError("Quarantine lock ownership or mode is invalid")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def _write_state(self, state: dict) -> None:
        self._verify_directory(create=True)
        payload = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "ascii",
        )
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".quarantine-state-", dir=self.directory,
        )
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.state_path)
            directory_descriptor = os.open(
                self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def _release_message(generation: int, challenge: str) -> bytes:
    return f"MK1AI-QUARANTINE-RELEASE-v1\n{generation}\n{challenge}\n".encode("ascii")


def _read_untrusted_signature(path: str | Path) -> bytes:
    signature_path = Path(path)
    signature_stat = signature_path.lstat()
    if (
        not stat.S_ISREG(signature_stat.st_mode)
        or signature_stat.st_size <= 0
        or signature_stat.st_size > MAX_SIGNATURE_BYTES
    ):
        raise QuarantineError("Operator signature file is invalid")
    return signature_path.read_bytes()


def _public_key_fingerprint(
    openssl: str,
    path: str | Path,
    expected_uid: int,
    *,
    strict_ancestors: bool,
) -> bytes:
    key_path = Path(path)
    key_stat = key_path.lstat()
    if (
        not stat.S_ISREG(key_stat.st_mode)
        or key_stat.st_uid != expected_uid
        or key_stat.st_mode & 0o022
        or key_stat.st_size > 16_384
    ):
        raise QuarantineError("Operator public key ownership or mode is invalid")
    if strict_ancestors:
        for parent in key_path.parents:
            parent_stat = parent.stat()
            if parent_stat.st_uid != expected_uid or parent_stat.st_mode & 0o022:
                raise QuarantineError("Operator public key has an untrusted parent directory")
    result = subprocess.run(
        [openssl, "pkey", "-pubin", "-in", str(key_path), "-outform", "DER"],
        check=False,
        capture_output=True,
        timeout=10,
        env={"PATH": "/usr/bin:/bin", "HOME": "/"},
    )
    if result.returncode != 0 or not result.stdout:
        raise QuarantineError("Operator public key could not be parsed")
    return hashlib.sha256(result.stdout).digest()


def _trusted_openssl(path: str | None, expected_uid: int) -> str:
    candidates = [path] if path else list(OPENSSL_PATHS)
    for candidate in candidates:
        if candidate is None or not os.path.exists(candidate):
            continue
        resolved = Path(candidate).resolve(strict=True)
        executable_stat = resolved.stat()
        if (
            stat.S_ISREG(executable_stat.st_mode)
            and executable_stat.st_uid == expected_uid
            and not executable_stat.st_mode & 0o022
        ):
            return str(resolved)
    raise QuarantineError("A trusted OpenSSL executable is required for release")


def _remove_nft_policy() -> bool:
    nft = shutil.which("nft", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if nft is None or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return False
    resolved = Path(nft).resolve(strict=True)
    executable_stat = resolved.stat()
    if (
        executable_stat.st_uid != 0
        or not stat.S_ISREG(executable_stat.st_mode)
        or executable_stat.st_mode & 0o022
    ):
        return False
    try:
        result = subprocess.run(
            [str(resolved), "-f", "-"],
            input="destroy table inet mk1ai_quarantine\n",
            text=True,
            check=False,
            capture_output=True,
            timeout=10,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/"},
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("enforce")
    commands.add_parser("issue-release-challenge")
    release = commands.add_parser("release")
    release.add_argument("--challenge", required=True)
    release.add_argument("--signature-1", required=True, type=Path)
    release.add_argument("--signature-2", required=True, type=Path)
    args = parser.parse_args()
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        parser.error("quarantine operations must run as root")
    store = QuarantineStateStore()
    try:
        if args.command == "enforce":
            store.enforce()
        elif args.command == "issue-release-challenge":
            os.write(1, store.issue_challenge())
        else:
            store.release(args.challenge, args.signature_1, args.signature_2)
    except (OSError, QuarantineError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
