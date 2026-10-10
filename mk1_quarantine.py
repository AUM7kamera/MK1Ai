"""Persistent fail-closed network quarantine and two-key release."""

from __future__ import annotations

import argparse
import base64
import fcntl
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
from mk1_quorum import (
    MAX_APPROVAL_BUNDLE_BYTES,
    QuorumError,
    load_trusted_quorum_keys,
    verify_approval_bundle,
)


STATE_DIRECTORY = Path("/var/lib/mk1ai-security")
STATE_FILE = "quarantine-state.json"
LOCK_FILE = "quarantine-state.lock"
APPROVER_KEYS = (
    ("node-1", Path("/etc/mk1ai/quorum/node-1.pub")),
    ("node-2", Path("/etc/mk1ai/quorum/node-2.pub")),
    ("node-3", Path("/etc/mk1ai/quorum/node-3.pub")),
)
MAX_STATE_BYTES = 4096


class QuarantineError(RuntimeError):
    pass


class QuarantineStateStore:
    def __init__(
        self,
        directory: str | Path = STATE_DIRECTORY,
        *,
        expected_uid: int = 0,
        strict_ancestors: bool = True,
        approver_keys: tuple[tuple[str, Path], ...] = APPROVER_KEYS,
        nft_apply=apply_nft_policy,
        nft_remove=None,
        airgap_disable=disable_all_network_paths,
    ):
        self.directory = Path(directory)
        self.state_path = self.directory / STATE_FILE
        self.lock_path = self.directory / LOCK_FILE
        self.expected_uid = expected_uid
        self.strict_ancestors = strict_ancestors
        self.approver_keys = dict(approver_keys)
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
        approval_bundle_path: str | Path,
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
            approval_bundle = _read_untrusted_approval_bundle(approval_bundle_path)
            self._verify_approvals(message, approval_bundle)
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

    def _verify_approvals(self, message: bytes, approval_bundle: bytes) -> None:
        try:
            trusted_keys = load_trusted_quorum_keys(
                self.approver_keys,
                expected_uid=self.expected_uid,
                strict_ancestors=self.strict_ancestors,
            )
            verify_approval_bundle(
                message,
                approval_bundle,
                trusted_keys,
                threshold=2,
            )
        except QuorumError as exc:
            raise QuarantineError(str(exc)) from exc

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


def _read_untrusted_approval_bundle(path: str | Path) -> bytes:
    bundle_path = Path(path)
    try:
        file_descriptor = os.open(
            bundle_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise QuarantineError("Operator approval bundle could not be opened") from exc
    try:
        bundle_stat = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(bundle_stat.st_mode)
            or bundle_stat.st_size <= 0
            or bundle_stat.st_size > MAX_APPROVAL_BUNDLE_BYTES
        ):
            raise QuarantineError("Operator approval bundle is invalid")
        chunks: list[bytes] = []
        remaining = MAX_APPROVAL_BUNDLE_BYTES + 1
        while remaining:
            chunk = os.read(file_descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        bundle = b"".join(chunks)
        if len(bundle) > MAX_APPROVAL_BUNDLE_BYTES:
            raise QuarantineError("Operator approval bundle exceeds its size limit")
        return bundle
    finally:
        os.close(file_descriptor)


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
    release.add_argument("--approval-bundle", required=True, type=Path)
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
            store.release(args.challenge, args.approval_bundle)
    except (OSError, QuarantineError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
