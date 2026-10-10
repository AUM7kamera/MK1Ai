import base64
import hashlib
import json
import os
import pathlib
import pty
import select
import subprocess
import tempfile
import time
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "proxmox-transfer-registration.sh"


class ProxmoxRegistrationTransferTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = pathlib.Path(self.temp_dir.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.profile_path = self.root / "profile.json"
        self.command_log = self.root / "pct.log"
        credential_id = b"out-of-band-confirmation-test"
        encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
        profile = {
            "version": 1,
            "user_id": encode(b"owner"),
            "credentials": [{
                "credential_id": encode(credential_id),
                "public_key": encode(b"public-key"),
                "sign_count": 0,
            }],
        }
        self.profile_path.write_text(json.dumps(profile), encoding="ascii")
        self.fingerprint = hashlib.sha256(credential_id).hexdigest()
        fake_pct = self.bin_dir / "pct"
        fake_pct.write_text(
            "#!/bin/sh\n"
            'printf "%s\\n" "$*" >> "$MK1_TEST_PCT_LOG"\n'
            'case "$1" in\n'
            '  status) if [ "$2" = "101" ]; then echo "status: running"; else echo "status: stopped"; fi ;;\n'
            '  pull) cp "$MK1_TEST_PROFILE" "$4" ;;\n'
            '  *) exit 0 ;;\n'
            "esac\n",
            encoding="ascii",
        )
        fake_pct.chmod(0o700)
        self.env = os.environ.copy()
        self.env["PATH"] = f"{self.bin_dir}{os.pathsep}{self.env['PATH']}"
        self.env["MK1_TEST_PROFILE"] = str(self.profile_path)
        self.env["MK1_TEST_PCT_LOG"] = str(self.command_log)

    def test_transfer_refuses_noninteractive_fingerprint_confirmation(self):
        result = subprocess.run(
            ["bash", str(SCRIPT), "101", "100"],
            env=self.env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Interactive out-of-band fingerprint confirmation is required", result.stderr)
        self.assertNotIn("push", self.command_log.read_text(encoding="ascii"))

    def test_transfer_rejects_mismatched_out_of_band_fingerprint(self):
        child_pid, master = pty.fork()
        if child_pid == 0:
            os.execve(
                "/bin/bash",
                ["bash", str(SCRIPT), "101", "100"],
                self.env,
            )
        output = bytearray()
        prompt = b"type the full fingerprint:"
        deadline = time.monotonic() + 10
        status = None
        try:
            while prompt not in output and time.monotonic() < deadline:
                readable, _, _ = select.select([master], [], [], 0.2)
                if readable:
                    output.extend(os.read(master, 4096))
            self.assertIn(prompt, output)
            os.write(master, (("0" * 64) + "\n").encode("ascii"))
            while time.monotonic() < deadline:
                readable, _, _ = select.select([master], [], [], 0.2)
                if not readable:
                    completed_pid, status = os.waitpid(child_pid, os.WNOHANG)
                    if completed_pid:
                        break
                    continue
                try:
                    output.extend(os.read(master, 4096))
                except OSError:
                    completed_pid, status = os.waitpid(child_pid, os.WNOHANG)
                    if completed_pid:
                        break
            else:
                os.kill(child_pid, 9)
                os.waitpid(child_pid, 0)
                self.fail("profile transfer did not exit after invalid confirmation")
        finally:
            os.close(master)
        if status is None:
            completed_pid, status = os.waitpid(child_pid, 0)
        transcript = output.decode("utf-8", errors="replace")

        self.assertEqual(completed_pid, child_pid)
        self.assertNotEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertIn(self.fingerprint, transcript)
        self.assertIn("Credential fingerprint confirmation failed", transcript)
        logged_commands = self.command_log.read_text(encoding="ascii")
        self.assertNotIn("push", logged_commands)
        self.assertNotIn("start", logged_commands)


if __name__ == "__main__":
    unittest.main()
