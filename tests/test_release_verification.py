import pathlib
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[1]


class ReleaseVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = pathlib.Path(self.temp_dir.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.private_key = self.root / "release-key.pem"
        self.public_key = self.root / "release-key.pub"
        subprocess.run(
            [
                "openssl", "genpkey", "-algorithm", "ED25519",
                "-out", str(self.private_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        self.private_key.chmod(0o600)
        subprocess.run(
            [
                "openssl", "pkey", "-in", str(self.private_key), "-pubout",
                "-out", str(self.public_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        (self.bundle / "release-signing.pub").write_bytes(self.public_key.read_bytes())
        (self.bundle / "sample.bin").write_bytes(b"release payload")
        subprocess.run(
            [
                sys.executable,
                str(REPOSITORY_ROOT / "scripts" / "sign_release.py"),
                str(self.bundle),
                str(self.private_key),
            ],
            check=True,
            cwd=REPOSITORY_ROOT,
        )

    def verify(self):
        return subprocess.run(
            [
                sys.executable,
                str(REPOSITORY_ROOT / "scripts" / "verify_release.py"),
                "--bundle",
                str(self.bundle),
                "--public-key",
                str(self.public_key),
            ],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
        )

    def test_signed_release_bundle_verifies(self):
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_modified_payload_is_rejected(self):
        (self.bundle / "sample.bin").write_bytes(b"tampered payload")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("verification failed", result.stderr.lower())

    def test_untrusted_public_key_is_rejected(self):
        other_key = self.root / "other-key.pem"
        other_public_key = self.root / "other-key.pub"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(other_key)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "openssl", "pkey", "-in", str(other_key), "-pubout",
                "-out", str(other_public_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        result = subprocess.run(
            [
                sys.executable,
                str(REPOSITORY_ROOT / "scripts" / "verify_release.py"),
                "--bundle",
                str(self.bundle),
                "--public-key",
                str(other_public_key),
            ],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_unsigned_extra_file_is_rejected(self):
        (self.bundle / "unsigned.txt").write_text("untracked", encoding="utf-8")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsigned files", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
