import fcntl
import json
import os
import pathlib
import pty
import shutil
import subprocess
import sys
import tempfile
import termios
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class LauncherScriptTest(unittest.TestCase):
    def make_run_directory(self, root: pathlib.Path) -> pathlib.Path:
        shutil.copy2(ROOT / "run.sh", root / "run.sh")
        python_directory = root / ".venv-mk1" / "bin"
        python_directory.mkdir(parents=True)
        wrapper = python_directory / "python"
        wrapper.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = \"-\" ]; then\n"
            f"  exec {sys.executable!r} \"$@\"\n"
            "fi\n"
            "printf '%s\\n' \"$*\" >> \"$MK1_TEST_PYTHON_LOG\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        return root

    def run_launcher(self, root: pathlib.Path) -> subprocess.CompletedProcess[bytes]:
        master, slave = pty.openpty()

        def acquire_terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        env = os.environ.copy()
        env["MK1_TEST_PYTHON_LOG"] = str(root / "python.log")
        process = subprocess.Popen(
            ["bash", "run.sh"],
            cwd=root,
            env=env,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            preexec_fn=acquire_terminal,
        )
        os.close(slave)
        os.write(master, b"\n")
        try:
            process.wait(timeout=10)
            output = bytearray()
            while True:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
            return subprocess.CompletedProcess(
                process.args, process.returncode, bytes(output), b"",
            )
        finally:
            os.close(master)

    def test_run_script_preserves_existing_configuration(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = self.make_run_directory(pathlib.Path(temp_dir))
            data_dir = root / "ai_data"
            data_dir.mkdir(mode=0o755)
            config = {
                "ram_limit": 900,
                "mode": "normal",
                "compact_log": False,
                "colab_endpoint": "https://saved.example.test/rsi",
            }
            config_path = data_dir / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")

            result = self.run_launcher(root)

            self.assertEqual(result.returncode, 0, result.stdout.decode(errors="replace"))
            self.assertEqual(json.loads(config_path.read_text(encoding="utf-8")), config)
            self.assertEqual(data_dir.stat().st_mode & 0o777, 0o700)
            self.assertIn("airgap_ai_defender.py --config ai_data/config.json", (
                root / "python.log"
            ).read_text(encoding="utf-8"))

    def test_run_script_refuses_to_overwrite_invalid_configuration(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = self.make_run_directory(pathlib.Path(temp_dir))
            data_dir = root / "ai_data"
            data_dir.mkdir()
            config_path = data_dir / "config.json"
            original = b'{"mode":'
            config_path.write_bytes(original)

            result = self.run_launcher(root)

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(config_path.read_bytes(), original)

    def test_panel_script_parses_with_empty_optional_arrays(self):
        result = subprocess.run(
            ["bash", "-n", str(ROOT / "mk1-panel.sh")],
            check=False,
            capture_output=True,
            timeout=5,
        )

        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    @unittest.skipUnless(
        any(
            subprocess.run(
                ["pkg-config", "--exists", name], check=False, capture_output=True,
            ).returncode == 0
            for name in ("ncursesw", "ncurses")
        ) if shutil.which("pkg-config") else False,
        "ncurses開発パッケージ(libncurses-dev相当)が必要です",
    )
    def test_panel_reports_missing_pqc_provider_and_can_require_it(self):
        package_check = subprocess.run(
            ["pkg-config", "--exists", "liboqs"],
            check=False,
            capture_output=True,
            timeout=5,
        )
        if package_check.returncode == 0:
            self.skipTest("liboqs is installed")

        optional_build = subprocess.run(
            ["bash", str(ROOT / "mk1-panel.sh"), "--check"],
            check=False,
            capture_output=True,
            timeout=120,
        )
        self.assertEqual(
            optional_build.returncode, 0,
            optional_build.stderr.decode(errors="replace"),
        )
        self.assertIn("PQC provider なし", optional_build.stderr.decode(errors="replace"))

        required_build = subprocess.run(
            ["bash", str(ROOT / "mk1-panel.sh"), "--require-oqs"],
            check=False,
            capture_output=True,
            timeout=20,
        )
        self.assertNotEqual(required_build.returncode, 0)
        self.assertIn("liboqs が必要", required_build.stderr.decode(errors="replace"))

    def test_privileged_wireguard_wrapper_rejects_arbitrary_ip_subcommands(self):
        result = subprocess.run(
            ["sh", str(ROOT / "security" / "mk1-wg-link"), "wg0", "netns"],
            check=False,
            capture_output=True,
            timeout=5,
        )

        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
