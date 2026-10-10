from __future__ import annotations

import os
import pathlib
import tempfile
import unittest
from unittest import mock

from mk1_airgap import AirgapPathController, MODULES, blacklist_contents


class AirgapPathControllerTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = pathlib.Path(self.temporary_directory.name)
        self.sysfs = self.root / "sys"
        self.modules = self.root / "modules"
        self.modprobe = self.root / "etc/modprobe.d/mk1ai-airgap.conf"
        self.modules.mkdir()
        (self.modules / "modules.builtin").write_text("", encoding="ascii")
        for relative in (
            "class/net",
            "class/rfkill",
            "class/bluetooth",
            "class/wwan",
            "class/usbmisc",
            "class/tty",
            "bus/thunderbolt/devices",
            "module",
        ):
            (self.sysfs / relative).mkdir(parents=True, exist_ok=True)
        (self.sysfs / "bus/thunderbolt/devices/domain0").mkdir()
        (self.sysfs / "bus/thunderbolt/devices/domain0/security").write_text(
            "dpon",
            encoding="ascii",
        )
        self.fake_ip = self.root / "ip"
        self.fake_ip.write_text("", encoding="ascii")
        self.fake_ip.chmod(0o755)
        self.fake_rfkill = self.root / "rfkill"
        self.fake_rfkill.write_text("", encoding="ascii")
        self.fake_rfkill.chmod(0o755)
        self.fake_modprobe = self.root / "modprobe"
        self.fake_modprobe.write_text("", encoding="ascii")
        self.fake_modprobe.chmod(0o755)
        self.controller = AirgapPathController(
            sysfs_root=self.sysfs,
            modules_root=self.modules,
            blacklist_path=self.modprobe,
            expected_uid=os.geteuid(),
        )

    def prepare_radio(self, *, soft="1", hard="0"):
        radio = self.sysfs / "class/rfkill/rfkill0"
        radio.mkdir()
        (radio / "soft").write_text(soft, encoding="ascii")
        (radio / "hard").write_text(hard, encoding="ascii")
        (radio / "type").write_text("wlan", encoding="ascii")
        return radio

    def completed_runner(self, command, **_kwargs):
        if pathlib.Path(command[0]).name == "ip" and command[1:3] == ["-o", "link"]:
            return mock.Mock(returncode=0, stdout="2: eth0: <BROADCAST> state DOWN\n")
        return mock.Mock(returncode=0, stdout="", stderr="")

    def test_complete_report_requires_all_enumerators_and_verified_radio_state(self):
        (self.sysfs / "class/net/eth0").mkdir()
        self.prepare_radio()
        with mock.patch.object(self.controller, "_trusted_executable") as executable, \
             mock.patch.object(self.controller, "runner", side_effect=self.completed_runner):
            executable.side_effect = lambda name: {
                "ip": str(self.fake_ip),
                "rfkill": str(self.fake_rfkill),
                "modprobe": str(self.fake_modprobe),
            }.get(name)
            report = self.controller.disable_all()

        self.assertTrue(report["completed"], report["failures"])
        self.assertEqual(report["interfaces"], ["eth0"])
        self.assertEqual(report["rfkill_radios"], ["rfkill0"])
        self.assertTrue(report["blacklist_installed"])
        self.assertEqual(self.modprobe.read_text(encoding="ascii"), blacklist_contents())
        self.assertEqual(report["physical_isolation"], False)

    def test_failed_interface_or_radio_verification_never_reports_completion(self):
        (self.sysfs / "class/net/eth0").mkdir()
        self.prepare_radio(soft="0", hard="0")
        self.controller.runner = mock.Mock(side_effect=lambda command, **kwargs: (
            mock.Mock(returncode=0, stdout="2: eth0: <BROADCAST> state UP\n")
            if command[1:3] == ["-o", "link"]
            else mock.Mock(returncode=0, stdout="", stderr="")
        ))
        with mock.patch.object(
            self.controller, "_trusted_executable",
            side_effect=lambda name: str(self.root / name),
        ):
            report = self.controller.disable_all()

        self.assertFalse(report["completed"])
        self.assertIn("interface_not_verified_down:eth0", report["failures"])
        self.assertIn("rfkill_not_blocked:rfkill0", report["failures"])

    def test_builtin_network_driver_prevents_isolation_complete(self):
        (self.modules / "modules.builtin").write_text(
            "kernel/drivers/net/usb/cdc_ether.ko\n",
            encoding="ascii",
        )
        with mock.patch.object(self.controller, "_trusted_executable", return_value=None):
            report = self.controller.disable_all()

        self.assertFalse(report["completed"])
        self.assertIn("prohibited_module_builtin:cdc_ether", report["failures"])

    def test_compressed_builtin_module_is_recognized(self):
        (self.modules / "modules.builtin").write_text(
            "kernel/drivers/net/usb/cdc_ether.ko.xz\n",
            encoding="ascii",
        )
        with mock.patch.object(self.controller, "_trusted_executable", return_value=None):
            report = self.controller.disable_all()

        self.assertFalse(report["completed"])
        self.assertIn("prohibited_module_builtin:cdc_ether", report["failures"])

    def test_thunderbolt_domain_is_locked_to_dpon(self):
        security = self.sysfs / "bus/thunderbolt/devices/domain0/security"
        security.write_text("user", encoding="ascii")

        with mock.patch.object(
            self.controller,
            "_trusted_executable",
            side_effect=lambda name: {
                "ip": str(self.fake_ip),
                "rfkill": str(self.fake_rfkill),
                "modprobe": str(self.fake_modprobe),
            }.get(name),
        ), mock.patch.object(self.controller, "runner", side_effect=self.completed_runner):
            report = self.controller.disable_all()

        self.assertEqual(security.read_text(encoding="ascii"), "dpon")
        self.assertTrue(report["completed"], report["failures"])

    def test_bluetooth_device_without_rfkill_control_prevents_completion(self):
        (self.sysfs / "class/bluetooth/hci0").mkdir()

        with mock.patch.object(self.controller, "_trusted_executable", return_value=None):
            report = self.controller.disable_all()

        self.assertFalse(report["completed"])
        self.assertIn("bluetooth_rfkill_radio_missing", report["failures"])

    def test_blacklist_covers_usb_network_modem_and_thunderbolt_drivers(self):
        contents = blacklist_contents()
        for module in MODULES:
            with self.subTest(module=module):
                self.assertIn(f"blacklist {module}\n", contents)
                self.assertIn(f"install {module} /bin/false\n", contents)


if __name__ == "__main__":
    unittest.main()
