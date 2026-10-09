import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from mk1_usb_guard import (
    USBHotplugMonitor,
    disable_network_interfaces,
    identify_usb_device,
    parse_uevent,
    scan_usb_storage_in_guest,
    usb_storage_is_mounted,
    verify_scan_guest,
)


class USBGuardTest(unittest.TestCase):
    def make_device(self, root, *, device_id="1-2", device_class="00", interface_class="08", serial="disk-1"):
        root = pathlib.Path(root)
        device_path = root / device_id
        device_path.mkdir(parents=True, exist_ok=True)
        for name, value in {
            "idVendor": "1234",
            "idProduct": "abcd",
            "serial": serial,
            "busnum": "1",
            "devnum": "7",
            "bDeviceClass": device_class,
        }.items():
            (device_path / name).write_text(value, encoding="ascii")
        interface_target = device_path / f"{device_id}:1.0"
        interface_target.mkdir(exist_ok=True)
        interface = root / f"{device_id}:1.0"
        if not interface.exists():
            interface.symlink_to(interface_target)
        (interface / "bInterfaceClass").write_text(interface_class, encoding="ascii")
        device = identify_usb_device(root, device_id)
        self.assertIsNotNone(device)
        assert device is not None
        return device

    @staticmethod
    def add_event(device_id):
        return (
            "ACTION=add\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0"
            f"DEVPATH=/devices/usb/{device_id}\0"
        ).encode("ascii")

    def test_uevent_fields_are_parsed_without_losing_values(self):
        event = parse_uevent(
            b"ACTION=add\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0DEVPATH=/devices/1-2\0"
        )

        self.assertEqual(event["ACTION"], "add")
        self.assertEqual(event["DEVPATH"], "/devices/1-2")

    def test_hid_is_blocked_by_deny_all_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir) / "usb"
            root.mkdir()
            device = self.make_device(root, device_class="00", interface_class="03", serial="kbd-serial")
            monitor = USBHotplugMonitor(
                enabled=mock.Mock(is_set=mock.Mock(return_value=True)),
                stop_event=mock.Mock(),
                sysfs_root=root,
            )

            with mock.patch("mk1_usb_guard.unbind_usb_device", return_value=True) as unbind:
                self.assertEqual(monitor.handle_uevent(self.add_event(device.device_id)), "blocked")
            unbind.assert_called_once()

    def test_hid_without_serial_is_blocked_even_if_vid_and_pid_are_known(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir) / "usb"
            root.mkdir()
            device = self.make_device(root, device_class="03", interface_class="03", serial="")
            monitor = USBHotplugMonitor(
                enabled=mock.Mock(),
                stop_event=mock.Mock(),
                sysfs_root=root,
            )
            with mock.patch("mk1_usb_guard.unbind_usb_device", return_value=True) as unbind:
                self.assertEqual(monitor.handle_uevent(self.add_event(device.device_id)), "blocked")
            unbind.assert_called_once()

    def test_usb_hubs_are_not_unbound_so_downstream_devices_remain_visible(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir) / "usb"
            root.mkdir()
            device = self.make_device(root, device_class="09", interface_class="09")
            monitor = USBHotplugMonitor(
                enabled=mock.Mock(),
                stop_event=mock.Mock(),
                sysfs_root=root,
            )
            with mock.patch("mk1_usb_guard.unbind_usb_device") as unbind:
                self.assertEqual(monitor.handle_uevent(self.add_event(device.device_id)), "hub_ignored")
            unbind.assert_not_called()

    def test_hid_with_additional_network_interface_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir) / "usb"
            root.mkdir()
            device = self.make_device(root, device_class="00", interface_class="03", serial="combo-1")
            extra_target = device.sysfs_path / f"{device.device_id}:1.1"
            extra_target.mkdir()
            (extra_target / "bInterfaceClass").write_text("02", encoding="ascii")
            (root / f"{device.device_id}:1.1").symlink_to(extra_target)
            monitor = USBHotplugMonitor(
                enabled=mock.Mock(),
                stop_event=mock.Mock(),
                sysfs_root=root,
            )

            with mock.patch("mk1_usb_guard.unbind_usb_device", return_value=True) as unbind:
                self.assertEqual(monitor.handle_uevent(self.add_event(device.device_id)), "blocked")

            unbind.assert_called_once()

    def test_scan_guest_verification_checks_signature_and_image_hashes(self):
        openssl = shutil.which("openssl")
        if openssl is None:
            self.skipTest("OpenSSL is not installed")
        with tempfile.TemporaryDirectory() as temp_dir:
            image_dir = pathlib.Path(temp_dir) / "guest"
            image_dir.mkdir()
            image_dir.chmod(0o700)
            private_key = pathlib.Path(temp_dir) / "signing.pem"
            public_key = pathlib.Path(temp_dir) / "trusted.pub"
            subprocess.run(
                [openssl, "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
                check=True, capture_output=True,
            )
            subprocess.run(
                [openssl, "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
                check=True, capture_output=True,
            )
            public_key.chmod(0o644)
            kernel = b"test-kernel"
            initramfs = b"test-initramfs"
            (image_dir / "vmlinuz").write_bytes(kernel)
            (image_dir / "initramfs.cpio.gz").write_bytes(initramfs)
            (image_dir / "vmlinuz").chmod(0o644)
            (image_dir / "initramfs.cpio.gz").chmod(0o644)
            manifest = {
                "format": 1,
                "kernel": {"file": "vmlinuz", "sha256": hashlib.sha256(kernel).hexdigest()},
                "initramfs": {
                    "file": "initramfs.cpio.gz",
                    "sha256": hashlib.sha256(initramfs).hexdigest(),
                },
            }
            manifest_path = image_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            manifest_path.chmod(0o644)
            signature_path = image_dir / "manifest.sig"
            subprocess.run(
                [
                    openssl, "pkeyutl", "-sign", "-rawin",
                    "-inkey", str(private_key), "-in", str(manifest_path),
                    "-out", str(signature_path),
                ],
                check=True, capture_output=True,
            )
            signature_path.chmod(0o644)

            verified = verify_scan_guest(image_dir, public_key)
            self.assertEqual(verified["kernel"], image_dir / "vmlinuz")

            (image_dir / "vmlinuz").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                verify_scan_guest(image_dir, public_key)

    def test_qemu_guest_has_no_network_and_requires_one_valid_verdict(self):
        device = mock.Mock(
            is_storage=True, bus_number=1, device_number=7,
        )
        process = mock.Mock()
        process.communicate.return_value = (b"MK1_SCAN_RESULT=clean\n", b"")
        process.returncode = 0
        with mock.patch("mk1_usb_guard.verify_scan_guest", return_value={
            "kernel": pathlib.Path("/trusted/vmlinuz"),
            "initramfs": pathlib.Path("/trusted/initramfs.cpio.gz"),
        }), mock.patch("mk1_usb_guard.shutil.which", return_value="/usr/bin/qemu-system-x86_64"), \
             mock.patch("mk1_usb_guard._trusted_system_executable", return_value="/usr/bin/qemu"), \
             mock.patch("mk1_usb_guard.subprocess.Popen", return_value=process) as popen:
            verdict = scan_usb_storage_in_guest(device, "/images", "/trusted.pub")

        command = popen.call_args.args[0]
        self.assertEqual(verdict, "clean")
        self.assertIn("-net", command)
        self.assertEqual(command[command.index("-net") + 1], "none")
        self.assertIn("hostbus=1,hostaddr=7", command[-1])
        self.assertIn("-sandbox", command)

    def test_unapproved_storage_scan_failure_leaves_device_unbound(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir) / "usb"
            root.mkdir()
            device = self.make_device(root)
            monitor = USBHotplugMonitor(
                enabled=mock.Mock(),
                stop_event=mock.Mock(),
                sysfs_root=root,
                image_directory=pathlib.Path(temp_dir) / "missing-guest",
                trusted_public_key=pathlib.Path(temp_dir) / "missing-key",
            )
            with mock.patch("mk1_usb_guard.usb_storage_is_mounted", return_value=False), \
                 mock.patch.object(monitor, "_unbind_storage_interfaces"), \
                 mock.patch("mk1_usb_guard.scan_usb_storage_in_guest", side_effect=RuntimeError("no qemu")), \
                 mock.patch("mk1_usb_guard.unbind_usb_device", return_value=True) as unbind:
                result = monitor.handle_uevent(self.add_event(device.device_id))

            self.assertEqual(result, "scan_error_unbound")
            unbind.assert_called_once_with(root, device)

    def test_scan_threat_invokes_callback_and_unbinds_storage(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir) / "usb"
            root.mkdir()
            device = self.make_device(root)
            callback = mock.Mock()
            monitor = USBHotplugMonitor(
                enabled=mock.Mock(),
                stop_event=mock.Mock(),
                sysfs_root=root,
                on_threat=callback,
            )
            with mock.patch("mk1_usb_guard.usb_storage_is_mounted", return_value=False), \
                 mock.patch.object(monitor, "_unbind_storage_interfaces"), \
                 mock.patch("mk1_usb_guard.scan_usb_storage_in_guest", return_value="threat"), \
                 mock.patch("mk1_usb_guard.unbind_usb_device", return_value=True):
                result = monitor.handle_uevent(self.add_event(device.device_id))

            self.assertEqual(result, "threat")
            callback.assert_called_once_with(device, "threat")

    def test_mounted_usb_block_device_is_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir) / "usb"
            root.mkdir()
            device = self.make_device(root)
            block_root = pathlib.Path(temp_dir) / "class-block"
            block_root.mkdir()
            block_target = device.sysfs_path / "1-2:1.0" / "host0" / "block" / "sda"
            block_target.mkdir(parents=True)
            (block_target / "dev").write_text("8:1", encoding="ascii")
            (block_root / "sda").symlink_to(block_target)
            mountinfo = pathlib.Path(temp_dir) / "mountinfo"
            mountinfo.write_text("36 25 8:1 / /media/usb rw - ext4 /dev/sda1 rw\n", encoding="ascii")

            self.assertTrue(usb_storage_is_mounted(
                device, block_root=block_root, mountinfo_path=mountinfo,
            ))

    def test_netlink_isolation_fails_if_any_interface_cannot_be_verified(self):
        failed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="operation not permitted",
        )
        with mock.patch("mk1_usb_guard.sys.platform", "linux"), \
             mock.patch("mk1_usb_guard.shutil.which", return_value="/usr/sbin/ip"), \
             mock.patch("mk1_usb_guard._trusted_system_executable", return_value="/usr/sbin/ip"), \
             mock.patch("mk1_usb_guard.subprocess.run", return_value=failed):
            self.assertFalse(disable_network_interfaces(["eth0"]))

    def test_netlink_isolation_uses_iproute2_and_verifies_each_interface(self):
        def completed(args, **_kwargs):
            if args[1:5] == ["link", "set", "dev", "eth0"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            if args[1:] == ["-o", "link", "show", "dev", "eth0"]:
                return subprocess.CompletedProcess(args, 0, "2: eth0: <BROADCAST,MULTICAST> state DOWN\n", "")
            if args[1:5] == ["link", "set", "dev", "wlan0"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            if args[1:] == ["-o", "link", "show", "dev", "wlan0"]:
                return subprocess.CompletedProcess(args, 0, "3: wlan0: <BROADCAST,MULTICAST> state DOWN\n", "")
            raise AssertionError(f"unexpected iproute2 command: {args}")

        with mock.patch("mk1_usb_guard.sys.platform", "linux"), \
             mock.patch("mk1_usb_guard.shutil.which", return_value="/usr/sbin/ip"), \
             mock.patch("mk1_usb_guard._trusted_system_executable", return_value="/usr/sbin/ip"), \
             mock.patch("mk1_usb_guard.subprocess.run", side_effect=completed) as run:
            self.assertTrue(disable_network_interfaces(["eth0", "wlan0", "lo"]))

        self.assertEqual(run.call_count, 4)

    def test_duplicate_add_events_are_processed_once_until_remove(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir) / "usb"
            root.mkdir()
            device = self.make_device(root, device_class="03", interface_class="03", serial="")
            monitor = USBHotplugMonitor(
                enabled=mock.Mock(),
                stop_event=mock.Mock(),
                sysfs_root=root,
            )
            with mock.patch("mk1_usb_guard.unbind_usb_device", return_value=True) as unbind:
                self.assertEqual(monitor.handle_uevent(self.add_event(device.device_id)), "blocked")
                self.assertEqual(monitor.handle_uevent(self.add_event(device.device_id)), "ignored")
                remove_event = (
                    "ACTION=remove\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0"
                    f"DEVPATH=/devices/usb/{device.device_id}\0"
                ).encode("ascii")
                self.assertEqual(monitor.handle_uevent(remove_event), "removed")
            self.assertEqual(unbind.call_count, 1)

    def test_full_policy_queue_unbinds_new_device_without_running_a_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir) / "usb"
            root.mkdir()
            device = self.make_device(root, device_class="03", interface_class="03", serial="")
            monitor = USBHotplugMonitor(
                enabled=mock.Mock(),
                stop_event=mock.Mock(),
                sysfs_root=root,
            )
            for _ in range(monitor._event_queue.maxsize):
                monitor._event_queue.put_nowait(b"")

            with mock.patch("mk1_usb_guard.unbind_usb_device", return_value=True) as unbind:
                self.assertFalse(monitor._enqueue_uevent(self.add_event(device.device_id)))

            unbind.assert_called_once_with(root, device)
            self.assertIn(device.device_id, monitor._processed_devices)


if __name__ == "__main__":
    unittest.main()
