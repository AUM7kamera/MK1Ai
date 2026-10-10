import hashlib
import json
import os
import pathlib
import shutil
import socket
import subprocess
import stat
import tempfile
import threading
import time
import unittest
from unittest import mock

import mk1_usb_guard
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

    def test_legacy_allowlist_cannot_authorize_spoofable_hid_descriptors(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir) / "usb"
            root.mkdir()
            device = self.make_device(root, device_class="00", interface_class="03", serial="kbd-serial")
            allowlist = pathlib.Path(temp_dir) / "allowlist.json"
            allowlist.write_text(json.dumps({
                "version": 1,
                "devices": [{"vid": "1234", "pid": "abcd", "serial": "kbd-serial"}],
            }), encoding="utf-8")
            allowlist.chmod(0o600)
            monitor = USBHotplugMonitor(
                enabled=mock.Mock(is_set=mock.Mock(return_value=True)),
                stop_event=mock.Mock(),
                sysfs_root=root,
            )

            with mock.patch("mk1_usb_guard.unbind_usb_device", return_value=True) as unbind:
                self.assertEqual(monitor.handle_uevent(self.add_event(device.device_id)), "blocked")

            unbind.assert_called_once_with(root, device)

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

    def test_composite_storage_with_non_storage_interface_is_blocked(self):
        for extra_class in ("02", "ff"):
            with self.subTest(interface_class=extra_class), tempfile.TemporaryDirectory() as temp_dir:
                root = pathlib.Path(temp_dir) / "usb"
                root.mkdir()
                device = self.make_device(root, interface_class="08")
                extra_target = device.sysfs_path / f"{device.device_id}:1.1"
                extra_target.mkdir()
                (extra_target / "bInterfaceClass").write_text(extra_class, encoding="ascii")
                (root / f"{device.device_id}:1.1").symlink_to(extra_target)
                composite = identify_usb_device(root, device.device_id)
                self.assertIsNotNone(composite)
                self.assertFalse(composite.is_storage)
                monitor = USBHotplugMonitor(
                    enabled=mock.Mock(),
                    stop_event=mock.Mock(),
                    sysfs_root=root,
                )

                with mock.patch(
                    "mk1_usb_guard.scan_usb_storage_in_guest",
                    side_effect=AssertionError("composite device must not be scanned/accepted"),
                ), mock.patch("mk1_usb_guard.unbind_usb_device", return_value=True) as unbind:
                    result = monitor.handle_uevent(self.add_event(device.device_id))

                self.assertEqual(result, "blocked")
                unbind.assert_called_once()

    def test_usbguard_policy_allows_only_exact_storage_interface_sets(self):
        security_dir = pathlib.Path(__file__).resolve().parents[1] / "security"
        contents = (security_dir / "usbguard/rules.conf").read_text(encoding="ascii")

        self.assertIn("block with-interface one-of { 03:*:* }", contents)
        self.assertIn("allow with-interface equals { 08:*:* }", contents)
        self.assertTrue(contents.rstrip().endswith("block"))

    def test_usbguard_installer_enables_kernel_default_deny_and_daemon(self):
        security_dir = pathlib.Path(__file__).resolve().parents[1] / "security"
        installer = (security_dir / "install-usb-guard.sh").read_text(encoding="utf-8")
        verifier = (security_dir / "verify-usb-guard.sh").read_text(encoding="utf-8")

        self.assertIn("usbcore.authorized_default=0", installer)
        self.assertIn("systemctl enable --now usbguard.service", installer)
        self.assertIn("systemctl is-active --quiet usbguard.service", installer)
        self.assertIn("before claiming boot-time USB default-deny", installer)
        self.assertIn("/proc/cmdline", verifier)
        self.assertIn("/sys/module/usbcore/parameters/authorized_default", verifier)
        self.assertIn("systemctl is-active --quiet usbguard.service", verifier)

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

    def test_scan_guest_rejects_writable_parent_directory(self):
        image_dir = pathlib.Path("/var/lib/mk1ai/usb-scan-guest")
        writable_parent = image_dir.parent
        original_stat = pathlib.Path.stat

        def parent_stat(path, *args, **kwargs):
            if path == writable_parent:
                return mock.Mock(st_uid=0, st_mode=stat.S_IFDIR | 0o775)
            return original_stat(path, *args, **kwargs)

        with mock.patch.object(
            pathlib.Path, "stat", autospec=True, side_effect=parent_stat,
        ), self.assertRaisesRegex(ValueError, "ancestors"):
            mk1_usb_guard._verify_root_owned_directory_ancestors(image_dir)

    def test_qemu_guest_has_no_network_and_requires_one_valid_verdict(self):
        device = mock.Mock(
            is_storage=True, bus_number=1, device_number=7,
        )
        process = mock.Mock()
        process.poll.return_value = 0
        process.returncode = 0
        with mock.patch("mk1_usb_guard.verify_scan_guest", return_value={
            "kernel": pathlib.Path("/trusted/vmlinuz"),
            "initramfs": pathlib.Path("/trusted/initramfs.cpio.gz"),
        }), mock.patch("mk1_usb_guard.shutil.which", return_value="/usr/bin/qemu-system-x86_64"), \
             mock.patch("mk1_usb_guard._trusted_system_executable", return_value="/usr/bin/qemu"), \
             mock.patch("secrets.token_hex", return_value="test-nonce"), \
             mock.patch(
                 "mk1_usb_guard._read_scan_guest_channel",
                 return_value=b"MK1_SCAN_RESULT=clean\n",
             ), \
             mock.patch("mk1_usb_guard.subprocess.Popen", return_value=process) as popen:
            verdict = scan_usb_storage_in_guest(device, "/images", "/trusted.pub")

        command = popen.call_args.args[0]
        self.assertEqual(verdict, "clean")
        self.assertIn("-net", command)
        self.assertEqual(command[command.index("-net") + 1], "none")
        self.assertIn("hostbus=1,hostaddr=7", command[-1])
        self.assertNotIn("mk1.scan_nonce", command[command.index("-append") + 1])
        self.assertIn("test-nonce", command[command.index("-chardev") + 1])
        self.assertEqual(command[command.index("-serial") + 1], "chardev:scan")
        self.assertIn("-sandbox", command)

    def test_qemu_scan_rejects_invalid_or_multiple_verdict_lines(self):
        device = mock.Mock(is_storage=True, bus_number=1, device_number=7)

        def run_with_output(output):
            process = mock.Mock()
            process.poll.return_value = 0
            process.returncode = 0
            with mock.patch("mk1_usb_guard.verify_scan_guest", return_value={
                "kernel": pathlib.Path("/trusted/vmlinuz"),
                "initramfs": pathlib.Path("/trusted/initramfs.cpio.gz"),
            }), mock.patch("mk1_usb_guard.shutil.which", return_value="/usr/bin/qemu"), \
                 mock.patch("mk1_usb_guard._trusted_system_executable", return_value="/usr/bin/qemu"), \
                 mock.patch("secrets.token_hex", return_value="expected"), \
                 mock.patch("mk1_usb_guard._read_scan_guest_channel", return_value=output), \
                 mock.patch("mk1_usb_guard.subprocess.Popen", return_value=process):
                return scan_usb_storage_in_guest(device, "/images", "/trusted.pub")

        with self.assertRaisesRegex(RuntimeError, "invalid verdict"):
            run_with_output(b"MK1_SCAN_RESULT=expected:clean\n")
        with self.assertRaisesRegex(RuntimeError, "unique verdict"):
            run_with_output(
                b"MK1_SCAN_RESULT=clean\nMK1_SCAN_RESULT=clean\n",
            )

    def test_scan_guest_channel_enforces_output_limit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(listener.close)
            listener.bind(str(pathlib.Path(temp_dir) / "channel.sock"))
            listener.listen(1)
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(client.close)
            client.connect(str(pathlib.Path(temp_dir) / "channel.sock"))
            client.sendall(b"12345")
            with mock.patch("mk1_usb_guard.MAX_GUEST_OUTPUT_BYTES", 4):
                with self.assertRaisesRegex(RuntimeError, "output limit"):
                    mk1_usb_guard._read_scan_guest_channel(
                        listener,
                        mock.Mock(
                            pid=os.getpid(),
                            poll=mock.Mock(return_value=None),
                        ),
                        time.monotonic() + 1,
                    )

    def test_scan_channel_rejects_non_qemu_peer(self):
        connection = mock.Mock()
        connection.getsockopt.return_value = mk1_usb_guard.struct.pack(
            "3i",
            1234,
            os.geteuid(),
            os.getegid(),
        )
        process = mock.Mock(pid=4321)

        with self.assertRaisesRegex(RuntimeError, "not the launched QEMU"):
            mk1_usb_guard._verify_scan_channel_peer(connection, process)

    def test_scan_channel_accepts_only_launched_qemu_credentials(self):
        process = mock.Mock(pid=os.getpid())
        connection = mock.Mock()
        connection.getsockopt.return_value = mk1_usb_guard.struct.pack(
            "3i",
            os.getpid(),
            os.geteuid(),
            os.getegid(),
        )

        mk1_usb_guard._verify_scan_channel_peer(connection, process)

    def test_repeated_netlink_errors_keep_guard_enabled_and_notify_parent(self):
        enabled = threading.Event()
        enabled.set()
        fatal = mock.Mock()
        monitor = USBHotplugMonitor(
            enabled=enabled,
            stop_event=threading.Event(),
            sysfs_root="/missing/usb/sysfs",
            on_fatal=fatal,
        )

        for _ in range(3):
            monitor._recover_netlink_error("mock ENOBUFS")

        self.assertTrue(enabled.is_set())
        fatal.assert_called_once()

    def test_startup_sysfs_reconciliation_retries_and_notifies_after_repeated_failure(self):
        enabled = threading.Event()
        enabled.set()
        stop_event = threading.Event()
        fatal = mock.Mock(side_effect=lambda _reason: stop_event.set())
        monitor = USBHotplugMonitor(
            enabled=enabled,
            stop_event=stop_event,
            sysfs_root="/mock/usb/sysfs",
            on_fatal=fatal,
        )
        netlink_socket = mock.Mock()

        def stop_after_select(*_args):
            stop_event.set()
            return [], [], []

        with mock.patch("mk1_usb_guard.list_hid_devices", return_value=[]), \
             mock.patch("mk1_usb_guard.socket.socket", return_value=netlink_socket), \
             mock.patch("mk1_usb_guard.select.select", side_effect=stop_after_select), \
             mock.patch.object(monitor, "_reconcile_sysfs", return_value=False) as reconcile:
            monitor.run()

        self.assertTrue(enabled.is_set())
        self.assertGreaterEqual(reconcile.call_count, 3)
        fatal.assert_called_once()

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
            device = self.make_device(root)
            monitor = USBHotplugMonitor(
                enabled=mock.Mock(),
                stop_event=mock.Mock(),
                sysfs_root=root,
            )
            for _ in range(monitor._event_queue.maxsize):
                monitor._event_queue.put_nowait(b"")

            with mock.patch.object(monitor, "_unbind_storage_interfaces"), \
                 mock.patch("mk1_usb_guard.unbind_usb_device", return_value=True) as unbind:
                self.assertFalse(monitor._enqueue_uevent(self.add_event(device.device_id)))
            unbind.assert_called_once_with(root, device)
            self.assertIn(device.device_id, monitor._processed_devices)

    def test_hid_is_unbound_while_storage_scan_worker_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir) / "usb"
            root.mkdir()
            storage = self.make_device(root, device_id="1-2")
            hid = self.make_device(
                root, device_id="1-3", device_class="03", interface_class="03", serial="",
            )
            enabled = threading.Event()
            enabled.set()
            stopped = threading.Event()
            monitor = USBHotplugMonitor(
                enabled=enabled, stop_event=stopped, sysfs_root=root,
            )
            scan_started = threading.Event()
            release_scan = threading.Event()

            def slow_scan(*_args, **_kwargs):
                scan_started.set()
                self.assertTrue(release_scan.wait(2))
                return "clean"

            worker = threading.Thread(target=monitor._event_worker, daemon=True)
            with mock.patch("mk1_usb_guard.usb_storage_is_mounted", return_value=False), \
                 mock.patch.object(monitor, "_unbind_storage_interfaces"), \
                 mock.patch("mk1_usb_guard.scan_usb_storage_in_guest", side_effect=slow_scan), \
                 mock.patch("mk1_usb_guard.unbind_usb_device", return_value=True) as unbind:
                worker.start()
                try:
                    monitor._enqueue_uevent(self.add_event(storage.device_id))
                    self.assertTrue(scan_started.wait(2))

                    self.assertTrue(monitor._enqueue_uevent(self.add_event(hid.device_id)))
                    unbind.assert_called_once_with(root, hid)
                finally:
                    release_scan.set()
                    stopped.set()
                    worker.join(2)
                self.assertFalse(worker.is_alive())


if __name__ == "__main__":
    unittest.main()
