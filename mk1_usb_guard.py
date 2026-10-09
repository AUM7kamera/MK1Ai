"""Linux USB policy, signed scan-guest verification, and disposable QEMU scans."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import re
import select
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LOGGER = logging.getLogger("mk1.usb")
NETLINK_KOBJECT_UEVENT = 15
USB_DEVICE_ID = re.compile(r"^[0-9]+-[0-9]+(?:\.[0-9]+)*$")
HEX_DEVICE_ID = re.compile(r"^[0-9a-fA-F]{4}$")
SERIAL_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")
MAX_GUEST_KERNEL_BYTES = 128 * 1024 * 1024
MAX_GUEST_INITRAMFS_BYTES = 768 * 1024 * 1024
GUEST_TIMEOUT_SECONDS = 180
MAX_GUEST_OUTPUT_BYTES = 1024 * 1024
SCAN_RESULT_PREFIX = b"MK1_SCAN_RESULT="
TRUSTED_EXECUTION_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass(frozen=True)
class USBDevice:
    device_id: str
    vendor_id: str
    product_id: str
    serial: str
    bus_number: int
    device_number: int
    sysfs_path: Path
    device_class: str
    interface_classes: frozenset[str]
    is_hid: bool
    is_storage: bool
    is_hub: bool


def _trusted_system_executable(path: str, name: str) -> str:
    resolved = Path(path).resolve(strict=True)
    executable_stat = resolved.stat()
    if (
        not stat.S_ISREG(executable_stat.st_mode)
        or executable_stat.st_uid != 0
        or executable_stat.st_mode & 0o022
    ):
        raise RuntimeError(f"{name} must be a root-owned, non-writable system executable")
    for parent in resolved.parents:
        parent_stat = parent.stat()
        if parent_stat.st_uid != 0 or parent_stat.st_mode & 0o022:
            raise RuntimeError(f"{name} is located in an untrusted directory")
    return str(resolved)


def parse_uevent(message: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    for item in message.split(b"\0"):
        if b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        try:
            fields[key.decode("ascii")] = value.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
    if "ACTION" not in fields and message.startswith(b"add@"):
        fields["ACTION"] = "add"
        fields["DEVPATH"] = message[4:].decode("utf-8", errors="replace")
    return fields


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return ""


def identify_usb_device(sysfs_root: str | Path, device_id: str) -> USBDevice | None:
    if not USB_DEVICE_ID.fullmatch(device_id):
        return None
    root = Path(sysfs_root)
    device_path = root / device_id
    try:
        resolved_path = device_path.resolve(strict=True)
        resolved_root = root.resolve(strict=True)
        resolved_path.relative_to(resolved_root)
    except (OSError, ValueError):
        return None

    vendor_id = _read_text(device_path / "idVendor").lower()
    product_id = _read_text(device_path / "idProduct").lower()
    serial = _read_text(device_path / "serial")
    bus_number = _read_text(device_path / "busnum")
    device_number = _read_text(device_path / "devnum")
    if (
        not HEX_DEVICE_ID.fullmatch(vendor_id)
        or not HEX_DEVICE_ID.fullmatch(product_id)
        or not bus_number.isdigit()
        or not device_number.isdigit()
        or (serial and not SERIAL_PATTERN.fullmatch(serial))
    ):
        return None

    interfaces = list(root.glob(f"{device_id}:*/bInterfaceClass"))
    interface_classes = {_read_text(path).lower() for path in interfaces}
    device_class = _read_text(device_path / "bDeviceClass").lower()
    return USBDevice(
        device_id=device_id,
        vendor_id=vendor_id,
        product_id=product_id,
        serial=serial,
        bus_number=int(bus_number),
        device_number=int(device_number),
        sysfs_path=device_path,
        device_class=device_class,
        interface_classes=frozenset(interface_classes),
        is_hid=device_class == "03" or "03" in interface_classes,
        is_storage=device_class == "08" or "08" in interface_classes,
        is_hub=device_class == "09" and interface_classes <= {"09"},
    )


def list_hid_devices(sysfs_root: str | Path = "/sys/bus/usb/devices") -> list[USBDevice]:
    devices: list[USBDevice] = []
    for device_path in Path(sysfs_root).iterdir():
        device = identify_usb_device(sysfs_root, device_path.name)
        if device is not None and device.is_hid:
            devices.append(device)
    return sorted(devices, key=lambda device: device.device_id)


def verify_scan_guest(
    image_directory: str | Path,
    trusted_public_key: str | Path,
    *,
    openssl: str | None = None,
    require_root_owned: bool = False,
) -> dict[str, Path]:
    image_dir = Path(image_directory)
    public_key = Path(trusted_public_key)
    discovered_openssl = openssl or shutil.which("openssl", path=TRUSTED_EXECUTION_PATH)
    if discovered_openssl is None:
        raise RuntimeError("OpenSSL is required to verify the scan guest signature")
    openssl_path = _trusted_system_executable(discovered_openssl, "OpenSSL")

    image_dir_stat = image_dir.lstat()
    if (
        not stat.S_ISDIR(image_dir_stat.st_mode)
        or image_dir_stat.st_mode & 0o022
        or (require_root_owned and image_dir_stat.st_uid != 0)
    ):
        raise ValueError("Scan-guest image directory must be protected and root-owned")
    if require_root_owned:
        _verify_root_owned_directory_ancestors(image_dir)
    manifest_path = image_dir / "manifest.json"
    signature_path = image_dir / "manifest.sig"
    public_key_stat = public_key.lstat()
    if (
        not stat.S_ISREG(public_key_stat.st_mode)
        or public_key_stat.st_mode & 0o022
        or (require_root_owned and public_key_stat.st_uid != 0)
    ):
        raise ValueError("Trusted scan-guest public key must be a protected regular file")
    manifest_stat = manifest_path.lstat()
    signature_stat = signature_path.lstat()
    if (
        not stat.S_ISREG(manifest_stat.st_mode)
        or manifest_stat.st_size > 16_384
        or manifest_stat.st_mode & 0o022
        or (require_root_owned and manifest_stat.st_uid != 0)
    ):
        raise ValueError("Scan-guest manifest is invalid")
    if (
        not stat.S_ISREG(signature_stat.st_mode)
        or signature_stat.st_size > 4096
        or signature_stat.st_mode & 0o022
        or (require_root_owned and signature_stat.st_uid != 0)
    ):
        raise ValueError("Scan-guest signature is invalid")
    manifest_bytes = manifest_path.read_bytes()
    document = json.loads(manifest_bytes)
    if not isinstance(document, dict) or document.get("format") != 1:
        raise ValueError("Unsupported scan-guest manifest format")
    expected_assets = {
        "kernel": ("vmlinuz", MAX_GUEST_KERNEL_BYTES),
        "initramfs": ("initramfs.cpio.gz", MAX_GUEST_INITRAMFS_BYTES),
    }
    for name, (filename, maximum_size) in expected_assets.items():
        asset = document.get(name)
        if not isinstance(asset, dict) or asset.get("file") != filename:
            raise ValueError(f"Scan-guest {name} entry is invalid")
        digest = asset.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"Scan-guest {name} SHA-256 is invalid")
        asset_path = image_dir / filename
        asset_stat = asset_path.lstat()
        if (
            not stat.S_ISREG(asset_stat.st_mode)
            or asset_stat.st_size <= 0
            or asset_stat.st_size > maximum_size
            or asset_stat.st_mode & 0o022
            or (require_root_owned and asset_stat.st_uid != 0)
        ):
            raise ValueError(f"Scan-guest {name} image is missing or exceeds limits")
        hasher = hashlib.sha256()
        with asset_path.open("rb") as image:
            for chunk in iter(lambda: image.read(1024 * 1024), b""):
                hasher.update(chunk)
        if hasher.hexdigest() != digest:
            raise ValueError(f"Scan-guest {name} SHA-256 does not match")

    completed = subprocess.run(  # nosec B603 - 信頼済みPATH(TRUSTED_EXECUTION_PATH)で固定されたバイナリ実行
        [
            openssl_path, "pkeyutl", "-verify", "-pubin",
            "-inkey", str(public_key), "-rawin",
            "-in", str(manifest_path), "-sigfile", str(signature_path),
        ],
        check=False,
        capture_output=True,
        timeout=10,
        env={"PATH": TRUSTED_EXECUTION_PATH, "HOME": "/"},
    )
    if completed.returncode != 0:
        raise ValueError("Scan-guest manifest signature verification failed")
    return {
        "kernel": image_dir / "vmlinuz",
        "initramfs": image_dir / "initramfs.cpio.gz",
    }


def _verify_root_owned_directory_ancestors(image_dir: Path) -> None:
    for parent in image_dir.parents:
        parent_stat = parent.stat()
        if parent_stat.st_uid != 0 or parent_stat.st_mode & 0o022:
            raise ValueError(
                "Scan-guest image directory ancestors must be root-owned and non-writable"
            )


def unbind_usb_device(sysfs_root: str | Path, device: USBDevice) -> bool:
    root = Path(sysfs_root).resolve()
    usb_driver = root.parent / "drivers" / "usb"
    unbind_path = usb_driver / "unbind"
    try:
        resolved_device = device.sysfs_path.resolve(strict=True)
        resolved_device.relative_to(root)
        if not USB_DEVICE_ID.fullmatch(device.device_id):
            return False
        if _read_text(resolved_device / "idVendor").lower() != device.vendor_id:
            return False
        if _read_text(resolved_device / "idProduct").lower() != device.product_id:
            return False
        if _read_text(resolved_device / "serial") != device.serial:
            return False
        if _read_text(resolved_device / "busnum") != str(device.bus_number):
            return False
        if _read_text(resolved_device / "devnum") != str(device.device_number):
            return False
        descriptor = os.open(unbind_path, os.O_WRONLY | os.O_CLOEXEC)
        try:
            os.write(descriptor, device.device_id.encode("ascii"))
        finally:
            os.close(descriptor)
        return True
    except OSError:
        LOGGER.exception("Could not disconnect USB device %s", device.device_id)
        return False


def usb_storage_is_mounted(
    device: USBDevice,
    *,
    block_root: str | Path = "/sys/class/block",
    mountinfo_path: str | Path = "/proc/self/mountinfo",
) -> bool:
    usb_path = device.sysfs_path.resolve()
    usb_block_devices: set[str] = set()
    for block_link in Path(block_root).iterdir():
        try:
            block_path = block_link.resolve(strict=True)
            block_path.relative_to(usb_path)
        except (OSError, ValueError):
            continue
        major_minor = _read_text(block_path / "dev")
        if major_minor:
            usb_block_devices.add(major_minor)
    if not usb_block_devices:
        return False
    with Path(mountinfo_path).open("r", encoding="ascii") as mountinfo:
        for line in mountinfo:
            fields = line.split()
            if len(fields) > 2 and fields[2] in usb_block_devices:
                return True
    return False


def scan_usb_storage_in_guest(
    device: USBDevice,
    image_directory: str | Path,
    trusted_public_key: str | Path,
    *,
    qemu_binary: str | None = None,
    timeout_seconds: int = GUEST_TIMEOUT_SECONDS,
    stop_event: Any = None,
) -> str:
    if not device.is_storage:
        raise ValueError("Only USB mass-storage devices can be scanned")
    if stop_event is not None and stop_event.is_set():
        raise RuntimeError("USB scan guest was cancelled before launch")
    images = verify_scan_guest(
        image_directory, trusted_public_key, require_root_owned=True,
    )
    discovered_qemu = qemu_binary or shutil.which(
        "qemu-system-x86_64", path=TRUSTED_EXECUTION_PATH,
    )
    if discovered_qemu is None:
        raise RuntimeError("qemu-system-x86_64 is not installed")
    qemu = _trusted_system_executable(discovered_qemu, "QEMU")
    scan_nonce = secrets.token_hex(16)
    command = [
        qemu,
        "-nodefaults",
        "-no-user-config",
        "-machine", "q35,accel=kvm",
        "-m", "2048",
        "-smp", "1",
        "-display", "none",
        "-monitor", "none",
        "-serial", "stdio",
        "-no-reboot",
        "-net", "none",
        "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        "-kernel", str(images["kernel"]),
        "-initrd", str(images["initramfs"]),
        "-append", f"console=ttyS0 rdinit=/init panic=1 mk1.scan_nonce={scan_nonce}",
        "-device", "qemu-xhci,id=usb",
        "-device", f"usb-host,hostbus={device.bus_number},hostaddr={device.device_number}",
    ]
    process = subprocess.Popen(  # nosec B603 - 信頼済みPATH(TRUSTED_EXECUTION_PATH)で固定されたバイナリ実行
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        env={"PATH": TRUSTED_EXECUTION_PATH, "HOME": "/"},
    )
    if process.stdout is None:
        process.kill()
        process.wait()
        raise RuntimeError("Disposable scan guest output pipe was not created")
    deadline = time.monotonic() + timeout_seconds
    output = bytearray()
    output_exceeded_limit = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or (stop_event is not None and stop_event.is_set()):
                raise RuntimeError("USB scan guest timed out or was cancelled")
            readable, _, _ = select.select(
                [process.stdout], [], [], min(0.25, remaining),
            )
            if readable:
                chunk = os.read(
                    process.stdout.fileno(),
                    min(65_536, MAX_GUEST_OUTPUT_BYTES + 1 - len(output)),
                )
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_GUEST_OUTPUT_BYTES:
                    output_exceeded_limit = True
                    process.kill()
                    break
            elif process.poll() is not None:
                break
        if output_exceeded_limit:
            raise RuntimeError("Disposable scan guest exceeded its output limit")
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return_code = process.returncode
    reports = [
        line
        for line in bytes(output).splitlines()
        if line.startswith(SCAN_RESULT_PREFIX)
    ]
    if return_code != 0 or len(reports) != 1:
        raise RuntimeError("Disposable scan guest failed or returned no unique verdict")
    expected_prefix = SCAN_RESULT_PREFIX + scan_nonce.encode("ascii") + b":"
    if not reports[0].startswith(expected_prefix):
        raise RuntimeError("Disposable scan guest returned a mismatched nonce")
    verdict_bytes = reports[0][len(expected_prefix):]
    try:
        verdict = verdict_bytes.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise RuntimeError("Disposable scan guest returned an invalid verdict") from exc
    if verdict not in {"clean", "threat", "error"}:
        raise RuntimeError("Disposable scan guest returned an invalid verdict")
    return verdict


def disable_network_interfaces(interfaces: list[str]) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    targets = [
        name for name in dict.fromkeys(interfaces)
        if isinstance(name, str)
        and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name)
        and name != "lo"
    ]
    if not targets:
        return False
    try:
        discovered_ip = shutil.which("ip", path=TRUSTED_EXECUTION_PATH)
        if discovered_ip is None:
            LOGGER.error("iproute2 is unavailable; refusing unverified network isolation")
            return False
        ip_binary = _trusted_system_executable(discovered_ip, "iproute2")
        results = []
        for name in targets:
            try:
                disabled = subprocess.run(  # nosec B603 - 信頼済みPATH(TRUSTED_EXECUTION_PATH)で固定されたバイナリ実行
                    [ip_binary, "link", "set", "dev", name, "down"],
                    check=False, capture_output=True, text=True, timeout=5,
                    env={"PATH": TRUSTED_EXECUTION_PATH, "HOME": "/"},
                )
                if disabled.returncode != 0:
                    LOGGER.error(
                        "iproute2 could not disable interface %s: %s",
                        name, disabled.stderr.strip(),
                    )
                    results.append(False)
                    continue
                verified = subprocess.run(  # nosec B603 - 信頼済みPATH(TRUSTED_EXECUTION_PATH)で固定されたバイナリ実行
                    [ip_binary, "-o", "link", "show", "dev", name],
                    check=False, capture_output=True, text=True, timeout=5,
                    env={"PATH": TRUSTED_EXECUTION_PATH, "HOME": "/"},
                )
                flags = re.search(r"<([^>]*)>", verified.stdout)
                results.append(
                    verified.returncode == 0
                    and flags is not None
                    and "UP" not in flags.group(1).split(",")
                )
                if not results[-1]:
                    LOGGER.error("iproute2 could not verify interface %s is down", name)
            except (OSError, subprocess.SubprocessError):
                LOGGER.exception("iproute2 network isolation failed for %s", name)
                results.append(False)
        return all(results)
    except (OSError, RuntimeError):
        LOGGER.exception("Could not initialize trusted iproute2 network isolation")
        return False


class USBHotplugMonitor:
    """Monitors kernel uevents and delegates every untrusted device to policy."""

    def __init__(
        self,
        *,
        enabled: threading.Event,
        stop_event: threading.Event,
        sysfs_root: str | Path = "/sys/bus/usb/devices",
        image_directory: str | Path = "/var/lib/mk1ai/usb-scan-guest",
        trusted_public_key: str | Path = "/etc/mk1ai/usb-scan-signing.pub",
        qemu_binary: str | None = None,
        on_threat: Any = None,
        on_fatal: Any = None,
        baseline_allow: bool | None = None,
    ) -> None:
        self.enabled = enabled
        self.stop_event = stop_event
        self.sysfs_root = Path(sysfs_root)
        self.image_directory = Path(image_directory)
        self.trusted_public_key = Path(trusted_public_key)
        self.qemu_binary = qemu_binary
        self.on_threat = on_threat
        self.on_fatal = on_fatal
        self.baseline_allow = (
            os.environ.get("MK1_USB_BASELINE_ALLOW") == "1"
            if baseline_allow is None else baseline_allow
        )
        self._processed_devices: set[str] = set()
        self._processed_devices_lock = threading.Lock()
        self._event_queue: queue.Queue[bytes] = queue.Queue(maxsize=64)
        self._netlink_resync_failures = 0

    def run(self) -> None:
        monitor: socket.socket | None = None
        baseline_checked = False
        worker_thread = threading.Thread(
            target=self._event_worker, name="mk1-usb-policy", daemon=True,
        )
        worker_thread.start()
        while not self.stop_event.is_set():
            if not self.enabled.is_set():
                if monitor is not None:
                    monitor.close()
                    monitor = None
                baseline_checked = False
                self._drain_event_queue()
                with self._processed_devices_lock:
                    self._processed_devices.clear()
                self.stop_event.wait(0.25)
                continue
            if not baseline_checked:
                baseline_checked = True
                try:
                    existing_hids = list_hid_devices(self.sysfs_root)
                except OSError:
                    self._recover_netlink_error("USB baseline enumeration failed")
                    existing_hids = []
                if existing_hids:
                    LOGGER.warning(
                        "USB guard found %d pre-existing HID device(s); baseline unbind may "
                        "lock out local input devices",
                        len(existing_hids),
                    )
                    if not self.baseline_allow:
                        self._notify_fatal(
                            "USB guard refused to unbind pre-existing HID devices; "
                            "set MK1_USB_BASELINE_ALLOW=1 to opt in",
                        )
                        break
            if monitor is None:
                try:
                    monitor = socket.socket(
                        socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_KOBJECT_UEVENT,
                    )
                    monitor.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262_144)
                    monitor.bind((os.getpid(), 1))
                    monitor.setblocking(False)
                    LOGGER.info("USB uevent monitor started; reconciling current devices")
                    if not self._reconcile_sysfs():
                        monitor.close()
                        monitor = None
                        self._recover_netlink_error(
                            "USB startup sysfs reconciliation failed",
                        )
                        self.stop_event.wait(0.25)
                        continue
                except OSError:
                    LOGGER.exception("Could not start the Linux USB uevent monitor")
                    if monitor is not None:
                        monitor.close()
                    monitor = None
                    self._recover_netlink_error("USB uevent socket creation failed")
                    self.stop_event.wait(0.25)
                    continue
            try:
                readable, _, _ = select.select([monitor], [], [], 0.25)
                if readable:
                    self._enqueue_uevent(monitor.recv(16_384))
            except (OSError, ValueError):
                if self.stop_event.is_set():
                    break
                LOGGER.exception("USB uevent monitor failed")
                if monitor is not None:
                    monitor.close()
                    monitor = None
                self._recover_netlink_error("USB uevent receive failed")
        if monitor is not None:
            monitor.close()
        worker_thread.join(timeout=5)
        if worker_thread.is_alive():
            LOGGER.error("USB policy worker did not stop")

    def _notify_fatal(self, reason: str) -> None:
        LOGGER.critical("%s", reason)
        if self.on_fatal is not None:
            self.on_fatal(reason)

    def _recover_netlink_error(self, reason: str) -> None:
        LOGGER.error("%s; re-enumerating USB devices from sysfs", reason)
        if self._reconcile_sysfs():
            self._netlink_resync_failures = 0
            return
        self._netlink_resync_failures += 1
        LOGGER.error(
            "USB sysfs re-enumeration failed (%d consecutive failure(s))",
            self._netlink_resync_failures,
        )
        if self._netlink_resync_failures >= 3:
            self._notify_fatal(
                "USB policy cannot re-enumerate sysfs after repeated netlink errors",
            )

    def _reconcile_sysfs(self) -> bool:
        try:
            devices = list(self.sysfs_root.iterdir())
            for device_path in devices:
                if identify_usb_device(self.sysfs_root, device_path.name) is not None:
                    event = (
                        "ACTION=add\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0"
                        f"DEVPATH=/sys/bus/usb/devices/{device_path.name}\0"
                    ).encode("ascii")
                    self._enqueue_uevent(event)
        except OSError:
            LOGGER.exception("Could not enumerate USB sysfs devices")
            return False
        return True

    def _event_worker(self) -> None:
        while not self.stop_event.is_set():
            try:
                message = self._event_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            if not self.enabled.is_set():
                continue
            try:
                self.handle_uevent(message)
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
                LOGGER.exception("USB policy failed; attempting immediate device unbind")
                self._fail_closed_uevent(message, "USB policy processing failed")

    def _enqueue_uevent(self, message: bytes) -> bool:
        event = parse_uevent(message)
        if (
            event.get("SUBSYSTEM") != "usb"
            or event.get("DEVTYPE") != "usb_device"
            or event.get("ACTION") not in {"add", "remove"}
        ):
            return True
        if event.get("ACTION") == "remove":
            self.handle_uevent(message)
            return True
        device_id = Path(event.get("DEVPATH", "")).name
        device = identify_usb_device(self.sysfs_root, device_id)
        if device is None or device.is_hub or device.is_hid or not device.is_storage:
            try:
                self.handle_uevent(message)
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
                LOGGER.exception("Immediate USB policy failed; attempting emergency unbind")
                self._fail_closed_uevent(message, "immediate USB policy processing failed")
                return False
            return True
        try:
            self._event_queue.put_nowait(message)
            return True
        except queue.Full:
            LOGGER.critical("USB policy queue is full; immediately unbinding the new device")
            self._fail_closed_uevent(message, "USB policy queue overflow")
            return False

    def _drain_event_queue(self) -> None:
        while True:
            try:
                self._event_queue.get_nowait()
            except queue.Empty:
                return

    def _fail_closed_uevent(self, message: bytes, reason: str) -> None:
        event = parse_uevent(message)
        if (
            event.get("ACTION") != "add"
            or event.get("SUBSYSTEM") != "usb"
            or event.get("DEVTYPE") != "usb_device"
        ):
            return
        device_id = Path(event.get("DEVPATH", "")).name
        device = identify_usb_device(self.sysfs_root, device_id)
        if device is None or device.is_hub:
            LOGGER.critical("Unable to identify USB device for emergency isolation")
            return
        with self._processed_devices_lock:
            self._processed_devices.add(device_id)
        if device.is_storage:
            self._unbind_storage_interfaces(device)
        self._unbind(device, reason)

    def handle_uevent(self, message: bytes) -> str:
        event = parse_uevent(message)
        if event.get("SUBSYSTEM") != "usb" or event.get("DEVTYPE") != "usb_device":
            return "ignored"
        device_id = Path(event.get("DEVPATH", "")).name
        if event.get("ACTION") == "remove":
            with self._processed_devices_lock:
                self._processed_devices.discard(device_id)
            return "removed"
        with self._processed_devices_lock:
            already_processed = device_id in self._processed_devices
        if event.get("ACTION") != "add" or already_processed:
            return "ignored"
        device = identify_usb_device(self.sysfs_root, device_id)
        if device is None:
            LOGGER.critical("Could not identify USB device reported by kernel: %s", device_id)
            return "invalid"
        with self._processed_devices_lock:
            if device_id in self._processed_devices:
                return "ignored"
            self._processed_devices.add(device_id)
        if device.is_hub:
            return "hub_ignored"

        if device.is_hid and (
            device.device_class not in {"00", "03"}
            or device.interface_classes - {"03"}
        ):
            return self._unbind(device, "composite or non-HID interface is not permitted")
        if device.is_hid:
            return self._unbind(
                device,
                "USB HID devices are blocked because descriptors do not authenticate device identity",
            )

        if device.is_storage:
            try:
                mounted = usb_storage_is_mounted(device)
            except OSError:
                LOGGER.exception("Could not verify whether USB storage is mounted")
                mounted = True
            if mounted:
                self._unbind_storage_interfaces(device)
                return self._unbind(device, "USB storage was already mounted on the host")
            self._unbind_storage_interfaces(device)
            try:
                mounted_after_detach = usb_storage_is_mounted(device)
            except OSError:
                LOGGER.exception("Could not recheck USB mount state after detaching its driver")
                mounted_after_detach = True
            if mounted_after_detach:
                return self._unbind(
                    device, "USB storage remained mounted after host driver detach",
                )
            try:
                current_device = identify_usb_device(self.sysfs_root, device.device_id)
                if current_device is None or current_device != device:
                    raise RuntimeError("USB identity changed before guest scan")
                verdict = scan_usb_storage_in_guest(
                    current_device,
                    self.image_directory,
                    self.trusted_public_key,
                    qemu_binary=self.qemu_binary,
                    stop_event=self.stop_event,
                )
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
                LOGGER.exception("USB MicroVM scan failed; USB device will be blocked")
                verdict = "error"
            disconnected = unbind_usb_device(self.sysfs_root, device)
            if verdict != "clean":
                LOGGER.critical(
                    "USB storage device %s received verdict %s and was isolated",
                    device.device_id, verdict,
                )
                if self.on_threat is not None:
                    self.on_threat(device, verdict)
                if not disconnected:
                    return f"{verdict}_unbind_failed"
                return "threat" if verdict == "threat" else "scan_error_unbound"
            return "scanned_clean_unbound" if disconnected else "clean_unbind_failed"

        return self._unbind(device, "unapproved USB device class")

    def _unbind_storage_interfaces(self, device: USBDevice) -> None:
        for interface in device.sysfs_path.parent.glob(f"{device.device_id}:*"):
            driver_link = interface / "driver"
            try:
                driver = driver_link.resolve(strict=True)
                if driver.name not in {"usb-storage", "uas"}:
                    continue
                unbind_path = driver / "unbind"
                descriptor = os.open(unbind_path, os.O_WRONLY | os.O_CLOEXEC)
                try:
                    os.write(descriptor, interface.name.encode("ascii"))
                finally:
                    os.close(descriptor)
            except OSError:
                LOGGER.exception("Could not detach host storage driver from %s", interface)

    def _unbind(self, device: USBDevice, reason: str) -> str:
        disconnected = unbind_usb_device(self.sysfs_root, device)
        LOGGER.warning(
            "USB device %s blocked (%s): %s",
            device.device_id, reason, "sysfs unbind succeeded" if disconnected else "unbind failed",
        )
        return "blocked" if disconnected else "unbind_failed"


def _main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Inspect USB HID devices; the USB policy blocks all HID devices",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "list-hid",
        help="List connected HID descriptors for diagnostics; they are not trusted",
    )
    parser.parse_args()
    print("USB HID devices are always blocked; listed descriptors are not authenticated.")
    for device in list_hid_devices():
        print(
            f"{device.device_id} VID={device.vendor_id} PID={device.product_id} "
            f"serial={device.serial or '<missing>'}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
