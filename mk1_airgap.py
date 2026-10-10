"""Fail-closed Linux logical air-gap path enumeration and disablement."""

from __future__ import annotations

import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import logging
from pathlib import Path


LOGGER = logging.getLogger("mk1.airgap")
TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
MODULES = (
    "cdc_ether",
    "rndis_host",
    "rndis_wlan",
    "cdc_ncm",
    "cdc_mbim",
    "qmi_wwan",
    "option",
    "cdc_acm",
    "cdc_wdm",
    "usbnet",
    "thunderbolt",
    "bluetooth",
    "btusb",
    "hci_uart",
)
BLACKLIST_PATH = Path("/etc/modprobe.d/mk1ai-airgap.conf")
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


def blacklist_contents() -> str:
    lines = []
    for module in MODULES:
        lines.extend((f"blacklist {module}", f"install {module} /bin/false"))
    return "\n".join(lines) + "\n"


def _module_name_from_inventory_path(path: str) -> str:
    name = Path(path).name
    for suffix in (".ko.xz", ".ko.zst", ".ko.gz", ".ko"):
        if name.endswith(suffix):
            name = name[:-len(suffix)]
            break
    return name.replace("-", "_")


class AirgapPathController:
    def __init__(
        self,
        *,
        sysfs_root: str | Path = "/sys",
        modules_root: str | Path | None = None,
        blacklist_path: str | Path = BLACKLIST_PATH,
        runner=subprocess.run,
        expected_uid: int = 0,
    ):
        self.sysfs_root = Path(sysfs_root)
        self.modules_root = Path(
            modules_root or Path("/lib/modules") / platform.release(),
        )
        self.blacklist_path = Path(blacklist_path)
        self.runner = runner
        self.expected_uid = expected_uid
        self.failures: list[str] = []
        self.report = {
            "interfaces": [],
            "rfkill_radios": [],
            "modem_devices": [],
            "thunderbolt_devices": [],
            "blacklist_installed": False,
            "modules_removed": [],
            "failures": self.failures,
            "completed": False,
            "physical_isolation": False,
        }

    def disable_all(self) -> dict:
        if self.expected_uid == 0 and (not hasattr(os, "geteuid") or os.geteuid() != 0):
            self.failures.append("root_required")
            return self.report

        self._install_blacklist()
        self._disable_interfaces()
        self._block_rfkill_radios()
        self._disable_thunderbolt()
        self._unload_prohibited_modules()
        self._disable_modem_devices()
        self.report["completed"] = not self.failures
        return self.report

    def _install_blacklist(self) -> None:
        try:
            self.blacklist_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            parent_stat = self.blacklist_path.parent.stat()
            if parent_stat.st_uid != self.expected_uid or parent_stat.st_mode & 0o022:
                raise OSError("modprobe configuration directory is not trusted")
            try:
                current_stat = self.blacklist_path.lstat()
            except FileNotFoundError:
                current_stat = None
            if current_stat is not None and (
                not stat.S_ISREG(current_stat.st_mode)
                or current_stat.st_uid != self.expected_uid
            ):
                raise OSError("modprobe blacklist is not a trusted regular file")
            descriptor, temporary = tempfile.mkstemp(
                prefix=".mk1ai-airgap-", dir=self.blacklist_path.parent,
            )
            try:
                os.fchmod(descriptor, 0o644)
                with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                    handle.write(blacklist_contents())
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.blacklist_path)
            finally:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
            final_stat = self.blacklist_path.stat()
            if (
                final_stat.st_uid != self.expected_uid
                or final_stat.st_mode & 0o022
                or self.blacklist_path.read_text(encoding="ascii") != blacklist_contents()
            ):
                raise OSError("modprobe blacklist could not be verified")
            self.report["blacklist_installed"] = True
        except OSError as exc:
            self.failures.append(f"modprobe_blacklist:{exc}")

    def _disable_interfaces(self) -> None:
        net_root = self.sysfs_root / "class/net"
        try:
            entries = sorted(net_root.iterdir(), key=lambda entry: entry.name)
        except OSError as exc:
            self.failures.append(f"network_interface_enumeration:{exc}")
            return
        ip = self._trusted_executable("ip")
        for entry in entries:
            if entry.name == "lo":
                continue
            name = entry.name
            if not INTERFACE_PATTERN.fullmatch(name):
                self.failures.append(f"invalid_network_interface:{name}")
                continue
            if ip is None:
                self.failures.append("iproute2_unavailable")
                return
            try:
                stopped = self.runner(
                    [ip, "link", "set", "dev", name, "down"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env={"PATH": TRUSTED_PATH, "HOME": "/"},
                )
                verified = self.runner(
                    [ip, "-o", "link", "show", "dev", name],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env={"PATH": TRUSTED_PATH, "HOME": "/"},
                )
            except (OSError, subprocess.SubprocessError) as exc:
                self.failures.append(f"interface_disable:{name}:{exc}")
                continue
            if stopped.returncode != 0 or verified.returncode != 0 or "state DOWN" not in verified.stdout:
                self.failures.append(f"interface_not_verified_down:{name}")
            else:
                self.report["interfaces"].append(name)

    def _block_rfkill_radios(self) -> None:
        rfkill_root = self.sysfs_root / "class/rfkill"
        try:
            radios = sorted(rfkill_root.iterdir(), key=lambda entry: entry.name)
        except OSError as exc:
            self.failures.append(f"rfkill_enumeration:{exc}")
            return
        rfkill = self._trusted_executable("rfkill")
        if radios and rfkill is None:
            self.failures.append("rfkill_tool_unavailable")
            return
        if radios:
            try:
                result = self.runner(
                    [rfkill, "block", "all"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env={"PATH": TRUSTED_PATH, "HOME": "/"},
                )
            except (OSError, subprocess.SubprocessError) as exc:
                self.failures.append(f"rfkill_block:{exc}")
                return
            if result.returncode != 0:
                self.failures.append("rfkill_block_failed")
                return
        for radio in radios:
            soft = self._read_attribute(radio / "soft")
            hard = self._read_attribute(radio / "hard")
            if soft not in {"0", "1"} or hard not in {"0", "1"}:
                self.failures.append(f"rfkill_state_unreadable:{radio.name}")
            elif soft != "1" and hard != "1":
                self.failures.append(f"rfkill_not_blocked:{radio.name}")
            else:
                self.report["rfkill_radios"].append(radio.name)
        bluetooth_root = self.sysfs_root / "class/bluetooth"
        try:
            bluetooth_devices = sorted(
                bluetooth_root.iterdir(),
                key=lambda entry: entry.name,
            )
        except OSError as exc:
            self.failures.append(f"bluetooth_enumeration:{exc}")
            return
        if bluetooth_devices and not any(
            self._read_attribute(radio / "type").lower() == "bluetooth"
            for radio in radios
        ):
            self.failures.append("bluetooth_rfkill_radio_missing")

    def _disable_thunderbolt(self) -> None:
        thunderbolt_root = self.sysfs_root / "bus/thunderbolt/devices"
        try:
            devices = sorted(thunderbolt_root.iterdir(), key=lambda entry: entry.name)
        except OSError as exc:
            self.failures.append(f"thunderbolt_enumeration:{exc}")
            return
        domains = [device for device in devices if device.name.startswith("domain")]
        for domain in domains:
            security = domain / "security"
            current = self._read_attribute(security).lower()
            if not current:
                self.failures.append(f"thunderbolt_security_unreadable:{domain.name}")
                continue
            if current != "dpon":
                try:
                    security.write_text("dpon", encoding="ascii")
                except OSError as exc:
                    self.failures.append(
                        f"thunderbolt_security_set_failed:{domain.name}:{exc}",
                    )
                    continue
            if self._read_attribute(security).lower() != "dpon":
                self.failures.append(f"thunderbolt_security_not_dpon:{domain.name}")
        for device in devices:
            if device.name.startswith("domain"):
                continue
            authorized = device / "authorized"
            if not authorized.is_file():
                self.failures.append(f"thunderbolt_authorization_unavailable:{device.name}")
                continue
            try:
                authorized.write_text("0", encoding="ascii")
            except OSError as exc:
                self.failures.append(f"thunderbolt_disable:{device.name}:{exc}")
                continue
            if self._read_attribute(authorized) != "0":
                self.failures.append(f"thunderbolt_not_disabled:{device.name}")
            else:
                self.report["thunderbolt_devices"].append(device.name)

    def _unload_prohibited_modules(self) -> None:
        builtin_file = self.modules_root / "modules.builtin"
        try:
            builtin_modules = {
                _module_name_from_inventory_path(line.strip())
                for line in builtin_file.read_text(encoding="ascii").splitlines()
                if line.strip()
            }
        except OSError as exc:
            self.failures.append(f"builtin_module_inventory:{exc}")
            return
        modprobe = self._trusted_executable("modprobe")
        for module in MODULES:
            if module in builtin_modules:
                self.failures.append(f"prohibited_module_builtin:{module}")
                continue
            module_path = self.sysfs_root / "module" / module
            if not module_path.exists():
                continue
            if modprobe is None:
                self.failures.append(f"modprobe_unavailable:{module}")
                continue
            try:
                result = self.runner(
                    [modprobe, "-r", module],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    env={"PATH": TRUSTED_PATH, "HOME": "/"},
                )
            except (OSError, subprocess.SubprocessError) as exc:
                self.failures.append(f"module_remove:{module}:{exc}")
                continue
            if result.returncode != 0 or module_path.exists():
                self.failures.append(f"module_still_available:{module}")
            else:
                self.report["modules_removed"].append(module)

    def _disable_modem_devices(self) -> None:
        class_roots = (
            ("wwan", None),
            ("usbmisc", ("cdc-wdm",)),
            ("tty", ("ttyUSB", "ttyACM")),
        )
        for class_name, prefixes in class_roots:
            root = self.sysfs_root / "class" / class_name
            try:
                devices = sorted(root.iterdir(), key=lambda entry: entry.name)
            except OSError as exc:
                self.failures.append(f"modem_enumeration:{class_name}:{exc}")
                continue
            for device in devices:
                if prefixes is not None and not device.name.startswith(prefixes):
                    continue
                self.report["modem_devices"].append(f"{class_name}/{device.name}")
                if not self._unbind_sysfs_device(device):
                    self.failures.append(f"modem_unbind_failed:{class_name}/{device.name}")
                elif device.exists():
                    self.failures.append(f"modem_still_present:{class_name}/{device.name}")

    def _unbind_sysfs_device(self, device: Path) -> bool:
        try:
            resolved = device.resolve(strict=True)
        except OSError:
            return False
        for parent in (resolved, *resolved.parents):
            driver_link = parent / "driver"
            try:
                driver = driver_link.resolve(strict=True)
                unbind = driver / "unbind"
                descriptor = os.open(unbind, os.O_WRONLY | os.O_CLOEXEC)
                try:
                    os.write(descriptor, parent.name.encode("ascii"))
                finally:
                    os.close(descriptor)
                return True
            except (OSError, UnicodeError):
                continue
        return False

    def _trusted_executable(self, name: str) -> str | None:
        discovered = shutil.which(name, path=TRUSTED_PATH)
        if discovered is None:
            return None
        try:
            resolved = Path(discovered).resolve(strict=True)
            executable_stat = resolved.stat()
            if (
                not stat.S_ISREG(executable_stat.st_mode)
                or executable_stat.st_uid != self.expected_uid
                or executable_stat.st_mode & 0o022
            ):
                return None
            for parent in resolved.parents:
                parent_stat = parent.stat()
                if parent_stat.st_uid != self.expected_uid or parent_stat.st_mode & 0o022:
                    return None
            return str(resolved)
        except OSError:
            return None

    @staticmethod
    def _read_attribute(path: Path) -> str:
        try:
            return path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError):
            return ""


def disable_all_network_paths() -> bool:
    report = AirgapPathController().disable_all()
    for failure in report["failures"]:
        LOGGER.critical("Air-gap path verification failed: %s", failure)
    return report["completed"]
