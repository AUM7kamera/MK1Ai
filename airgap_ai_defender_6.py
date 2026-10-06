"""
airgap_ai_defender_6.py

100% 完全ローカル自律型 AI 司令塔。
外部 API を一切使わず、ローカル PyTorch チェックポイントを直接ロードし、
起動直後にデバイスプロファイルを取得、ブート時ハードニング、
リソース自律制御、AES 傾向学習、絶対防衛キルスイッチ、自己防衛スレッドを備えます。
"""

import argparse
import hashlib
import json
import logging
import math
import mmap
import re
import os
import platform
import socket
import subprocess
import sys
import tempfile
import threading
import time
import secrets
import shutil
from typing import Any

try:
    import torch
    import torch.nn as nn
except ImportError:
    torch = None

    class _DummyModule:
        def __init__(self, *_args, **_kwargs):
            del _args, _kwargs

        def __call__(self, value):
            return value

        def load_state_dict(self, _state_dict):
            del _state_dict
            return None

    class _DummyLinear(_DummyModule):
        pass

    class _DummyReLU(_DummyModule):
        pass

    class _DummySequential(_DummyModule):
        def __init__(self, *layers):
            self.layers = layers

        def __call__(self, value):
            for layer in self.layers:
                value = layer(value)
            return value

    class _DummyNN:
        Module = _DummyModule
        Linear = _DummyLinear
        ReLU = _DummyReLU
        Sequential = _DummySequential

    nn: Any = _DummyNN()

try:
    import psutil
except ImportError:
    psutil = None

try:
    import resource
except ImportError:
    resource = None


class SecurityLogger(logging.Logger):
    def warning(self, msg, *args, **kwargs):
        super().warning(self._decorate_message(msg, "WARNING"), *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        super().critical(self._decorate_message(msg, "CRITICAL"), *args, **kwargs)

    @staticmethod
    def _decorate_message(msg: str, level: str) -> str:
        prefix = {
            "WARNING": "[ANOMALY_DETECTION / THREAT_INDEX]",
            "CRITICAL": "[ACTIVE_DEFENSE / ABSOLUTE_DEFENSE]",
        }.get(level, "")
        color = "\033[1;31m" if level in {"WARNING", "CRITICAL"} else ""
        reset = "\033[0m" if color else ""
        return f"{color}{prefix} {msg}{reset}" if prefix else msg


logging.setLoggerClass(SecurityLogger)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("AirgapAI6")

_MODEL_HASH_ENV = "AIRGAP_MODEL_HASH"
_DEFAULT_SWAP_SIZE_MB = 100


def _safe_sha256(path: str) -> str | None:
    try:
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except OSError:
        return None


def _normalize_expected_hash(raw_value: str) -> str | None:
    value = (raw_value or "").strip()
    if not value:
        return None
    match = re.search(r"[A-Fa-f0-9]{64}", value)
    if match:
        return match.group(0).lower()
    return None


def _get_expected_model_hash(model_path: str) -> str | None:
    candidate = f"{model_path}.sha256"
    if os.path.exists(candidate):
        return _normalize_expected_hash(pathlib_read_text(candidate))

    explicit = os.environ.get(_MODEL_HASH_ENV, "").strip()
    if explicit:
        return _normalize_expected_hash(explicit)
    return None


def pathlib_read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _verify_model_hash(model_path: str, expected_hash: str) -> bool:
    actual = _safe_sha256(model_path)
    return actual == expected_hash if actual else False


def _validate_model_state_dict(state_dict: dict) -> bool:
    if not isinstance(state_dict, dict):
        return False
    required = {
        "shared_layer.0.weight",
        "shared_layer.0.bias",
        "shared_layer.2.weight",
        "shared_layer.2.bias",
        "head_a.weight",
        "head_a.bias",
        "head_b.weight",
        "head_b.bias",
        "head_c.weight",
        "head_c.bias",
    }
    return required.issubset(set(state_dict.keys()))


class AbsoluteDefenseModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.shared_layer = nn.Sequential(
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
        )
        self.head_a = nn.Linear(32, 1)
        self.head_b = nn.Linear(32, 1)
        self.head_c = nn.Linear(32, 1)

    def forward(self, x):
        if torch is None:
            raise RuntimeError("PyTorch is required for model inference")
        shared = self.shared_layer(x)
        return {
            "head_a": torch.sigmoid(self.head_a(shared)).squeeze(-1),
            "head_b": torch.sigmoid(self.head_b(shared)).squeeze(-1),
            "head_c": torch.sigmoid(self.head_c(shared)).squeeze(-1),
        }


def load_local_model(model, model_path: str) -> bool:
    if torch is None:
        log.warning("[MODEL] PyTorch が見つかりません。ローカルモデルをロードできません。")
        return False

    if not os.path.exists(model_path):
        log.warning(f"[MODEL] ローカルモデルが見つかりません: {model_path}")
        return False

    expected_hash = _get_expected_model_hash(model_path)
    if not expected_hash:
        log.warning("[MODEL] 期待されるモデルハッシュが設定されていません。ロードを拒否します。")
        return False
    if not _verify_model_hash(model_path, expected_hash):
        log.warning("[MODEL] モデルハッシュが一致しません。ロードを中止します。")
        return False

    device = torch.device("cpu")
    if hasattr(torch, "cuda") and torch.cuda.is_available():
        try:
            device = torch.device("cuda:0")
        except Exception:
            device = torch.device("cpu")

    load_kwargs = {"map_location": device, "weights_only": True}
    try:
        loaded = torch.load(model_path, **load_kwargs)
    except TypeError:
        try:
            loaded = torch.load(model_path, map_location=device)
        except Exception as exc:
            log.warning(f"[MODEL] ローカルモデルのロードに失敗しました: {exc}")
            return False
    except Exception as exc:
        log.warning(f"[MODEL] ローカルモデルのロードに失敗しました: {exc}")
        return False
    if isinstance(loaded, dict) and "state_dict" in loaded:
        state_dict = loaded["state_dict"]
    elif isinstance(loaded, dict) and "model_state_dict" in loaded:
        state_dict = loaded["model_state_dict"]
    else:
        state_dict = loaded

    if not _validate_model_state_dict(state_dict):
        log.warning("[MODEL] ロードした state_dict が想定構造と一致しません。")
        return False

    model.load_state_dict(state_dict)
    log.info("[MODEL] ローカルモデルを正常にロードしました。完全ローカル運用を開始します。")
    return True


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for cnt in counts:
        if cnt:
            p = cnt / length
            entropy -= p * math.log2(p)
    return entropy


def detect_aes_pattern(packet_bytes: bytes) -> dict:
    length = len(packet_bytes)
    if length < 32:
        return {"aes_candidate": False, "score": 0.0, "entropy": 0.0, "mode": None}

    entropy = _shannon_entropy(packet_bytes[:min(length, 256)])
    iv_entropy = _shannon_entropy(packet_bytes[:16])
    iv_unusual = iv_entropy > 3.8 and length % 16 == 0
    score = min(1.0, max(0.0, (entropy - 6.5) / 1.5 + (0.2 if iv_unusual else 0.0)))
    if length >= 48:
        if packet_bytes[0:16] == packet_bytes[16:32]:
            score += 0.1
    mode = "gcm" if b"GCM" in packet_bytes[:64] else "cbc"
    return {
        "aes_candidate": score >= 0.65,
        "score": min(score, 1.0),
        "entropy": entropy,
        "mode": mode,
        "iv_entropy": iv_entropy,
    }


def analyze_packet_security(packet_bytes: bytes, src_ip: str = "", dst_ip: str = "") -> dict:
    aes = detect_aes_pattern(packet_bytes)
    jitter = 0.0
    if len(packet_bytes) > 0:
        jitter = float(sum(packet_bytes[i] ^ packet_bytes[-1] for i in range(min(len(packet_bytes), 8)))) / 256.0
    ratio = len([b for b in packet_bytes if b < 32 or b > 127]) / max(1, len(packet_bytes))
    behavior = "benign"
    if aes["aes_candidate"] and ratio > 0.6:
        behavior = "encrypted_c2"
    elif aes["entropy"] > 7.2 and ratio > 0.75:
        behavior = "high_entropy_payload"
    return {
        "aes": aes,
        "jitter": jitter,
        "binary_ratio": ratio,
        "behavior": behavior,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }


def discover_available_interfaces() -> list:
    result = []
    sysfs_dir = "/sys/class/net"
    try:
        for name in sorted(os.listdir(sysfs_dir)):
            if name == "lo":
                continue
            if os.path.isdir(os.path.join(sysfs_dir, name)):
                result.append(name)
    except OSError:
        pass
    return result


def profile_environment() -> dict:
    profile = {
        "timestamp": time.time(),
        "hostname": socket.gethostname(),
        "os": {},
        "cpu": {},
        "memory": {},
        "storage": {},
        "available_interfaces": discover_available_interfaces(),
        "network_layers": [],
        "tools": {},
        "permissions": {},
    }
    profile["os"] = {
        "system": platform.system() or "unknown",
        "release": platform.release() or "",
        "version": platform.version() or "",
        "machine": platform.machine() or "",
    }
    profile["cpu"]["cores"] = os.cpu_count() or 1
    if psutil:
        try:
            profile["memory"] = {
                "total_mb": int(psutil.virtual_memory().total / 1024 / 1024),
                "available_mb": int(psutil.virtual_memory().available / 1024 / 1024),
            }
        except Exception:
            profile["memory"] = {"total_mb": 0, "available_mb": 0}
    else:
        profile["memory"] = {"total_mb": 0, "available_mb": 0}
    try:
        total, _, free = shutil.disk_usage(".")
        profile["storage"] = {
            "total_mb": int(total / 1024 / 1024),
            "free_mb": int(free / 1024 / 1024),
        }
    except Exception:
        profile["storage"] = {"total_mb": 0, "free_mb": 0}
    for iface in profile["available_interfaces"]:
        if iface.startswith(("eth", "en", "wlan")):
            profile["network_layers"].append("physical")
        if iface.startswith(("veth", "docker", "br", "virbr", "tun", "tap")):
            profile["network_layers"].append("virtual")
        if iface.startswith("wg") or "wg" in iface or "tailscale" in iface:
            profile["network_layers"].append("vpn")
    profile["network_layers"] = sorted(set(profile["network_layers"]))
    for tool_name in ("ip", "iptables", "nft", "route"):
        profile["tools"][tool_name] = shutil.which(tool_name) is not None
    profile["permissions"]["root"] = getattr(os, "geteuid", lambda: 0)() == 0
    profile["permissions"]["sudo"] = shutil.which("sudo") is not None
    log.info("[PROFILE] デバイスプロファイルを取得しました。")
    log.info(json.dumps(profile, indent=2, ensure_ascii=False))
    return profile


def _write_sysctl(path: str, value: str) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(value)
        return True
    except Exception as exc:
        log.warning(f"[BOOT_HARDENING] sysctl の書き込みに失敗しました: {path} ({exc})")
        return False


def _apply_kernel_hardening(report: dict):
    mappings = {
        "/proc/sys/net/ipv4/ip_forward": "0",
        "/proc/sys/net/ipv4/tcp_syncookies": "1",
        "/proc/sys/net/ipv4/conf/all/rp_filter": "1",
        "/proc/sys/net/ipv4/conf/default/rp_filter": "1",
        "/proc/sys/net/ipv4/conf/all/accept_source_route": "0",
        "/proc/sys/net/ipv4/conf/default/accept_source_route": "0",
        "/proc/sys/kernel/sysrq": "0",
        "/proc/sys/vm/swappiness": "10",
        "/proc/sys/vm/overcommit_memory": "2",
        "/proc/sys/fs/suid_dumpable": "0",
    }
    for path, value in mappings.items():
        if os.path.exists(path) and _write_sysctl(path, value):
            report["applied"].append(path)
        else:
            report["failures"].append(path)


def _apply_process_limits(report: dict):
    if resource is None:
        report["failures"].append("resource_module_missing")
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target_soft = min(soft if soft > 0 else hard, 4096)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target_soft, hard))
        report["applied"].append("rlimit_nofile")
    except Exception as exc:
        log.warning(f"[BOOT_HARDENING] RLIMIT_NOFILE 設定失敗 ({exc})")
        report["failures"].append("rlimit_nofile")
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
        if soft > 512 or soft == resource.RLIM_INFINITY:
            resource.setrlimit(resource.RLIMIT_NPROC, (512, hard))
        report["applied"].append("rlimit_nproc")
    except Exception as exc:
        log.warning(f"[BOOT_HARDENING] RLIMIT_NPROC 設定失敗 ({exc})")
        report["failures"].append("rlimit_nproc")


def boot_time_auto_hardening(profile: dict) -> dict:
    report = {"applied": [], "failures": []}
    if profile.get("permissions", {}).get("root"):
        log.info("[BOOT_HARDENING] ブート時自動最適化を開始します。")
        _apply_kernel_hardening(report)
        _apply_process_limits(report)
    else:
        log.warning("[BOOT_HARDENING] root 権限なし。安全設定の一部をスキップします。")
        report["failures"].append("missing_root")
    log.info(f"[BOOT_HARDENING] 適用: {report['applied']} 失敗: {report['failures']}")
    return report


def _run_command(cmd: list[str], dry_run: bool = False) -> bool:
    if dry_run:
        log.warning(f"[COMMAND] Dry-Run: {cmd}")
        return True
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception as exc:
        log.warning(f"[COMMAND] 実行失敗: {cmd} ({exc})")
        return False


def generate_absolute_defense_payload(profile: dict) -> dict:
    commands = []
    for iface in profile.get("available_interfaces", []):
        commands.append(["ip", "link", "set", iface, "down"])
    if profile.get("tools", {}).get("ip"):
        commands.append(["ip", "route", "replace", "default", "unreachable"])
        commands.append(["ip", "route", "add", "default", "unreachable"])
    if profile.get("tools", {}).get("iptables"):
        commands.extend([
            ["iptables", "-F"],
            ["iptables", "-P", "INPUT", "DROP"],
            ["iptables", "-P", "OUTPUT", "DROP"],
            ["iptables", "-P", "FORWARD", "DROP"],
        ])
    if profile.get("tools", {}).get("nft"):
        commands.append(["nft", "flush", "ruleset"])
    return {"commands": commands, "profile": profile}


def _is_suspicious_process(proc) -> bool:
    try:
        if proc.pid == os.getpid():
            return False
        name = (proc.name() or "").lower()
        cmdline = proc.cmdline() or []
        cmdline_text = " ".join(cmdline)
        protected_names = {
            "systemd",
            "init",
            "kthreadd",
            "ksoftirqd",
            "kworker",
            "dbus-daemon",
            "sshd",
            "cron",
            "crond",
            "rsyslogd",
            "systemd-journald",
            "systemd-logind",
            "NetworkManager",
            "docker",
            "containerd",
            "nginx",
            "apache2",
            "httpd",
            "mysqld",
            "postgres",
            "snapd",
            "polkitd",
        }
        if name in protected_names:
            return False
        if "(deleted)" in cmdline_text:
            if proc.pid == 1 or proc.ppid() == 1:
                return False
            return True
        if proc.pid != os.getpid() and name in {"bash", "sh", "python", "perl"}:
            return False
    except Exception:
        return False
    return False


def _kill_suspicious_processes(dry_run: bool = False) -> int:
    count = 0
    if psutil is None:
        return count
    for proc in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        if _is_suspicious_process(proc):
            try:
                if dry_run:
                    log.warning(f"[SELF_DEFENSE] Dry-Run: SIGKILL {proc.pid}")
                else:
                    proc.kill()
                count += 1
            except Exception as exc:
                log.warning(f"[SELF_DEFENSE] プロセス SIGKILL に失敗 {proc.pid} ({exc})")
    return count


def execute_kill_switch(interface: str, dry_run: bool, profile: dict | None = None) -> bool:
    if profile is None:
        profile = profile_environment()
    payload = generate_absolute_defense_payload(profile)
    log.critical(f"[KILL_SWITCH] キルスイッチを発動します: interface={interface}")
    success = True
    for cmd in payload["commands"]:
        if not _run_command(cmd, dry_run=dry_run):
            success = False
    if _kill_suspicious_processes(dry_run=dry_run) > 0:
        log.warning("[KILL_SWITCH] 不審プロセスを先制遮断しました。")
    return success


class MemoryManager:
    def __init__(self, max_memory_mb: int = 512, swap_dir: str = "./swap"):
        self.max_bytes = max_memory_mb * 1024 * 1024
        self.swap_dir = swap_dir
        self.process = psutil.Process(os.getpid()) if psutil else None
        os.makedirs(swap_dir, exist_ok=True)
        try:
            os.chmod(swap_dir, 0o700)
        except Exception:
            pass
        swap_fd, self.swap_path = tempfile.mkstemp(prefix="vm_swap_", suffix=".bin", dir=swap_dir)
        try:
            os.fchmod(swap_fd, 0o600)
        except Exception:
            pass
        self.swap_fd = os.fdopen(swap_fd, "r+b")
        self.swap_fd.truncate(_DEFAULT_SWAP_SIZE_MB * 1024 * 1024)
        self.mmap = mmap.mmap(self.swap_fd.fileno(), 0)
        self.offset = 0
        self.is_critical = False
        self._ema_ratio = 0.0
        self._ema_alpha = 0.2
        self._lock = threading.Lock()
        self._swap_key = secrets.token_bytes(32)
        log.info(f"[MEMORY] MemoryManager 起動: {max_memory_mb}MB, swap={self.swap_path}")

    def get_usage_ratio(self) -> float:
        if self.process is None:
            return 0.0
        rss = self.process.memory_info().rss
        ratio = rss / float(self.max_bytes)
        self._ema_ratio = self._ema_alpha * ratio + (1.0 - self._ema_alpha) * self._ema_ratio
        return self._ema_ratio

    def check(self, head_c_score: float = 0.0) -> float:
        ratio = self.get_usage_ratio()
        self.is_critical = ratio > 0.92 or (ratio > 0.80 and head_c_score > 0.65)
        if head_c_score > 0.75:
            self.is_critical = True
        if self.is_critical:
            log.warning(f"[MEMORY] Head C 先制退避: ratio={ratio:.2f}, score={head_c_score:.2f}")
        return ratio

    @property
    def should_preemptive_evict(self) -> bool:
        return self.is_critical

    def _xor_encrypt(self, data: bytes) -> bytes:
        return bytes(b ^ self._swap_key[i % len(self._swap_key)] for i, b in enumerate(data))

    def evict_buffer(self, data: list) -> int:
        if not data:
            return 0
        blob = (json.dumps(data) + "\n").encode("utf-8")
        encrypted = self._xor_encrypt(blob)
        with self._lock:
            if len(encrypted) >= len(self.mmap):
                return 0
            if self.offset + len(encrypted) >= len(self.mmap):
                self.offset = 0
                log.warning("[MEMORY] swap 領域が循環したため位置をリセットしました。")
            self.mmap.seek(self.offset)
            self.mmap.write(encrypted)
            self.offset += len(encrypted)
        log.warning(f"[MEMORY] {len(data)} 件のバッファを暗号化してストレージへ退避しました。")
        return len(data)

    def cleanup(self):
        with self._lock:
            try:
                self.mmap.close()
                self.swap_fd.close()
            except Exception:
                pass
        try:
            os.unlink(self.swap_path)
        except OSError:
            pass


class SelfProtection:
    def __init__(self, model_path: str, interface: str, dry_run: bool = True):
        self.model_path = model_path
        self.interface = interface
        self.dry_run = dry_run
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.base_hash = self._compute_self_hash()

    def _compute_self_hash(self) -> str | None:
        script_path = None
        if "__file__" in globals():
            script_path = os.path.abspath(__file__)
        elif len(sys.argv) > 0:
            script_path = os.path.abspath(sys.argv[0])
        if script_path and os.path.exists(script_path):
            return _safe_sha256(script_path)
        return None

    def _check_integrity(self) -> bool:
        new_hash = self._compute_self_hash()
        if self.base_hash and new_hash and new_hash != self.base_hash:
            log.critical("[SELF_DEFENSE] 実行ファイルが改ざんされました 防衛を発動します。")
            return False
        return True

    def _monitor_loop(self):
        while not self.stop_event.wait(2.0):
            state_ok = self._check_integrity()
            if not state_ok:
                execute_kill_switch(self.interface, dry_run=self.dry_run)
                break
            if os.name == "posix":
                try:
                    with open(f"/proc/{os.getpid()}/status", "r", encoding="utf-8") as handle:
                        text = handle.read()
                    if "State:\tT" in text or "State:\tZ" in text:
                        log.critical("[SELF_DEFENSE] プロセス状態が停止またはゾンビになりました。即時隔離します。")
                        execute_kill_switch(self.interface, dry_run=self.dry_run)
                        break
                except Exception:
                    pass
        log.info("[SELF_DEFENSE] 監視スレッドを終了します。")

    def start(self):
        self.thread.start()
        log.info("[SELF_DEFENSE] 自己防衛監視を開始しました。")

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=5.0)


def main() -> int:
    parser = argparse.ArgumentParser(description="airgap_ai_defender_6: 完全ローカルAI防御司令塔")
    parser.add_argument("--model-path", default="./cloud_base_model.pth", help="ローカルPyTorchモデルのパス")
    parser.add_argument("--interface", default="eth0", help="主要監視インターフェース")
    parser.add_argument("--swap-dir", default="./swap", help="仮想メモリ/暗号化スワップ領域")
    parser.add_argument("--dry-run", action="store_true", help="実際の隔離コマンドを実行しない")
    args = parser.parse_args()

    model = AbsoluteDefenseModel()
    load_local_model(model, args.model_path)

    profile = profile_environment()
    boot_time_auto_hardening(profile)

    memory_manager = MemoryManager(max_memory_mb=512, swap_dir=args.swap_dir)
    self_defense = SelfProtection(args.model_path, args.interface, dry_run=args.dry_run)
    self_defense.start()

    try:
        cycle_data = ["initialization", "hardening", "monitoring"]
        ratio = memory_manager.check(head_c_score=0.5)
        if memory_manager.should_preemptive_evict:
            memory_manager.evict_buffer(cycle_data)
        if ratio > 0.95:
            execute_kill_switch(args.interface, dry_run=args.dry_run, profile=profile)
        time.sleep(0.5)
    finally:
        self_defense.stop()
        memory_manager.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
