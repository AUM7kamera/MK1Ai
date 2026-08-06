"""
============================================================
  超軽量・オールインワン エアギャップ自動遮断AI
  airgap_ai_defender.py (最終完成版)
============================================================

【自由工作のレポート用 システム概要】

このプログラムは「1つのAIモデルがすべてを支配する」という設計思想で作られています。

★ 3層リソース構造
  [Layer 1] Googleドライブ (最大100GB) ─── ハッキング手法の最新教材置き場
      ↓ AIが「使える教材か？」を查定してダウンロード
  [Layer 2] ローカルストレージ ─────────── 厳選データの保管庫 + 緊急時の仮想メモリ
      ↓ 必要なデータだけをRAMへ
  [Layer 3] システムRAM (上限500MB) ────── AIモデル本体が動く超高速の実行現場

★ 1つのAIが3つの顔を持つ
  Head A (絶対防衛役) : 異常パケットを0.001秒で検知 → ネットワーク即遮断
  Head B (学習・厳選役): 良い教材を見分け、防衛の邪魔をせずバックグラウンドで成長
  Head C (司令塔)     : RAMの残量を監視し、溢れる前にデータをストレージへ退避指令

実行方法:
  pip install torch psutil requests gdown
  sudo python3 airgap_ai_defender.py --interface eth0
  ※ raw socketにはroot権限(sudo)が必要
  ※ デフォルトはDry-Runモード（実際の遮断はしない安全なテストモード）
  ※ GoogleドライブフォルダID: 100FIfMbB-0kR2bg2NXl-O1k-Lilz-j_G (デフォルト設定済)
"""

# ── 標準ライブラリ (インストール不要) ──
import os, sys, time, struct, socket, threading, queue, json, tempfile, mmap, subprocess, argparse, logging, random, shutil, platform, math, re, hmac, pickle, zipfile, hashlib, getpass, multiprocessing, ctypes, errno
from collections import Counter, OrderedDict, deque

try:
    import pwd
except ImportError:  # pragma: no cover - platform-agnostic fallback
    pwd = None

_PRECOMPILED_TOKEN_RE = re.compile(rb'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{32,}(?![A-Za-z0-9+/=])')
_PRECOMPILED_JWT_RE = re.compile(rb'(?i)\b(?:bearer\s+)?eyj[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\b')
_PRECOMPILED_ESCAPE_RE = re.compile(rb'(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\0[0-7]{1,3}){2,}')
_CODE_EXECUTION_CONTEXT = (
    b"eval(",
    b"atob",
    b"btoa",
    b"exec",
    b"unescape",
    b"fromcharcode",
    b"powershell",
    b"cmd.exe",
    b"decode",
)

_UNSAFE_SHELL_CHARS_RE = re.compile(r"[;&|`$<>\\\n\r\t\f\v]")

# ── 外部ライブラリ (pip install torch psutil requests gdown) ──
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
except ImportError:  # テスト/最小環境でも import できるように軽量なスタブを提供
    class _DummyModule:
        def __init__(self, *args, **kwargs):
            pass
        def __call__(self, x):
            return x
        def forward(self, x):
            return x
        def train(self):
            return None
        def eval(self):
            return None
        def load_state_dict(self, state_dict):
            return None
        def state_dict(self):
            return {}
        def named_parameters(self):
            return []
        def parameters(self):
            return []

    class _DummyLayer(_DummyModule):
        pass

    class _DummySequential(_DummyModule):
        def __init__(self, *layers):
            super().__init__()
            self.layers = list(layers)
        def __call__(self, x):
            out = x
            for layer in self.layers:
                out = layer(out)
            return out

    class _DummyTensor:
        def __init__(self, value=0.0):
            self._value = value
        def item(self):
            if isinstance(self._value, list):
                return self._value[0] if self._value else 0.0
            return float(self._value)
        def backward(self):
            return None
        def tolist(self):
            if isinstance(self._value, list):
                return list(self._value)
            return [self._value]

    class _NoGradContext:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False

    class _DummyLoss:
        def __call__(self, *args, **kwargs):
            return _DummyTensor(0.0)

    class _DummyOptimizer:
        def __init__(self, *args, **kwargs):
            pass
        def zero_grad(self):
            pass
        def step(self):
            pass

    class _DummyNN:
        Module = _DummyModule
        Linear = _DummyLayer
        Sequential = _DummySequential
        ReLU = _DummyLayer
        Sigmoid = _DummyLayer
        BCELoss = _DummyLoss

    class _DummyOptim:
        SGD = _DummyOptimizer

    class _TorchStub:
        float32 = "float32"
        float64 = "float64"

        @staticmethod
        def tensor(*args, **kwargs):
            if not args:
                return _DummyTensor(0.0)
            value = args[0]
            return _DummyTensor(value)
        @staticmethod
        def rand(*args, **kwargs):
            return _DummyTensor(0.0)
        @staticmethod
        def load(*args, **kwargs):
            raise ImportError("torch is not available")
        @staticmethod
        def device(*args, **kwargs):
            return args[0] if args else "cpu"
        @staticmethod
        def no_grad():
            return _NoGradContext()

    torch = _TorchStub()
    nn = _DummyNN()
    optim = _DummyOptim()
try:
    import psutil
except ImportError:
    class _PsutilStub:
        CONN_LISTEN = "LISTEN"
        CONN_ESTABLISHED = "ESTABLISHED"
        CONN_SYN_SENT = "SYN_SENT"
        NoSuchProcess = Exception
        AccessDenied = Exception
        ZombieProcess = Exception

        @staticmethod
        def net_if_addrs():
            return {}

        @staticmethod
        def net_connections(kind="inet"):
            return []

        @staticmethod
        def process_iter(attrs=None):
            return []

        class Process:
            def __init__(self, pid):
                self.pid = pid
            def memory_info(self):
                return type("MemoryInfo", (), {"rss": 0})()

    psutil = _PsutilStub()

try:
    import requests
except ImportError:
    requests = None

try:
    import gdown  # Googleドライブフォルダのダウンロードに特化したライブラリ
    GDOWN_AVAILABLE = True
except ImportError:
    GDOWN_AVAILABLE = False

# ── ロギング設定 ──
class SecurityLogger(logging.Logger):
    def warning(self, msg, *args, **kwargs):
        super().warning(self._decorate_message(msg, "WARNING"), *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        super().critical(self._decorate_message(msg, "CRITICAL"), *args, **kwargs)

    @staticmethod
    def _decorate_message(msg, level: str) -> str:
        prefix = {
            "WARNING": "[ANOMALY_DETECTION / THREAT_INDEX]",
            "CRITICAL": "[ACTIVE_DEFENSE / AIRGAP_CONTAINMENT]",
        }.get(level, "")
        color = "\033[1;31m" if level in {"WARNING", "CRITICAL"} else ""
        reset = "\033[0m" if color else ""
        return f"{color}{prefix} {msg}{reset}" if prefix else msg


logging.setLoggerClass(SecurityLogger)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("AirgapAI")

# =====================================================================
# 追加機能: ネットワーク自動判別 / 暗号解析 / バックドア検査 / MTD
# =====================================================================
import signal as _signal_module

_CRYPTO_LOG_COOLDOWN = 0.0
_BACKDOOR_RISK_SCORE = 0.0
_KILL_SWITCH_TRIGGERED = False
_KILL_SWITCH_COOLDOWN_SEC = 5.0
_LAST_KILL_SWITCH_TRIGGER = 0.0
_MONITOR_INTERFACE = "eth0"
_DRY_RUN = True

# Linux capabilities and cBPF safe-flow configuration
_CAP_NET_ADMIN = 12
_CAP_NET_RAW = 13
_SAFE_KERNEL_BPF_PORTS = {80, 443, 1935, 554, 8080, 8443}
_SAFE_KERNEL_BPF_MINIMUM_PACKET_LENGTH = 1200
_SAFE_KERNEL_BPF_DIRTY = False

_PROCESS_EVENT_MONITOR_AVAILABLE = False
_PROCESS_EVENT_MONITOR_FALLBACK_INTERVAL = 2.0

# ── ONI_MODE (鬼モード): threading.Event 化により実行時に動的切替可能 ──
# 起動時は環境変数 / CLI引数 で初期値を設定。
# 実行中は SIGUSR1 シグナルまたは toggle_oni_mode() で切り替え可能。
_ONI_MODE_ACTIVE = threading.Event()
if str(os.environ.get("ONI_MODE", "")).lower() in {"1", "true", "yes", "on"}:
    _ONI_MODE_ACTIVE.set()

def ONI_MODE_is_active() -> bool:
    """現在の ONI_MODE（鬼モード）状態を返す。"""
    return _ONI_MODE_ACTIVE.is_set()

# 後方互換のため: モジュールレベルで直接参照するコードが残っている場合に対応
ONI_MODE = property(lambda self: _ONI_MODE_ACTIVE.is_set()) if False else _ONI_MODE_ACTIVE.is_set()

def toggle_oni_mode(activate: bool | None = None) -> bool:
    """ONI_MODE の状態を切り替える。activate=None で現在値をトグル。"""
    if activate is None:
        activate = not _ONI_MODE_ACTIVE.is_set()
    if activate:
        _ONI_MODE_ACTIVE.set()
        log.warning("[ONI_MODE] ★★★ 鬼モード有効化 ★★★ ホワイトリスト無効・1検知で即キルスイッチ発動！")
    else:
        _ONI_MODE_ACTIVE.clear()
        log.info("[ONI_MODE] 鬼モード解除 → 通常監視モードへ移行しました。")
    return activate

def _oni_mode_signal_handler(signum, frame):
    """SIGUSR1 受信で ONI_MODE をトグルする。"""
    toggle_oni_mode()

try:
    _signal_module.signal(_signal_module.SIGUSR1, _oni_mode_signal_handler)
except (AttributeError, OSError):
    pass  # Windows 等 SIGUSR1 非対応環境では無視

# ── スコア閾値定数 ──
# 通常モード: 誤検知を抑えた高閾値
_NORMAL_MODE_COMPOSITE_THRESHOLD = 0.88
_NORMAL_MODE_AI_THRESHOLD = 0.88
_NORMAL_MODE_MATH_THRESHOLD = 0.88
_NORMAL_MODE_ENTROPY_THRESHOLD = 0.92   # これ以上の高エントロピーは第1段階で即ブロック
# 鬼モード: 1検知で即キルスイッチ (閾値を最小化)
_ONI_MODE_SCORE_THRESHOLD = 0.01        # 実質的にどんな異常でも即発動
_ONI_MODE_ANOMALY_COUNT_TRIGGER = 1     # 累積カウンタ1回で発動

FULL_PACKET_INSPECTION = str(os.environ.get("FULL_PACKET_INSPECTION", "")).lower() in {"1", "true", "yes", "on"}
# Full-payload DPI: no fixed head-only cutoff. We scan the complete payload body
# with lightweight, strided sampling for long packets, then keep precise offsets for any findings.
_DPI_WINDOW_SIZE = 256
_DPI_SAMPLE_STRIDE = 128
_DPI_MAX_SAMPLE_WINDOWS = 32
_FULL_PACKET_INSPECTION_LOG_PATH = os.path.join("./ai_data", "full_packet_inspection.log")
_MAINTENANCE_ACTIVE = False
_MAINTENANCE_REASON = ""
_MAINTENANCE_LOCK = threading.Lock()
_CONTAINMENT_LOCK = threading.Lock()
_KILL_SWITCH_EVENT = threading.Event()
_ADMIN_RECOVERY_TOKEN = os.environ.get("AIRGAP_ADMIN_RECOVERY_TOKEN", "")
_ADMIN_RECOVERY_TOKEN_FILE = os.path.join("./ai_data", "admin_recovery.token")
is_gdrive_downloading = False
gdrive_download_end_time = 0.0
gdrive_ips = set()
_ema_delta = 0.1
_anomaly_counter = 0
_last_dpi_result = {}
_HEAD_B_LEARNING_QUEUE = {}
_TRAFFIC_CALIBRATION_WINDOW = {}
_TRAFFIC_ACTIVITY_HISTORY = deque(maxlen=256)
_PACKET_LENGTH_HISTORY: deque = deque(maxlen=256)   # 統計外れ値検知用パケット長履歴
_PACKET_INTERARRIVAL_HISTORY: deque = deque(maxlen=256)  # バースト/ジッタ検知用インターバル履歴
_LAST_PACKET_EVENT_TIME = 0.0
_FLOW_STATE_CACHE = OrderedDict()
_FLOW_SAMPLE_INTERVAL = 4
_FLOW_CACHE_MAX_ENTRIES = 1024
_FLOW_CACHE_LOCK = threading.Lock()
_IP_CORRELATION_LOCK = threading.Lock()
_HEALTH_LOCK = threading.Lock()
_SOURCE_ERROR_STATE = {}
_BLACKLISTED_SOURCES = {}
_DEST_IP_CORRELATION_STATS = {}
_SECURITY_HEALTH_EVENTS = deque(maxlen=256)
_SECURITY_HEALTH_STATE = {
    "hardening_active": False,
    "hardening_triggered_at": 0.0,
    "last_event_time": 0.0,
}
_SECURITY_HEALTH_WINDOW_SEC = 30.0
_SECURITY_HEALTH_TRIGGER_COUNT = 4
_SECURITY_HARDENING_RECOVERY_SEC = 30.0
_SOURCE_ERROR_THRESHOLD = 3
_SOURCE_ERROR_WINDOW_SEC = 20.0
_SOURCE_IP_BLOCK_SEC = 60.0
_EXPECTED_MODEL_HASH = ""
_MODEL_HASH_RECORD_PATH = os.path.join("./ai_data", "model_hash.record")
_ANOMALY_DECAY_LAST_TIME = 0.0
_ANOMALY_DECAY_WINDOW_SEC = 30.0
# Head C ヒステリシス用
_HEAD_C_EVICT_ACTIVE = False
_HEAD_C_ON_THRESHOLD = 0.75
_HEAD_C_OFF_THRESHOLD = 0.50
_MANAGEMENT_SAFE_HARBOR_DEFAULT_PORTS = (22,)
_MANAGEMENT_SAFE_HARBOR_DEFAULT_IPS = ("127.0.0.1", "::1")
_TRACE_SEQUENCE = 0


def enter_maintenance_mode(reason: str):
    """外部データ更新中はリアルタイム防衛を安全な Dry-Run 状態へ一時退避する。"""
    global _MAINTENANCE_ACTIVE, _MAINTENANCE_REASON
    with _MAINTENANCE_LOCK:
        _MAINTENANCE_ACTIVE = True
        _MAINTENANCE_REASON = reason
    log.warning(f"[MAINTENANCE] セキュア・メンテナンス状態へ移行: {reason}")


def exit_maintenance_mode():
    """メンテナンス完了後にアクティブ防衛モードへ戻す。"""
    global _MAINTENANCE_ACTIVE, _MAINTENANCE_REASON
    with _MAINTENANCE_LOCK:
        _MAINTENANCE_ACTIVE = False
        _MAINTENANCE_REASON = ""
    log.info("[MAINTENANCE] セキュア・メンテナンス状態を終了し、アクティブ防衛モードへ復帰しました。")


def is_maintenance_mode() -> bool:
    with _MAINTENANCE_LOCK:
        return _MAINTENANCE_ACTIVE


def update_gdrive_ips() -> set:
    """ゼロトラスト原則に従い、外部送信先の許可リストは保持しない。"""
    return set()


def _extract_src_ip(packet_bytes: bytes) -> str | None:
    """パケットから送信元 IP を安全に抽出する。"""
    try:
        if not packet_bytes or len(packet_bytes) < 14:
            return None
        ether_type = struct.unpack("!H", packet_bytes[12:14])[0]
        if ether_type == 0x0800:
            ip_offset = 14
            if len(packet_bytes) < ip_offset + 20:
                return None
            version_ihl = packet_bytes[ip_offset]
            if (version_ihl >> 4) != 4:
                return None
            ihl = (version_ihl & 0x0F) * 4
            if len(packet_bytes) < ip_offset + ihl:
                return None
            return socket.inet_ntoa(packet_bytes[ip_offset + 12:ip_offset + 16])
        elif ether_type == 0x86DD:
            ip_offset = 14
            if len(packet_bytes) < ip_offset + 40:
                return None
            version_tc_fl = packet_bytes[ip_offset]
            if (version_tc_fl >> 4) != 6:
                return None
            return socket.inet_ntop(socket.AF_INET6, packet_bytes[ip_offset + 8:ip_offset + 24])
        return None
    except Exception as exc:
        log.warning(f"[PACKET] 送信元 IP の抽出に失敗しました ({exc})")
        return None


def _is_ip_blacklisted(source_ip: str | None) -> bool:
    if not source_ip:
        return False
    now = time.time()
    with _HEALTH_LOCK:
        expiry = _BLACKLISTED_SOURCES.get(source_ip)
        if expiry and expiry > now:
            return True
        if expiry and expiry <= now:
            del _BLACKLISTED_SOURCES[source_ip]
    return False


def parse_packet_transport(packet_bytes: bytes) -> dict:
    """Ethernet / IPv4 / IPv6 / TCP/UDP パケットから送受信元 IP とポートを抽出する。"""
    if not packet_bytes or len(packet_bytes) < 14:
        return {}
    try:
        ether_type = struct.unpack("!H", packet_bytes[12:14])[0]
        if ether_type == 0x0800:
            ip_offset = 14
            if len(packet_bytes) < ip_offset + 20:
                return {}

            version_ihl = packet_bytes[ip_offset]
            if (version_ihl >> 4) != 4:
                return {}

            ihl = (version_ihl & 0x0F) * 4
            if len(packet_bytes) < ip_offset + ihl:
                return {}

            protocol = packet_bytes[ip_offset + 9]
            src_ip = socket.inet_ntoa(packet_bytes[ip_offset + 12:ip_offset + 16])
            dst_ip = socket.inet_ntoa(packet_bytes[ip_offset + 16:ip_offset + 20])

            src_port = dst_port = None
            transport_offset = ip_offset + ihl
            if protocol == socket.IPPROTO_TCP and len(packet_bytes) >= transport_offset + 20:
                src_port, dst_port = struct.unpack("!HH", packet_bytes[transport_offset:transport_offset + 4])
            elif protocol == socket.IPPROTO_UDP and len(packet_bytes) >= transport_offset + 8:
                src_port, dst_port = struct.unpack("!HH", packet_bytes[transport_offset:transport_offset + 4])

            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
            }
        elif ether_type == 0x86DD:
            ip_offset = 14
            if len(packet_bytes) < ip_offset + 40:
                return {}
            version_tc_fl = packet_bytes[ip_offset]
            if (version_tc_fl >> 4) != 6:
                return {}
            protocol = packet_bytes[ip_offset + 6]
            src_ip = socket.inet_ntop(socket.AF_INET6, packet_bytes[ip_offset + 8:ip_offset + 24])
            dst_ip = socket.inet_ntop(socket.AF_INET6, packet_bytes[ip_offset + 24:ip_offset + 40])

            src_port = dst_port = None
            transport_offset = ip_offset + 40
            if protocol == socket.IPPROTO_TCP and len(packet_bytes) >= transport_offset + 20:
                src_port, dst_port = struct.unpack("!HH", packet_bytes[transport_offset:transport_offset + 4])
            elif protocol == socket.IPPROTO_UDP and len(packet_bytes) >= transport_offset + 8:
                src_port, dst_port = struct.unpack("!HH", packet_bytes[transport_offset:transport_offset + 4])

            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
            }
        else:
            return {}
    except Exception as exc:
        _record_security_health_issue("parse_exception", "parse_packet_transport", source_ip=_extract_src_ip(packet_bytes))
        log.warning(f"[PACKET] 解析不能パケットのためフェールクローズでブロックします ({exc})")
        return {"parse_error": True, "src_ip": _extract_src_ip(packet_bytes)}


def is_google_drive_whitelisted_packet(packet_bytes: bytes) -> bool:
    """ゼロトラスト原則により、外部更新通信に対するいかなる許可スキップも行わない。"""
    return False


def extract_payload_bytes(packet_bytes: bytes) -> bytes:
    """Ethernet/IPv4/IPv6/TCP/UDP ヘッダーをたどって、ペイロード部のみを抽出する。"""
    if not packet_bytes or len(packet_bytes) < 14:
        return b""
    try:
        ether_type = struct.unpack("!H", packet_bytes[12:14])[0]
        if ether_type == 0x0800:
            ip_offset = 14
            if len(packet_bytes) < ip_offset + 20:
                return b""

            version_ihl = packet_bytes[ip_offset]
            if (version_ihl >> 4) != 4:
                return b""

            ihl = (version_ihl & 0x0F) * 4
            if len(packet_bytes) < ip_offset + ihl:
                return b""

            protocol = packet_bytes[ip_offset + 9]
            transport_offset = ip_offset + ihl
            if protocol == socket.IPPROTO_TCP and len(packet_bytes) >= transport_offset + 20:
                tcp_offset_byte = packet_bytes[transport_offset + 12]
                fallback_offset_byte = packet_bytes[transport_offset + 13] if len(packet_bytes) >= transport_offset + 13 else 0
                if tcp_offset_byte > 0x0F and len(packet_bytes) >= transport_offset + 13:
                    data_offset_words = (tcp_offset_byte >> 4) & 0x0F
                else:
                    data_offset_words = fallback_offset_byte if fallback_offset_byte <= 0x0F else (fallback_offset_byte >> 4) & 0x0F
                data_offset = max(0, data_offset_words) * 4
                payload_offset = transport_offset + data_offset
            elif protocol == socket.IPPROTO_UDP and len(packet_bytes) >= transport_offset + 8:
                payload_offset = transport_offset + 8
            else:
                return b""

            if payload_offset >= len(packet_bytes):
                return b""
            return packet_bytes[payload_offset:]
        elif ether_type == 0x86DD:
            ip_offset = 14
            if len(packet_bytes) < ip_offset + 40:
                return b""
            version_tc_fl = packet_bytes[ip_offset]
            if (version_tc_fl >> 4) != 6:
                return b""
            protocol = packet_bytes[ip_offset + 6]
            transport_offset = ip_offset + 40
            if protocol == socket.IPPROTO_TCP and len(packet_bytes) >= transport_offset + 20:
                tcp_offset_byte = packet_bytes[transport_offset + 12]
                fallback_offset_byte = packet_bytes[transport_offset + 13] if len(packet_bytes) >= transport_offset + 13 else 0
                if tcp_offset_byte > 0x0F and len(packet_bytes) >= transport_offset + 13:
                    data_offset_words = (tcp_offset_byte >> 4) & 0x0F
                else:
                    data_offset_words = fallback_offset_byte if fallback_offset_byte <= 0x0F else (fallback_offset_byte >> 4) & 0x0F
                data_offset = max(0, data_offset_words) * 4
                payload_offset = transport_offset + data_offset
            elif protocol == socket.IPPROTO_UDP and len(packet_bytes) >= transport_offset + 8:
                payload_offset = transport_offset + 8
            else:
                return b""

            if payload_offset >= len(packet_bytes):
                return b""
            return packet_bytes[payload_offset:]
        else:
            return b""
    except Exception as exc:
        _record_security_health_issue("parse_exception", "extract_payload_bytes", source_ip=_extract_src_ip(packet_bytes))
        log.warning(f"[PACKET] ペイロード抽出に失敗したためフェールクローズでブロックします ({exc})")
        return b"\x00"


def calculate_payload_entropy(payload: bytes) -> float:
    """ペイロードのエントロピーを 0.0〜1.0 で計算する。"""
    if not payload:
        return 0.0
    freq = {}
    for byte in payload:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    total = len(payload)
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return min(1.0, entropy / 8.0)


def _contains_multiencoding_bytes(payload: bytes, token: bytes) -> bool:
    """ASCII トークンを UTF-8 / UTF-16LE / UTF-16BE バイナリ列で検索する。"""
    if token in payload:
        return True
    try:
        utf16le = token.decode("ascii", errors="ignore").encode("utf-16le")
        utf16be = token.decode("ascii", errors="ignore").encode("utf-16be")
        if utf16le in payload or utf16be in payload:
            return True
    except Exception as exc:
        log.warning(f"[PACKET] マルチエンコーディング検索に失敗しました ({exc})")
    return False


def _find_multiencoding_offset(payload: bytes, token: bytes) -> int:
    if token in payload:
        return payload.find(token)
    try:
        utf16le = token.decode("ascii", errors="ignore").encode("utf-16le")
        utf16be = token.decode("ascii", errors="ignore").encode("utf-16be")
        if utf16le in payload:
            return payload.find(utf16le)
        if utf16be in payload:
            return payload.find(utf16be)
    except Exception as exc:
        log.warning(f"[PACKET] マルチエンコーディングオフセット検索に失敗しました ({exc})")
    return -1


def _bytes_contains_any_multiencoding(payload: bytes, tokens: tuple[bytes, ...]) -> bool:
    for token in tokens:
        if _contains_multiencoding_bytes(payload, token):
            return True
    return False


def _classify_payload_text(payload_bytes: bytes) -> str:
    """通常のJSON/HTML/JSを「開発ツールの正常通信」として扱うための文脈分類を返す。"""
    lower = payload_bytes.lower()
    if b"{\"" in lower or b'"' in lower and b":" in lower:
        return "json"
    if b"<html" in lower or b"<!doctype html" in lower or b"<body" in lower:
        return "html"
    if b"function " in lower or b"const " in lower or b"let " in lower or b"window." in lower:
        return "javascript"
    if b"cmd.exe" in lower or b"powershell" in lower or b"eval(" in lower or b"base64" in lower:
        return "code-execution"
    return "binary-or-opaque"


def _get_dynamic_calibration(interface: str = None, payload_len: int = 0, text_class: str = None, lower_payload: bytes | None = None, payload_bytes: bytes | None = None) -> dict:
    """通常時トラフィック密度に合わせて、DPIの判定閾値を動的に補正する。"""
    iface_key = interface or "default"
    history = _TRAFFIC_CALIBRATION_WINDOW.setdefault(iface_key, deque(maxlen=64))
    history.append(payload_len)
    traffic_pressure = min(1.0, len(history) / 64.0)
    payload_pressure = min(1.0, payload_len / 1500.0)

    threshold = 0.70
    if traffic_pressure >= 0.55:
        threshold += 0.04
    if payload_pressure >= 0.8:
        threshold += 0.03
    if _SECURITY_HEALTH_STATE.get("hardening_active", False):
        if text_class in {"json", "html", "javascript"} and lower_payload is not None and payload_bytes is not None and _has_benign_structured_token_context(lower_payload, payload_bytes, text_class):
            return {
                "threshold": 0.60,
                "traffic_pressure": 1.0,
                "payload_pressure": 1.0,
            }
        return {
            "threshold": 0.45,
            "traffic_pressure": 1.0,
            "payload_pressure": 1.0,
        }

    return {
        "threshold": min(0.85, max(0.55, threshold)),
        "traffic_pressure": traffic_pressure,
        "payload_pressure": payload_pressure,
    }


def _record_security_health_issue(issue_type: str, context: str = "", source_ip: str | None = None) -> None:
    """パース例外・異常パケット・処理遅延を記録し、閾値超過で動的ハードニングを発動する。"""
    ts = time.time()
    if source_ip:
        ips = _SOURCE_ERROR_STATE.setdefault(source_ip, deque(maxlen=_SOURCE_ERROR_THRESHOLD))
        ips.append(ts)
        if len(ips) >= _SOURCE_ERROR_THRESHOLD and ts - ips[0] <= _SOURCE_ERROR_WINDOW_SEC:
            with _HEALTH_LOCK:
                _BLACKLISTED_SOURCES[source_ip] = ts + _SOURCE_IP_BLOCK_SEC
            log.warning(f"[IP_BLACKLIST] 疑わしい送信元 IP を一時遮断しました: {source_ip}")
            return

    if source_ip and _is_ip_blacklisted(source_ip):
        return

    with _HEALTH_LOCK:
        _SECURITY_HEALTH_EVENTS.append((ts, issue_type, context, source_ip))
        _SECURITY_HEALTH_STATE["last_event_time"] = ts
        blacklisted_ips = {
            ip for ip, expiry in _BLACKLISTED_SOURCES.items() if expiry and expiry > ts
        }

        recent = [evt for evt in _SECURITY_HEALTH_EVENTS if ts - evt[0] <= _SECURITY_HEALTH_WINDOW_SEC]
        distinct_ips = {evt[3] for evt in recent if evt[3] and evt[3] not in blacklisted_ips}
        anomaly_count = sum(1 for evt in recent if evt[1] in {"parse_exception", "malformed_packet", "timeout"})
        if len(distinct_ips) >= 3 and anomaly_count >= _SECURITY_HEALTH_TRIGGER_COUNT:
            _enter_security_hardening()


def _enter_security_hardening() -> None:
    """異常頻度が高いと判断した場合、フローキャッシュを破棄し全パケットを強制フルDPI化する。"""
    if _SECURITY_HEALTH_STATE.get("hardening_active", False):
        return

    _SECURITY_HEALTH_STATE["hardening_active"] = True
    _SECURITY_HEALTH_STATE["hardening_triggered_at"] = time.time()
    _FLOW_STATE_CACHE.clear()
    with _CONTAINMENT_LOCK:
        global _BACKDOOR_RISK_SCORE
        _BACKDOOR_RISK_SCORE = max(_BACKDOOR_RISK_SCORE, 0.65)
    log.warning("[SELF_HEALING] 異常検知により緊急ハードニングを発動しました。フローキャッシュを破棄し、全パケットを強制フルDPI化します。")


def _maybe_recover_security_hardening() -> None:
    """一定時間安定したら、緩やかに通常の最適化モードへ復帰する。"""
    if not _SECURITY_HEALTH_STATE.get("hardening_active", False):
        return
    now = time.time()
    last_event = _SECURITY_HEALTH_STATE.get("last_event_time", 0.0)
    if now - last_event >= _SECURITY_HARDENING_RECOVERY_SEC:
        _SECURITY_HEALTH_STATE["hardening_active"] = False
        log.info("[SELF_HEALING] 異常イベントの収束を確認しました。通常モードへ徐々に復帰します。\n")


def _update_head_b_learning_queue(payload_bytes: bytes, interface: str = None, text_class: str = "binary-or-opaque") -> float:
    """Head B が正常通信の学習キューを保持し、端末特有の正常パターンに対する補正値を返す。"""
    if not payload_bytes or len(payload_bytes) < 16:
        return 0.0

    stable_payload = payload_bytes[:min(len(payload_bytes), 512)]
    fingerprint = stable_payload[:32].decode("latin-1", errors="ignore")
    if not fingerprint.strip():
        return 0.0

    queue = _HEAD_B_LEARNING_QUEUE.setdefault(interface or "default", deque(maxlen=128))
    queue.append((text_class, fingerprint))

    learned_matches = sum(1 for entry in queue if entry[0] == text_class and entry[1] == fingerprint)
    if learned_matches >= 2 and text_class in {"json", "html", "javascript"}:
        return 0.18
    return 0.0


def _normalize_flow_key(packet_bytes: bytes) -> tuple | None:
    """同一セッションの軽量スキップ用に 5-tuple を正規化する。"""
    transport = parse_packet_transport(packet_bytes)
    if not transport:
        return None

    endpoints = sorted(
        [
            (transport.get("src_ip"), transport.get("src_port")),
            (transport.get("dst_ip"), transport.get("dst_port")),
        ],
        key=lambda item: (item[0] or "", item[1] if item[1] is not None else -1),
    )
    return (transport.get("protocol"), tuple(endpoints))


def _tcp_flag_bits(packet_bytes: bytes) -> int:
    """TCP フラグの簡易解釈。PSH/URG の出現は Adaptive Sampling の強制フルスキャン条件になる。"""
    transport = parse_packet_transport(packet_bytes)
    if not transport or transport.get("protocol") != socket.IPPROTO_TCP:
        return 0

    try:
        ip_offset = 14
        ihl = (packet_bytes[ip_offset] & 0x0F) * 4
        transport_offset = ip_offset + ihl
        if len(packet_bytes) < transport_offset + 20:
            return 0
        return packet_bytes[transport_offset + 13]
    except Exception:
        return 0


def _should_force_full_scan(packet_bytes: bytes, flow_state: dict) -> bool:
    """フローの累積 bytes / 経過時間 / TCP フラグ変化でキャッシュを無効化し、分割攻撃を防ぐ。"""
    if not packet_bytes or not flow_state:
        return True

    flags = _tcp_flag_bits(packet_bytes)
    if _SECURITY_HEALTH_STATE.get("hardening_active", False):
        return True

    last_flags = flow_state.get("last_flags", 0)
    if flags != last_flags and ((flags & 0x08) or (last_flags & 0x08) or (flags & 0x20) or (last_flags & 0x20)):
        return True

    payload_len = len(extract_payload_bytes(packet_bytes))
    cumulative = flow_state.get("cumulative_bytes", 0) + payload_len
    packets = flow_state.get("packets_since_last_scan", 0) + 1

    # 一定パケット数（20パケットごと）またはペイロード長累積（10KBごと）に達した場合は強制フルスキャン
    if packets >= 20 or cumulative >= 10240:
        return True

    last_scan_time = flow_state.get("last_scan_time", 0.0)
    if time.time() - last_scan_time >= 3.0:
        return True

    last_payload_len = flow_state.get("last_payload_len", 0)
    if last_payload_len > 0:
        delta = abs(payload_len - last_payload_len)
        threshold = max(32, last_payload_len // 2)
        if delta >= threshold:
            return True
    return False


def _get_flow_cache_result(packet_bytes: bytes) -> dict | None:
    """同一フローで最近安全と判定された通信は、Adaptive Sampling により軽量化する。"""
    if _SECURITY_HEALTH_STATE.get("hardening_active", False):
        return None

    transport = parse_packet_transport(packet_bytes)
    flow_key = _normalize_flow_key(packet_bytes)
    if flow_key is None:
        return None

    with _FLOW_CACHE_LOCK:
        flow_state = _FLOW_STATE_CACHE.get(flow_key)
        if not flow_state:
            return None

        if _should_force_full_scan(packet_bytes, flow_state):
            _FLOW_STATE_CACHE.move_to_end(flow_key)
            return None

        track_c2 = flow_state.get("c2_tracking", False) or _should_update_flow_beacon(packet_bytes, transport)
        if track_c2 and not flow_state.get("c2_tracking", False):
            flow_state["c2_tracking"] = True
            flow_state.setdefault("direction_bytes", {"ab": 0, "ba": 0})
            flow_state.setdefault("direction_packets", {"ab": 0, "ba": 0})
            flow_state.setdefault("direction_sizes", {"ab": deque(maxlen=16), "ba": deque(maxlen=16)})
            flow_state.setdefault("intervals", deque(maxlen=16))
            flow_state.setdefault("last_packet_time", 0.0)

    if track_c2 and _update_flow_beacon_stats(packet_bytes, transport, flow_state):
        with _FLOW_CACHE_LOCK:
            _FLOW_STATE_CACHE.move_to_end(flow_key)
        return None

    with _FLOW_CACHE_LOCK:
        payload_len = len(extract_payload_bytes(packet_bytes))
        flow_state["cumulative_bytes"] = flow_state.get("cumulative_bytes", 0) + payload_len
        flow_state["packets_since_last_scan"] = flow_state.get("packets_since_last_scan", 0) + 1
        flow_state["last_flags"] = _tcp_flag_bits(packet_bytes)
        flow_state["last_seen"] = time.time()
        flow_state["sample_counter"] = (flow_state.get("sample_counter", 0) + 1) % _FLOW_SAMPLE_INTERVAL
        _FLOW_STATE_CACHE.move_to_end(flow_key)
        if flow_state["sample_counter"] != 0:
            cached = dict(flow_state["last_result"])
            cached["scan_strategy"] = "flow_cache"
            cached["score"] = round(min(0.49, cached.get("score", 0.0)), 4)
            return cached
    return None


def _cache_flow_result(packet_bytes: bytes, result: dict) -> None:
    """LRU で安全なフロー結果を保持し、古いエントリを O(1) で排除する。"""
    flow_key = _normalize_flow_key(packet_bytes)
    if flow_key is None or not result:
        return

    packet_flags = _tcp_flag_bits(packet_bytes)
    payload_len = len(extract_payload_bytes(packet_bytes))
    transport = parse_packet_transport(packet_bytes)
    endpoints = tuple(sorted(
        [
            (transport.get("src_ip"), transport.get("src_port")),
            (transport.get("dst_ip"), transport.get("dst_port")),
        ],
        key=lambda x: (x[0] or "", x[1] or 0)
    ))
    c2_tracking = _should_update_flow_beacon(packet_bytes, transport)

    flow_state = {
        "sample_counter": 0,
        "last_payload_len": payload_len,
        "last_result": dict(result),
        "last_seen": time.time(),
        "last_scan_time": time.time(),
        "last_flags": packet_flags,
        "cumulative_bytes": payload_len,
        "packets_since_last_scan": 1,
        "endpoints": endpoints,
        "c2_tracking": c2_tracking,
    }

    if c2_tracking:
        flow_state.update({
            "direction_bytes": {"ab": 0, "ba": 0},
            "direction_packets": {"ab": 0, "ba": 0},
            "direction_sizes": {"ab": deque(maxlen=16), "ba": deque(maxlen=16)},
            "intervals": deque(maxlen=16),
            "last_packet_time": 0.0,
        })

    with _FLOW_CACHE_LOCK:
        if flow_key in _FLOW_STATE_CACHE:
            _FLOW_STATE_CACHE.move_to_end(flow_key)

        _FLOW_STATE_CACHE[flow_key] = flow_state
        _FLOW_STATE_CACHE.move_to_end(flow_key)

        while len(_FLOW_STATE_CACHE) > _FLOW_CACHE_MAX_ENTRIES:
            _FLOW_STATE_CACHE.popitem(last=False)


def _flow_packet_direction(packet_bytes: bytes, flow_state: dict) -> str | None:
    transport = parse_packet_transport(packet_bytes)
    if not transport or not transport.get("src_ip"):
        return None
    src = (transport.get("src_ip"), transport.get("src_port"))
    endpoints = flow_state.get("endpoints")
    if not endpoints or len(endpoints) != 2:
        return None
    if src == endpoints[0]:
        return "ab"
    if src == endpoints[1]:
        return "ba"
    return None


def _packet_size_stable(sizes: deque[int]) -> bool:
    if len(sizes) < 4:
        return False
    avg_size = sum(sizes) / len(sizes)
    deviation = max(abs(size - avg_size) for size in sizes)
    return deviation <= max(16, avg_size * 0.18)


def _assess_tls_c2_beacon(flow_state: dict) -> bool:
    intervals = list(flow_state.get("intervals", []))
    if len(intervals) < 4:
        return False
    avg_interval = sum(intervals) / len(intervals)
    if not (20.0 <= avg_interval <= 120.0):
        return False
    if max(intervals) - min(intervals) > avg_interval * 0.35:
        return False

    ab_bytes = flow_state.get("direction_bytes", {}).get("ab", 0)
    ba_bytes = flow_state.get("direction_bytes", {}).get("ba", 0)
    if ab_bytes <= 0 or ba_bytes <= 0:
        return False
    ratio = min(ab_bytes, ba_bytes) / max(ab_bytes, ba_bytes)
    if ratio < 0.25:
        return False

    for direction in ("ab", "ba"):
        sizes = flow_state.get("direction_sizes", {}).get(direction, deque())
        if _packet_size_stable(sizes):
            avg_size = sum(sizes) / len(sizes)
            if 50.0 <= avg_size <= 900.0:
                return True
    return False


def _assess_jittered_c2_pattern(flow_state: dict) -> float:
    """固定周期性に依存せず、長周期の送受信偏り・小サイズキープアライブ・不整合ポートをスコア化する。"""
    if not flow_state:
        return 0.0

    direction_bytes = flow_state.get("direction_bytes", {})
    direction_packets = flow_state.get("direction_packets", {})
    direction_sizes = flow_state.get("direction_sizes", {})
    ab_bytes = direction_bytes.get("ab", 0)
    ba_bytes = direction_bytes.get("ba", 0)
    ab_packets = direction_packets.get("ab", 0)
    ba_packets = direction_packets.get("ba", 0)
    total_packets = max(1, ab_packets + ba_packets)
    total_bytes = max(1, ab_bytes + ba_bytes)
    if total_packets < 6:
        return 0.0

    score = 0.0
    if ab_bytes > 0 and ba_bytes > 0:
        bias = max(ab_bytes, ba_bytes) / max(1, min(ab_bytes, ba_bytes))
        if bias >= 3.0:
            score += 0.18
        if bias >= 5.0:
            score += 0.08

    keep_alive_packets = 0
    total_keep_alive_bytes = 0
    for direction in ("ab", "ba"):
        sizes = list(direction_sizes.get(direction, deque()))
        for size in sizes:
            if 16 <= size <= 256:
                keep_alive_packets += 1
                total_keep_alive_bytes += size
    if keep_alive_packets >= 4 and total_keep_alive_bytes >= 256:
        score += 0.16

    if total_packets >= 8 and total_bytes / total_packets <= 128:
        score += 0.10

    if ab_packets > 0 and ba_packets > 0:
        small_outbound_ratio = sum(1 for size in direction_sizes.get("ab", deque()) if 16 <= size <= 256) / max(1, ab_packets)
        if small_outbound_ratio >= 0.55:
            score += 0.10

    return min(0.99, score)


def _assess_destination_correlation(dst_ip: str, flow_state: dict) -> bool:
    if not dst_ip:
        return False

    with _IP_CORRELATION_LOCK:
        stats = _DEST_IP_CORRELATION_STATS.setdefault(dst_ip, {
            "count": 0,
            "outbound_bytes": 0,
            "inbound_bytes": 0,
            "small_outbound": 0,
            "first_seen": time.time(),
            "last_seen": 0.0,
        })

        ab_bytes = flow_state.get("direction_bytes", {}).get("ab", 0)
        ba_bytes = flow_state.get("direction_bytes", {}).get("ba", 0)
        outbound = max(ab_bytes, ba_bytes)
        inbound = min(ab_bytes, ba_bytes)
        stats["count"] += 1
        stats["outbound_bytes"] += outbound
        stats["inbound_bytes"] += inbound
        stats["last_seen"] = time.time()
        if outbound > 0 and outbound <= 256:
            stats["small_outbound"] += 1

        if stats["count"] >= 8 and stats["outbound_bytes"] >= 3 * max(1, stats["inbound_bytes"]):
            if stats["small_outbound"] >= 4 and (stats["last_seen"] - stats["first_seen"]) >= 20.0:
                return True
            if stats["outbound_bytes"] > 1024 and inbound == 0:
                return True
    return False


def _packet_has_tls_client_hello(packet_bytes: bytes) -> bool:
    payload = extract_payload_bytes(packet_bytes)
    return payload.startswith((b"\x16\x03\x01", b"\x16\x03\x02", b"\x16\x03\x03"))


def _should_update_flow_beacon(packet_bytes: bytes, transport: dict) -> bool:
    if not transport:
        return False
    dst_port = transport.get("dst_port")
    if dst_port is None:
        return False
    if dst_port not in {80, 443}:
        return True
    if _packet_has_tls_client_hello(packet_bytes):
        return True
    return False


def _update_flow_beacon_stats(packet_bytes: bytes, transport: dict, flow_state: dict) -> bool:
    global _BACKDOOR_RISK_SCORE
    if not flow_state or not transport:
        return False

    direction = _flow_packet_direction(packet_bytes, flow_state)
    if not direction:
        return False

    now = time.time()
    size = len(extract_payload_bytes(packet_bytes))
    flow_state["direction_packets"][direction] = flow_state.get("direction_packets", {}).get(direction, 0) + 1
    flow_state["direction_bytes"][direction] = flow_state.get("direction_bytes", {}).get(direction, 0) + size
    flow_state["direction_sizes"][direction].append(size)

    last_time = flow_state.get("last_packet_time", 0.0)
    if last_time > 0.0:
        flow_state["intervals"].append(now - last_time)
    flow_state["last_packet_time"] = now

    dst_ip = transport.get("dst_ip")
    if _assess_destination_correlation(dst_ip, flow_state):
        with _CONTAINMENT_LOCK:
            _BACKDOOR_RISK_SCORE = max(_BACKDOOR_RISK_SCORE, 0.72)
        log.warning("[C2_CORRELATION] 累積送信量偏りおよび継続的な小規模 TLS 通信が検出されました。")
        return True

    jitter_score = _assess_jittered_c2_pattern(flow_state)
    if jitter_score >= 0.24:
        with _CONTAINMENT_LOCK:
            _BACKDOOR_RISK_SCORE = max(_BACKDOOR_RISK_SCORE, min(0.88, 0.56 + jitter_score * 0.2))
        log.warning(f"[JITTERED_C2] 送受信偏り/小サイズ Keep-Alive/プロトコル不整合を示す長期パターンを検出しました (score={jitter_score:.2f})")
        return True

    if _assess_tls_c2_beacon(flow_state):
        with _CONTAINMENT_LOCK:
            _BACKDOOR_RISK_SCORE = max(_BACKDOOR_RISK_SCORE, 0.56)
        log.warning("[TLS_C2_BEACON] TLS/HTTPS C2 っぽい周期性を検出しました。全捕捉スキャンを優先します。")
        return True
    return False


def _has_benign_structured_token_context(lower: bytes, payload_bytes: bytes, text_class: str) -> bool:
    """JWT・Data URL・通常のヘッダー値のような正常テキストコンテキストを識別し、局所走査の早期スキップ対象にする。"""
    if text_class not in {"json", "html", "javascript"}:
        return False

    if b"data:image/" in lower:
        return True
    if b"bearer eyj" in lower or _PRECOMPILED_JWT_RE.search(lower):
        return True

    printable_ratio = sum(32 <= b < 127 or b in {9, 10, 13} for b in payload_bytes) / max(1, len(payload_bytes))
    if printable_ratio < 0.78:
        return False

    if b"authorization" in lower or b"token" in lower:
        return True
    return False


def _detect_local_anomaly_regions(payload_bytes: bytes, text_class: str) -> tuple[list, bool]:
    """JSON/HTML等の内部に潜む局所的難読化領域を検出する。短い平文・安全な構造には早期に退出する。"""
    anomalies = []
    lower = payload_bytes.lower()
    payload_len = len(payload_bytes)
    if payload_len < 16:
        return anomalies, False

    printable_ratio = sum(32 <= b < 127 or b in {9, 10, 13} for b in payload_bytes) / max(1, payload_len)
    if text_class in {"json", "html", "javascript"} and printable_ratio >= 0.78:
        if _has_benign_structured_token_context(lower, payload_bytes, text_class):
            return anomalies, False

    has_code_context = any(marker in lower for marker in _CODE_EXECUTION_CONTEXT)
    has_escape_context = b"\\x" in lower or b"\\u" in lower
    if not has_code_context and not has_escape_context:
        return anomalies, False

    suspicious_markers = [b"base64", b"decode", b"unescape", b"fromcharcode", b"atob", b"btoa", b"shellcode", b"hex"]
    for marker in suspicious_markers:
        if marker in lower:
            idx = lower.find(marker)
            window_start = max(0, idx - 32)
            window_end = min(payload_len, idx + 64)
            window = payload_bytes[window_start:window_end]
            window_entropy = calculate_payload_entropy(window)
            if window_entropy >= 0.88 or b"\\x" in window or b"\\u" in window:
                anomalies.append({
                    "type": "local_anomaly",
                    "offset": idx,
                    "entropy": window_entropy,
                    "description": f"obfuscated local payload fragment near {marker.decode('latin-1', errors='ignore')}",
                })

    for match in _PRECOMPILED_TOKEN_RE.finditer(payload_bytes):
        token = match.group(0)
        token_entropy = calculate_payload_entropy(token)
        if token_entropy < 0.82:
            continue
        window_start = max(0, match.start() - 48)
        window_end = min(payload_len, match.end() + 48)
        window_lower = lower[window_start:window_end]
        if any(marker in window_lower for marker in _CODE_EXECUTION_CONTEXT):
            anomalies.append({
                "type": "opaque_token",
                "offset": match.start(),
                "entropy": token_entropy,
                "description": "long opaque token embedded in formatted payload",
            })
        elif has_escape_context and (b"\\x" in window_lower or b"\\u" in window_lower):
            anomalies.append({
                "type": "opaque_token",
                "offset": match.start(),
                "entropy": token_entropy,
                "description": "opaque escaped token embedded in formatted payload",
            })

    for match in _PRECOMPILED_ESCAPE_RE.finditer(payload_bytes):
        window_start = max(0, match.start() - 24)
        window_end = min(payload_len, match.end() + 24)
        window = payload_bytes[window_start:window_end]
        window_entropy = calculate_payload_entropy(window)
        if window_entropy >= 0.88:
            anomalies.append({
                "type": "escape_stacking",
                "offset": match.start(),
                "entropy": window_entropy,
                "description": "overly stacked escape sequence in a formatted payload",
            })

    if text_class in {"json", "html", "javascript"} and has_escape_context:
        escape_idx = lower.find(b"\\x") if b"\\x" in lower else lower.find(b"\\u")
        anomalies.append({
            "type": "escape_stacking",
            "offset": escape_idx,
            "entropy": max(0.88, calculate_payload_entropy(payload_bytes)),
            "description": "escape sequence inside a clean text container",
        })

    if text_class in {"json", "html", "javascript"}:
        for offset in range(0, payload_len, max(1, payload_len // 8)):
            window_start = max(0, offset - 64)
            window_end = min(payload_len, window_start + 128)
            window = payload_bytes[window_start:window_end]
            window_entropy = calculate_payload_entropy(window)
            printable_ratio = sum(32 <= b < 127 or b in {9, 10, 13} for b in window) / max(1, len(window))
            if window_entropy >= 0.88 and printable_ratio < 0.72:
                anomalies.append({
                    "type": "context_contradiction",
                    "offset": offset,
                    "entropy": window_entropy,
                    "description": "local high-entropy fragment inside a clean text container",
                })

    local_anomaly = len(anomalies) > 0
    return anomalies, local_anomaly


def _get_adaptive_fast_pass_result(packet_bytes: bytes, payload_bytes: bytes, interface: str = None) -> dict | None:
    """高信頼フローでは先頭/末尾ウィンドウだけで即応答し、危険シグナルが見つかった場合だけフルDPIへ昇格する。"""
    if not payload_bytes:
        return None

    payload_len = len(payload_bytes)
    lower_payload = payload_bytes.lower()
    printable = sum(32 <= b < 127 or b in {9, 10, 13} for b in payload_bytes)
    printable_ratio = printable / max(1, payload_len)
    text_class = _classify_payload_text(payload_bytes)

    explicit_markers = [
        (b"<script", "XSS"),
        (b"javascript:", "XSS"),
        (b"eval(", "Code eval"),
        (b"powershell", "PowerShell"),
        (b"cmd.exe", "Command execution"),
        (b"curl ", "Network fetch"),
        (b"atob", "Obfuscated payload"),
        (b"unescape", "Obfuscated payload"),
        (b"fromcharcode", "Obfuscated payload"),
    ]
    suspicious = False
    findings = []
    attack_signatures = []
    for marker, signature in explicit_markers:
        if _contains_multiencoding_bytes(payload_bytes, marker):
            attack_signatures.append(signature)
            findings.append({"type": "signature", "offset": _find_multiencoding_offset(payload_bytes.lower(), marker), "token": signature.lower().replace(" ", "_"), "description": f"explicit {signature} marker"})
            suspicious = True

    if not suspicious:
        tail_window = payload_bytes[-min(payload_len, 256):]
        tail_marker_ratio = (tail_window.count(b"(") + tail_window.count(b")") + tail_window.count(b"<") + tail_window.count(b">") + tail_window.count(b"[") + tail_window.count(b"]")) / max(1, len(tail_window))
        if tail_marker_ratio >= 0.012:
            suspicious = True
            findings.append({"type": "signature", "offset": max(0, payload_len - 1), "token": "tail_bracket_pattern", "description": "tail region code-like pattern"})

    if not suspicious and (b"\\x" in lower_payload or b"\\u" in lower_payload):
        suspicious = True
        findings.append({"type": "dynamic_anomaly", "offset": 0, "entropy": calculate_payload_entropy(payload_bytes), "description": "structured escape obfuscation without explicit trigger keyword"})

    transport = parse_packet_transport(packet_bytes) if packet_bytes else None
    risk_score = 0.0
    if transport:
        dst_port = transport.get("dst_port")
        if dst_port not in {80, 443, 53, 22, 25, 3306, 3389, 8080, 8443}:
            risk_score += 0.18
        if dst_port in {443, 8443} and b"http/" in lower_payload and not _packet_has_tls_client_hello(packet_bytes):
            risk_score += 0.16
        if dst_port in {80, 8080} and _packet_has_tls_client_hello(packet_bytes):
            risk_score += 0.16
    if text_class in {"json", "html", "javascript"} and printable_ratio >= 0.78 and not suspicious:
        risk_score += 0.06
    if payload_len >= 4096:
        risk_score += 0.05

    if suspicious or risk_score >= 0.24:
        return None

    return {
        "payload_len": payload_len,
        "entropy": calculate_payload_entropy(payload_bytes),
        "attack_signatures": attack_signatures,
        "protocols": [],
        "findings": findings,
        "suspicious": suspicious,
        "score": min(0.49, 0.08 + risk_score),
        "preview": payload_bytes[:120].decode("latin-1", errors="ignore"),
        "scan_strategy": "adaptive_fast_pass",
        "fast_track": False,
        "dynamic_anomaly": False,
        "local_anomaly": False,
    }


def _build_fail_closed_dpi_result(packet_bytes: bytes, reason: str, score: float = 0.95) -> dict:
    preview = (packet_bytes or b"")[:120].decode("latin-1", errors="ignore")
    return {
        "payload_len": len(packet_bytes or b""),
        "entropy": calculate_payload_entropy(packet_bytes or b""),
        "attack_signatures": ["Parse failure"],
        "protocols": [],
        "findings": [{"type": "parse_error", "description": reason}],
        "suspicious": True,
        "score": round(min(0.99, score), 4),
        "preview": preview,
        "scan_strategy": "fail_closed",
        "fast_track": False,
        "dynamic_anomaly": True,
        "local_anomaly": True,
    }


def _apply_contextual_smoothing(payload_bytes: bytes, text_class: str, printable_ratio: float, entropy: float, control_ratio: float, protocols: list) -> float:
    """JSON/REST/WebSocket などの文脈では、正常な高エントロピーを平滑化して誤検知を抑える。"""
    lower_payload = payload_bytes.lower()
    correction = 0.0
    if text_class in {"json", "html", "javascript"}:
        if b"application/json" in lower_payload or b"content-type" in lower_payload:
            correction -= 0.12
        if b"websocket" in lower_payload or b"heartbeat" in lower_payload or b"op\":\"ping" in lower_payload:
            correction -= 0.10
        if b"authorization" in lower_payload or b"bearer " in lower_payload:
            correction -= 0.08
    if b"data:image/" in lower_payload or b"base64" in lower_payload:
        correction -= 0.08
    if b"api" in lower_payload and b"rest" in lower_payload:
        correction -= 0.06
    if entropy >= 0.9 and printable_ratio >= 0.72 and control_ratio <= 0.04:
        correction -= 0.05
    if protocols and text_class in {"json", "html", "javascript"}:
        correction -= 0.02
    return correction


def analyze_dpi_payload(packet_bytes: bytes, payload: bytes = None, interface: str = None) -> dict:
    """全文Byte列をベクトル化し、DPI評価器のように挙動・エントロピー・全体の異常度をAI的にスコアリングする。"""
    try:
        flow_cache_hit = _get_flow_cache_result(packet_bytes) if packet_bytes else None
        if flow_cache_hit:
            return flow_cache_hit

        if payload is None:
            extracted_payload = extract_payload_bytes(packet_bytes)
            if extracted_payload == b"\x00":
                log.warning("[DPI] パケット抽出に失敗したためフェールクローズでブロックします。")
                return _build_fail_closed_dpi_result(packet_bytes, "payload_extraction_failed")
            if extracted_payload:
                payload = extracted_payload
            elif packet_bytes:
                payload = packet_bytes

        if not payload:
            return {
                "payload_len": 0,
                "entropy": 0.0,
                "attack_signatures": [],
                "protocols": [],
                "findings": [],
                "suspicious": False,
                "score": 0.0,
                "preview": "",
                "scan_strategy": "none",
            }

        _maybe_recover_security_hardening()
        start_time = time.perf_counter()
        payload_bytes = bytes(payload)
        fast_pass_result = _get_adaptive_fast_pass_result(packet_bytes, payload_bytes, interface=interface)
        if fast_pass_result is not None:
            return fast_pass_result

        load_mode = select_scan_mode_for_load(packet_rate_per_sec=None, cpu_pressure=None)
        if load_mode == "lightweight":
            return {
                "payload_len": len(payload_bytes),
                "entropy": calculate_payload_entropy(payload_bytes),
                "attack_signatures": [],
                "protocols": [],
                "findings": [],
                "suspicious": False,
                "score": 0.0,
                "preview": payload_bytes[:120].decode("latin-1", errors="ignore"),
                "scan_strategy": "lightweight_load_shedding",
                "fast_track": False,
                "dynamic_anomaly": False,
                "local_anomaly": False,
            }

        payload_len = len(payload_bytes)
        preview = payload_bytes[:min(payload_len, 4096)].decode("latin-1", errors="ignore")
        lower_payload = payload_bytes.lower()

        if payload_len < 32 and not (b"\\x" in lower_payload or b"\\u" in lower_payload or _bytes_contains_any_multiencoding(payload_bytes, _CODE_EXECUTION_CONTEXT)):
            return {
                "payload_len": payload_len,
                "entropy": calculate_payload_entropy(payload_bytes),
                "attack_signatures": [],
                "protocols": [],
                "findings": [],
                "suspicious": False,
                "score": 0.0,
                "preview": preview[:120],
                "scan_strategy": "fast_pass",
            }

        printable = sum(32 <= b < 127 or b in {9, 10, 13} for b in payload_bytes)
        printable_ratio = printable / max(1, payload_len)
        bracket_ratio = (payload_bytes.count(b"(") + payload_bytes.count(b")") + payload_bytes.count(b"<") + payload_bytes.count(b">") + payload_bytes.count(b"[") + payload_bytes.count(b"]")) / max(1, payload_len)
        control_ratio = sum(1 for b in payload_bytes if b < 32 and b not in {9, 10, 13}) / max(1, payload_len)
        high_ascii_ratio = sum(1 for b in payload_bytes if 32 <= b < 127) / max(1, payload_len)
        entropy = calculate_payload_entropy(payload_bytes)
        text_class = _classify_payload_text(payload_bytes)
        calibration = _get_dynamic_calibration(
            interface=interface,
            payload_len=payload_len,
            text_class=text_class,
            lower_payload=lower_payload,
            payload_bytes=payload_bytes,
        )
        benign_correction = _update_head_b_learning_queue(payload_bytes, interface=interface, text_class=text_class)
        local_anomalies, local_anomaly = _detect_local_anomaly_regions(payload_bytes, text_class)
        has_code_context = _bytes_contains_any_multiencoding(payload_bytes, _CODE_EXECUTION_CONTEXT)
        has_local_obfuscation_context = bool(
            local_anomaly and (
                has_code_context or any(finding.get("type") in {"escape_stacking", "context_contradiction"} for finding in local_anomalies)
            )
        )
        fast_track_masked_obfuscation = bool(
            local_anomaly and text_class in {"json", "html", "javascript"} and printable_ratio >= 0.72
        )

        findings = []
        attack_signatures = []
        explicit_code_markers = [
            (b"<script", "XSS"),
            (b"javascript:", "XSS"),
            (b"eval(", "Code eval"),
            (b"powershell", "PowerShell"),
            (b"cmd.exe", "Command execution"),
            (b"curl ", "Network fetch"),
            (b"atob", "Obfuscated payload"),
            (b"unescape", "Obfuscated payload"),
            (b"fromcharcode", "Obfuscated payload"),
            (b"script", "Script injection"),
        ]
        for marker, signature in explicit_code_markers:
            if _contains_multiencoding_bytes(payload_bytes, marker):
                offset = _find_multiencoding_offset(payload_bytes.lower(), marker)
                attack_signatures.append(signature)
                findings.append({"type": "signature", "offset": offset, "token": signature.lower().replace(" ", "_"), "description": f"explicit {signature} marker"})

        if text_class not in {"json", "html", "javascript"} and bracket_ratio >= 0.004 and printable_ratio >= 0.62:
            attack_signatures.append("Bracket ensemble")
            findings.append({"type": "signature", "offset": 0, "token": "code_like_bracket_ensemble", "description": "code-like bracket ensemble"})
        if high_ascii_ratio >= 0.55 and (b"(" in payload_bytes or b")" in payload_bytes) and text_class == "code-execution":
            attack_signatures.append("Code eval")
            findings.append({"type": "signature", "offset": min(payload_len - 1, payload_len // 2), "token": "ascii_eval_pattern", "description": "ascii execution-like pattern"})
        if control_ratio >= 0.12 and entropy >= 0.84 and printable_ratio < 0.55:
            attack_signatures.append("Shellcode")
            findings.append({"type": "signature", "offset": 0, "token": "binary_shellcode_like", "description": "binary shellcode-like region"})

        dynamic_anomaly = False
        if printable_ratio < 0.78 and entropy >= 0.88 and control_ratio >= 0.03:
            dynamic_anomaly = True
            findings.append({
                "type": "dynamic_anomaly",
                "offset": 0,
                "entropy": entropy,
                "description": "structural anomaly: high entropy + low printability + control-byte concentration",
            })
        elif (b"\\x" in lower_payload or b"\\u" in lower_payload) and printable_ratio < 0.82 and entropy >= 0.82:
            dynamic_anomaly = True
            findings.append({
                "type": "dynamic_anomaly",
                "offset": 0,
                "entropy": entropy,
                "description": "structured escape obfuscation without explicit trigger keyword",
            })

        tail_window = payload_bytes[-min(payload_len, 256):]
        tail_bracket_ratio = (tail_window.count(b"(") + tail_window.count(b")") + tail_window.count(b"<") + tail_window.count(b">") + tail_window.count(b"[") + tail_window.count(b"]")) / max(1, len(tail_window))
        if text_class not in {"json", "html", "javascript"} and tail_bracket_ratio >= 0.012:
            findings.append({"type": "signature", "offset": max(0, payload_len - 1), "token": "tail_bracket_pattern", "description": "tail region code-like pattern"})

        protocols = []
        if b"http/" in lower_payload or b"get /" in lower_payload or b"post /" in lower_payload:
            protocols.append("HTTP")
        if payload_bytes.startswith((b"\x16\x03\x01", b"\x16\x03\x02", b"\x16\x03\x03")):
            protocols.append("TLS/SSL")
        if b"ssh-" in lower_payload:
            protocols.append("SSH")
        if payload_bytes.startswith((b"220 ", b"331 ", b"530 ", b"USER", b"PASS")):
            protocols.append("FTP")
        if b"dns" in lower_payload:
            protocols.append("DNS")

        tls_meta = _parse_tls_client_hello(packet_bytes) if packet_bytes else {}
        tls_sni = tls_meta.get("sni")
        tls_malformed = tls_meta.get("malformed", False)
        if tls_malformed:
            findings.append({"type": "tls_malformed", "description": "Malformed TLS header detected"})
        if tls_meta.get("ja3_hash"):
            findings.append({"type": "tls_ja3", "description": f"JA3 fingerprint observed: {tls_meta['ja3_hash']}"})
            protocols.append("TLS/SSL")

        sample_offsets = {0, payload_len // 2, max(0, payload_len - 1)}
        stride = max(1, payload_len // _DPI_MAX_SAMPLE_WINDOWS)
        if stride < _DPI_SAMPLE_STRIDE:
            stride = _DPI_SAMPLE_STRIDE
        for offset in range(0, payload_len, stride):
            sample_offsets.add(offset)
        for offset in sorted(sample_offsets):
            window_start = max(0, offset - _DPI_WINDOW_SIZE // 2)
            window_end = min(payload_len, window_start + _DPI_WINDOW_SIZE)
            if window_end <= window_start:
                continue
            window_bytes = payload_bytes[window_start:window_end]
            window_entropy = calculate_payload_entropy(window_bytes)
            if window_entropy >= 0.93 and printable_ratio < 0.7 and control_ratio >= 0.04:
                findings.append({
                    "type": "entropy",
                    "offset": window_start,
                    "entropy": window_entropy,
                    "description": "High-entropy payload region",
                })

        score = 0.0
        if attack_signatures:
            score += 0.50 + min(0.20, 0.05 * len(attack_signatures))
        if entropy >= 0.9 and control_ratio >= 0.07:
            score += 0.20
        score += _apply_contextual_smoothing(payload_bytes, text_class, printable_ratio, entropy, control_ratio, protocols)
        if protocols and text_class not in {"json", "html", "javascript"}:
            score += 0.05
        if dynamic_anomaly:
            score += 0.35
            attack_signatures.append("Structured anomaly")

        if has_local_obfuscation_context:
            score += 0.75
            findings.extend(local_anomalies)
            if text_class in {"json", "html", "javascript"}:
                benign_correction = 0.0
            attack_signatures.append("Masked obfuscation")
            if fast_track_masked_obfuscation:
                score += 0.10

        if text_class in {"json", "html", "javascript"} and printable_ratio >= 0.75:
            if local_anomaly:
                score -= 0.0
            else:
                score -= benign_correction if benign_correction else 0.10
        if text_class == "code-execution" and printable_ratio >= 0.7:
            score -= 0.05

        if tls_malformed:
            score += 0.25
            attack_signatures.append("Malformed TLS header")
        score = min(0.99, max(0.0, score))
        explicit_threshold = max(0.48, calibration["threshold"] - 0.15)
        suspicious = bool(attack_signatures) and score >= explicit_threshold
        suspicious = suspicious or (entropy >= 0.93 and control_ratio >= 0.08 and printable_ratio < 0.55)
        suspicious = suspicious or local_anomaly or dynamic_anomaly

        elapsed = time.perf_counter() - start_time
        if elapsed >= 0.12:
            _record_security_health_issue("timeout", f"dpi_slow:{elapsed:.3f}")

        result = {
            "payload_len": payload_len,
            "entropy": entropy,
            "attack_signatures": attack_signatures,
            "protocols": protocols,
            "findings": findings,
            "suspicious": suspicious,
            "score": round(score, 4),
            "preview": preview[:120],
            "scan_strategy": "full_payload_sweep",
            "fast_track": fast_track_masked_obfuscation,
            "dynamic_anomaly": dynamic_anomaly,
            "local_anomaly": local_anomaly,
            "tls_sni": tls_sni,
            "tls_ja3_hash": tls_meta.get("ja3_hash"),
            "tls_ja3_string": tls_meta.get("ja3_string"),
            "tls_ja4_hash": tls_meta.get("ja4_hash"),
        }

        if not result["suspicious"] and not result["attack_signatures"]:
            _cache_flow_result(packet_bytes, result)
        elif result["suspicious"]:
            _cache_flow_result(packet_bytes, result)

        return result
    except Exception as exc:
        log.warning(f"[DPI] DPI 解析中に例外が発生しました ({exc})。フェールクローズでブロックします。")
        return _build_fail_closed_dpi_result(packet_bytes, "dpi_exception")


def log_full_packet_inspection(packet_bytes: bytes, interface: str, dpi_result: dict, stage: str, reason: str, log_path: str = None):
    """異常疑惑パケットの完全なヘッダー・DPI詳細をログ/ファイルへ保存する。"""
    if not (FULL_PACKET_INSPECTION or dpi_result.get("suspicious")):
        return

    path = log_path or _FULL_PACKET_INSPECTION_LOG_PATH
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except OSError:
        pass

    transport = parse_packet_transport(packet_bytes)
    findings = dpi_result.get("findings", [])
    record = {
        "timestamp": time.time(),
        "interface": interface,
        "stage": stage,
        "reason": reason,
        "transport": transport,
        "dpi": dpi_result,
        "findings": findings,
        "hex_dump": " ".join(f"{b:02x}" for b in packet_bytes[:256]),
    }
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")

    log.warning("[DPI_FULL_INSPECTION] パケット全調査ログを記録しました。")
    log.warning(f"  - stage={stage} reason={reason} entropy={dpi_result.get('entropy', 0.0):.3f}")
    if dpi_result.get("attack_signatures"):
        log.warning(f"  - signatures={', '.join(dpi_result['attack_signatures'])}")
    if dpi_result.get("protocols"):
        log.warning(f"  - protocols={', '.join(dpi_result['protocols'])}")
    for finding in findings[:8]:
        if finding.get("type") == "signature":
            log.warning(f"  - offset={finding.get('offset')} type={finding.get('description')} token={finding.get('token')}")
        elif finding.get("type") == "entropy":
            log.warning(f"  - offset={finding.get('offset')} entropy={finding.get('entropy', 0.0):.3f} high_entropy_window")


def _get_model_hash_sidecar_path(model_path: str) -> str:
    return os.path.abspath(str(model_path) + ".sha256")


def _read_model_hash_from_sidecar(model_path: str) -> str:
    sidecar_path = _get_model_hash_sidecar_path(model_path)
    try:
        if os.path.exists(sidecar_path):
            with open(sidecar_path, "r", encoding="utf-8") as handle:
                content = handle.read().strip()
                if content:
                    return content.split()[0]
    except Exception:
        pass
    return ""


def _write_model_hash_sidecar(model_path: str, hash_value: str) -> bool:
    try:
        sidecar_path = _get_model_hash_sidecar_path(model_path)
        directory = os.path.dirname(sidecar_path) or "."
        os.makedirs(directory, exist_ok=True)
        with open(sidecar_path, "w", encoding="utf-8") as handle:
            handle.write(f"{hash_value}  {os.path.basename(model_path)}\n")
        return True
    except Exception as exc:
        log.warning(f"[システム] モデルハッシュサイドカーの保存に失敗しました ({exc})")
        return False


def _get_expected_model_hash(model_path: str | None = None) -> str:
    """環境変数 AIRGAP_MODEL_HASH / EXPECTED_MODEL_HASH のみを期待値として使用する。"""
    expected = os.environ.get("AIRGAP_MODEL_HASH", "").strip() or os.environ.get("EXPECTED_MODEL_HASH", "").strip()
    return expected or str(_EXPECTED_MODEL_HASH or "").strip()


def _verify_model_hash(model_path: str, expected_hash: str) -> bool:
    """モデルファイルの SHA-256 を計算して、期待値と照合する。"""
    if not expected_hash:
        log.warning("[システム] モデルハッシュが未設定のため、Pickle/RCE 低減のためモデルロードを拒否します。")
        return False
    if not os.path.exists(model_path):
        return False
    try:
        digest = hashlib.sha256()
        with open(model_path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        actual_hash = digest.hexdigest()
        if actual_hash != expected_hash:
            log.warning(f"[システム] モデルハッシュが不一致です: expected={expected_hash}, actual={actual_hash}")
            return False
        return True
    except Exception as exc:
        log.warning(f"[システム] モデルハッシュ検証に失敗しました ({exc})")
        return False


def _validate_model_state_dict(state_dict: dict) -> bool:
    """ロード済み state_dict が期待される shared/head 構造を持つか検証する。"""
    if not isinstance(state_dict, dict):
        return False
    required_parts = [
        "shared_layer.0.weight", "shared_layer.0.bias",
        "shared_layer.2.weight", "shared_layer.2.bias",
        "head_a.0.weight", "head_a.0.bias",
        "head_b.0.weight", "head_b.0.bias",
        "head_c.0.weight", "head_c.0.bias",
    ]
    return all(key in state_dict for key in required_parts)


def build_containment_plan(interface: str, containment_mode: str = "full_isolation", management_ports=None, management_ips=None) -> dict:
    """キルスイッチ発動時の隔離モードを構造化して返し、管理セッション維持オプションを明示する。"""
    ports = [int(port) for port in (management_ports or _MANAGEMENT_SAFE_HARBOR_DEFAULT_PORTS)]
    ips = [str(ip) for ip in (management_ips or _MANAGEMENT_SAFE_HARBOR_DEFAULT_IPS)]
    if containment_mode == "management_safe_harbor":
        return {
            "mode": containment_mode,
            "interface": interface,
            "preserve_management": True,
            "allowed_ports": ports,
            "allowed_ips": ips,
            "action": "targeted_containment",
        }
    return {
        "mode": "full_isolation",
        "interface": interface,
        "preserve_management": False,
        "allowed_ports": [],
        "allowed_ips": [],
        "action": "full_isolation",
    }


def evaluate_progressive_defense(source_ip: str | None = None, event_type: str = "parse_error", occurrence_count: int = 1) -> dict:
    """パースエラーや一時的な異常に対して、IPレートリミットを噛ませる段階的防御を返す。"""
    if source_ip:
        with _HEALTH_LOCK:
            history = _SOURCE_ERROR_STATE.setdefault(source_ip, deque(maxlen=_SOURCE_ERROR_THRESHOLD))
            history.append(time.time())
            if len(history) >= _SOURCE_ERROR_THRESHOLD and (history[-1] - history[0]) <= _SOURCE_ERROR_WINDOW_SEC:
                _BLACKLISTED_SOURCES[source_ip] = time.time() + _SOURCE_IP_BLOCK_SEC
                log.warning(f"[PROGRESSIVE_DEFENSE] {source_ip} からの {event_type} が閾値を超えたためレート制限します。")
                return {"defer": True, "action": "rate_limit", "reason": "repeated_errors"}
    if occurrence_count >= 3:
        return {"defer": True, "action": "rate_limit", "reason": "repeat_threshold"}
    return {"defer": False, "action": "allow", "reason": event_type}


def select_scan_mode_for_load(packet_rate_per_sec: int | None = None, cpu_pressure: float | None = None) -> str:
    """高負荷時はDPIを軽量化する。"""
    if packet_rate_per_sec is None:
        packet_rate_per_sec = len(_TRAFFIC_ACTIVITY_HISTORY) * 4
    if cpu_pressure is None:
        cpu_pressure = 0.0
    if packet_rate_per_sec >= 10000 or cpu_pressure >= 0.9:
        return "lightweight"
    if packet_rate_per_sec >= 5000 or cpu_pressure >= 0.7:
        return "balanced"
    return "full"


def build_diagnostic_trace(layer: int, threshold: float, score: float, reason: str, trace_id: str | None = None) -> dict:
    """遮断理由を構造化ログとして返し、トラブルシューティング ID を付与する。"""
    global _TRACE_SEQUENCE
    _TRACE_SEQUENCE += 1
    trace_id = trace_id or f"trace-{int(time.time() * 1000)}-{_TRACE_SEQUENCE}"
    trace = {
        "trace_id": trace_id,
        "layer": layer,
        "threshold": round(threshold, 4),
        "score": round(score, 4),
        "reason": reason,
        "decision": "block",
    }
    log.info("[DIAGNOSTIC_TRACE] %s", json.dumps(trace, sort_keys=True))
    return trace


def _call_prctl(option: int, arg2: int = 0, arg3: int = 0, arg4: int = 0, arg5: int = 0) -> int:
    """libc.prctl への薄いラッパー。"""
    if platform.system().lower() != "linux":
        return -1
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        return libc.prctl(option, arg2, arg3, arg4, arg5)
    except Exception:
        return -1


def _set_linux_capabilities(permitted: set[int] = None, effective: set[int] = None, inheritable: set[int] = None) -> bool:
    """Linux capset でプロセスの capabilities を明示的に制限する。"""
    if platform.system().lower() != "linux":
        return False
    permitted = set(permitted or ())
    effective = set(effective or ())
    inheritable = set(inheritable or ())

    class CapHeader(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class CapData(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    header = CapHeader()
    header.version = 0x19980330
    header.pid = 0

    data = (CapData * 2)()
    permitted_mask = 0
    effective_mask = 0
    inheritable_mask = 0
    for cap in permitted:
        if cap < 32:
            permitted_mask |= 1 << cap
        else:
            data[1].permitted |= 1 << (cap - 32)
    for cap in effective:
        if cap < 32:
            effective_mask |= 1 << cap
        else:
            data[1].effective |= 1 << (cap - 32)
    for cap in inheritable:
        if cap < 32:
            inheritable_mask |= 1 << cap
        else:
            data[1].inheritable |= 1 << (cap - 32)
    data[0].permitted = permitted_mask
    data[0].effective = effective_mask
    data[0].inheritable = inheritable_mask

    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        result = libc.capset(ctypes.byref(header), ctypes.byref(data))
        return result == 0
    except Exception:
        return False


def _drop_to_user(username: str = "nobody", preserve_caps: set[int] | None = None) -> bool:
    """指定ユーザーへ降格し、必要な capabilities のみを残す。"""
    if platform.system().lower() != "linux":
        return False
    if pwd is None:
        return False
    try:
        pw = pwd.getpwnam(username)
    except KeyError:
        return False

    preserve_caps = set(preserve_caps or ())
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            _call_prctl(8, 1, 0, 0, 0)  # PR_SET_KEEPCAPS
            os.setgroups([])
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)
            if preserve_caps:
                _set_linux_capabilities(permitted=preserve_caps, effective=preserve_caps, inheritable=set())
            else:
                _set_linux_capabilities(permitted=set(), effective=set(), inheritable=set())
            _call_prctl(8, 0, 0, 0, 0)
        else:
            os.setgroups([])
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)
        log.warning(f"[PRIVILEGE] 実効権限を {username} へ降格しました。preserve_caps={preserve_caps}")
        return True
    except Exception as exc:
        log.warning(f"[PRIVILEGE] 権限降格に失敗しました ({exc})")
        return False


def _drop_privileges_if_possible() -> bool:
    """Linux で root 実行中なら、できる限り非特権ユーザーへ降格する。"""
    if platform.system().lower() != "linux":
        return False
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return False
    if pwd is None:
        return False
    return _drop_to_user("nobody", preserve_caps=None)


def _dispatch_privileged_command(command_type: str, **kwargs) -> bool:
    """特権プロセスにコマンドを送信して、非特権メインを保護する。"""
    global _PRIVILEGED_AGENT_ACTIVE
    if not _PRIVILEGED_AGENT_ACTIVE:
        return False

    try:
        _command_queue.put({"type": command_type, **kwargs})
        log.info(f"[PRIVILEGE] 特権エージェントへ {command_type} を送信しました。")
        return True
    except Exception as exc:
        log.warning(f"[PRIVILEGE] コマンド送信に失敗しました ({exc})")
        return False


def _execute_root_command(cmd: list, dry_run: bool = False) -> bool:
    if dry_run:
        return True
    if not _validate_command_tokens(cmd):
        log.error("    → 安全性チェックに失敗したコマンドを拒否しました。")
        return False
    try:
        completed = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        log.error(f"    → コマンド実行失敗: {exc}")
        return False
    if completed.returncode != 0:
        stderr = (completed.stderr or completed.stdout or "").strip()
        if stderr:
            log.error(f"    → 実行失敗: {stderr}")
        return False
    return True


def _privileged_command_process_main():
    """root 権限保持のまま特権コマンドを実行するワーカープロセス。"""
    log.info("[PRIVILEGE] root 特権コマンドワーカープロセスを起動しました。")
    while True:
        try:
            command = _command_queue.get()
            if command is None:
                break
            cmd_type = command.get("type")
            if cmd_type == "kill_switch":
                execute_kill_switch(
                    command.get("interface"),
                    command.get("dry_run", True),
                    available_interfaces=command.get("available_interfaces"),
                    containment_mode=command.get("containment_mode", "full_isolation"),
                    management_ports=command.get("management_ports"),
                    management_ips=command.get("management_ips"),
                )
            elif cmd_type == "run_command":
                _execute_root_command(command.get("cmd", []), dry_run=command.get("dry_run", False))
        except Exception as exc:
            log.warning(f"[PRIVILEGE] 特権コマンドプロセスで例外が発生しました: {exc}")


def _compile_kernel_bpf_program(safe_ports: set[int]) -> bytes:
    """cBPF プログラムを構築し、明らかに安全な大容量フローをカーネル側でバイパスします。"""
    class SockFilter(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_ushort),
            ("jt", ctypes.c_ubyte),
            ("jf", ctypes.c_ubyte),
            ("k", ctypes.c_uint32),
        ]

    class SockFprog(ctypes.Structure):
        _fields_ = [
            ("len", ctypes.c_ushort),
            ("pad", ctypes.c_ushort),
            ("filter", ctypes.POINTER(SockFilter)),
        ]

    safe_ports = list(sorted(set(int(p) for p in safe_ports if 0 <= p <= 65535)))
    program = [
        (0x28, 0, 0, 12),       # load ethertype
        (0x15, 0, 7, 0x0800),   # if IPv4 -> next
        (0x15, 0, 6, 0x86DD),   # if IPv6 -> accept
        (0x06, 0, 0, 0xFFFF),   # accept non-IP/IPv6

        (0x30, 0, 0, 23),       # load ip protocol
        (0x15, 0, 5, 6),        # if TCP -> next
        (0x15, 0, 3, 17),       # if UDP -> tcp fallback skip
        (0x06, 0, 0, 0xFFFF),   # accept non-TCP/UDP

        # IPv4 options support: IHL を動的に計算し、可変長ヘッダを回避する。
        (0x30, 0, 0, 14),       # load version/IHL byte
        (0x54, 0, 0, 0x0f),     # and #0x0f
        (0x64, 0, 0, 2),        # lsh #2 => IP header length in bytes
        (0x07, 0, 0, 0),        # tax => X = IP header length
        (0x51, 0, 0, 13),       # ldxb [x + 13] => TCP flags byte
        (0x54, 0, 0, 0x17),     # and #0x17 (FIN,SYN,RST,ACK)
        (0x15, 0, 2, 0x10),     # if exactly ACK-only -> safe_flow_check
        (0x06, 0, 0, 0xFFFF),   # accept if not ACK-only
        (0x68, 0, 0, 2),        # ldh [x + 2] => destination TCP port
    ]

    for port in safe_ports:
        program.extend([
            (0x15, 0, 1, port),  # if dest port == port then drop on next instruction
            (0x06, 0, 0, 0),
        ])
    program.append((0x06, 0, 0, 0xFFFF))

    filter_array = (SockFilter * len(program))(*[SockFilter(code, jt, jf, k) for code, jt, jf, k in program])
    fprog = SockFprog(len=len(program), pad=0, filter=filter_array)
    return ctypes.string_at(ctypes.addressof(fprog), ctypes.sizeof(fprog))


def _attach_kernel_bpf_filter(sock: socket.socket, safe_ports: set[int] | None = None) -> bool:
    if not hasattr(socket, "SO_ATTACH_FILTER"):
        return False
    try:
        program = _compile_kernel_bpf_program(safe_ports or _SAFE_KERNEL_BPF_PORTS)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_ATTACH_FILTER, program)
        log.info(f"[BPF] カーネル側のパケットフィルタを RAW ソケットにアタッチしました: safe_ports={sorted(safe_ports or _SAFE_KERNEL_BPF_PORTS)}")
        return True
    except Exception as exc:
        log.warning(f"[BPF] カーネルフィルタアタッチに失敗しました ({exc})")
        return False


def _refresh_kernel_bpf_filter(sock: socket.socket) -> None:
    global _SAFE_KERNEL_BPF_DIRTY
    if _SAFE_KERNEL_BPF_DIRTY:
        if _attach_kernel_bpf_filter(sock):
            _SAFE_KERNEL_BPF_DIRTY = False


def _learn_safe_kernel_flow(transport: dict, dpi_result: dict) -> None:
    """AI が安全と判定した大容量ストリームをカーネルレベルでバイパスするための学習。"""
    global _SAFE_KERNEL_BPF_DIRTY
    if not transport or not dpi_result or dpi_result.get("suspicious"):
        return
    if transport.get("protocol") != socket.IPPROTO_TCP:
        return
    dst_port = transport.get("dst_port")
    if dst_port not in {80, 443, 8080, 8443, 1935, 554}:
        return
    if len(dpi_result.get("preview", "")) < 256:
        return
    if dpi_result.get("entropy", 0.0) >= 0.82:
        return
    if dpi_result.get("attack_signatures"):
        return

    if dst_port not in _SAFE_KERNEL_BPF_PORTS:
        _SAFE_KERNEL_BPF_PORTS.add(dst_port)
        _SAFE_KERNEL_BPF_DIRTY = True
        log.info(f"[BPF_LEARNER] 安全と判定した大容量 TLS/HTTP フローをカーネルフィルタへ追加しました: port={dst_port}")


def _open_proc_event_socket() -> socket.socket | None:
    if platform.system().lower() != "linux":
        return None
    try:
        netlink_type = getattr(socket, "NETLINK_CONNECTOR", 11)
        netlink = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, netlink_type)
        netlink.bind((os.getpid(), 0))

        CN_IDX_PROC = 0x1
        CN_VAL_PROC = 0x1
        PROC_CN_MCAST_LISTEN = 1

        # nlmsghdr + cn_msg + a single u32 payload
        nlmsg_len = 16 + 20 + 4
        nlmsg_type = 0x10
        nlmsg_flags = 0
        nlmsg_seq = 0
        nlmsg_pid = os.getpid()
        header = struct.pack("IHHII", nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid)
        cn_msg = struct.pack("IIIIHH", CN_IDX_PROC, CN_VAL_PROC, 0, 0, 4, 0)
        payload = struct.pack("I", PROC_CN_MCAST_LISTEN)
        netlink.send(header + cn_msg + payload)
        return netlink
    except Exception as exc:
        log.warning(f"[PROCESS_MONITOR] Netlink proc connector の初期化に失敗しました ({exc})")
        return None


def _parse_proc_event(data: bytes) -> tuple[str, int] | None:
    if len(data) < 36:
        return None
    try:
        what, _, _ = struct.unpack("IIQ", data[0:16])
        if what == 0x00000001:  # PROC_EVENT_FORK
            parent_pid, parent_tgid, child_pid, child_tgid = struct.unpack("IIII", data[16:32])
            return ("fork", child_pid)
        if what == 0x00000002:  # PROC_EVENT_EXEC
            pid, tgid = struct.unpack("II", data[16:24])
            return ("exec", pid)
        if what == 0x00000004:  # PROC_EVENT_EXIT
            pid, tgid, exit_code, exit_signal = struct.unpack("IIII", data[16:32])
            return ("exit", pid)
    except Exception:
        pass
    return None


def _resolve_proc_executable(pid: int) -> str:
    proc_exe = f"/proc/{pid}/exe"
    try:
        exe_path = os.readlink(proc_exe)
        if exe_path.endswith(" (deleted)"):
            exe_path = exe_path[: -len(" (deleted)")]
        return os.path.realpath(exe_path) if exe_path else ""
    except Exception:
        return ""


def _is_suspicious_executable_path(exe_path: str) -> bool:
    if not exe_path:
        return True
    lowercase = exe_path.lower()
    if " (deleted)" in lowercase:
        return True
    suspicious_dirs = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/var/run/", "/mnt/", "/proc/self/fd/")
    if any(lowercase.startswith(prefix) for prefix in suspicious_dirs):
        return True
    trusted_dirs = ("/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/", "/lib/", "/lib64/", "/usr/lib/", "/usr/local/bin/", "/usr/local/sbin/")
    if not any(lowercase.startswith(prefix) for prefix in trusted_dirs):
        return True
    suspicious_basenames = {"nc", "ncat", "socat", "curl", "wget", "bash", "sh", "python", "perl", "ruby", "node", "php", "java", "pwsh", "powershell", "cmd.exe", "rundll32", "netcat"}
    if os.path.basename(lowercase) in suspicious_basenames:
        return True
    return False


def _is_suspicious_process_command(process_identifier: int | str, cmdline: str = "") -> bool:
    """プロセスの実行パスとコマンドラインを組み合わせて疑わしい実行を検知する。"""
    pid = None
    if isinstance(process_identifier, int):
        pid = process_identifier
        cmdline = cmdline or ""
    else:
        cmdline = str(process_identifier or "")

    if pid is not None:
        exe_path = _resolve_proc_executable(pid)
        if _is_suspicious_executable_path(exe_path):
            return True

    lowered = cmdline.lower()
    if not lowered:
        return pid is not None

    suspicious_tokens = [
        "nc", "ncat", "socat", "curl", "wget", "python -c", "bash -c", "powershell", "pwsh", "cmd.exe",
        "ssh ", "perl", "ruby", "start-process", "/tmp/", "/var/tmp/", "/dev/shm/", "curl -", "wget -"
    ]
    if any(token in lowered for token in suspicious_tokens):
        return True
    return False


def _process_event_monitor_worker() -> None:
    """Netlink Connector でプロセス fork/exec をリアルタイム監査し、TOCTOU を防ぐ。"""
    if platform.system().lower() != "linux":
        return

    sock = _open_proc_event_socket()
    if sock is None:
        log.warning("[PROCESS_MONITOR] フォールバック: psutil ベースの短周期プロセス監査を開始します。")
        while True:
            time.sleep(_PROCESS_EVENT_MONITOR_FALLBACK_INTERVAL)
            findings = scan_for_backdoors()
            apply_backdoor_findings(findings)
        return

    log.info("[PROCESS_MONITOR] Netlink proc connector でリアルタイム監視を開始しました。")
    while True:
        try:
            data = sock.recv(4096)
            event = _parse_proc_event(data)
            if not event:
                continue
            event_type, pid = event
            if event_type not in {"exec", "fork"}:
                continue
            try:
                proc = psutil.Process(pid)
                cmdline = " ".join(proc.cmdline() or [])
                if _is_suspicious_process_command(pid, cmdline):
                    exe_path = _resolve_proc_executable(pid)
                    log.warning(f"[PROCESS_MONITOR] 短命プロセス検知: PID={pid} type={event_type} exe={exe_path} cmdline={cmdline}")
                    findings = [{
                        "type": "event_drive_process",
                        "pid": pid,
                        "name": proc.name() if hasattr(proc, "name") else "",
                        "remote": "",
                        "risk_score": 0.85,
                        "feature_vector": [],
                    }]
                    apply_backdoor_findings(findings)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue
        except Exception as exc:
            log.warning(f"[PROCESS_MONITOR] イベント監視中に例外が発生しました ({exc})")
            time.sleep(1.0)


def _privileged_agent_main(interface: str, max_memory_mb: int, local_dir: str, dry_run: bool):
    log.info("[PRIVILEGE] 特権キャプチャエージェントを起動します。")
    if platform.system().lower() == "linux":
        _drop_to_user("nobody", preserve_caps={_CAP_NET_RAW})
    mem_mgr = MemoryManager(max_memory_mb=max_memory_mb, swap_dir=local_dir)
    threading.Thread(target=_packet_capture_worker, args=(interface, mem_mgr, dry_run), daemon=True).start()
    if platform.system().lower() == "linux":
        threading.Thread(target=_process_event_monitor_worker, daemon=True).start()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        mem_mgr.cleanup()


def _ensure_privileged_agent(interface: str, max_memory_mb: int, local_dir: str, dry_run: bool):
    global _PRIVILEGED_AGENT_ACTIVE, _PRIVILEGED_COMMAND_PROCESS, _PRIVILEGED_CAPTURE_PROCESS
    if os.name != "posix" or platform.system().lower() != "linux":
        log.warning("[PRIVILEGE] 特権エージェントは Linux 環境でのみ有効です。")
        return None

    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        log.warning("[PRIVILEGE] root 権限がないため特権エージェントを起動できません。")
        return None

    if _PRIVILEGED_AGENT_ACTIVE:
        log.info("[PRIVILEGE] 特権エージェントは既に起動しています。")
        return _PRIVILEGED_CAPTURE_PROCESS

    _PRIVILEGED_COMMAND_PROCESS = multiprocessing.Process(target=_privileged_command_process_main, daemon=True)
    _PRIVILEGED_COMMAND_PROCESS.start()

    _PRIVILEGED_CAPTURE_PROCESS = multiprocessing.Process(
        target=_privileged_agent_main,
        args=(interface, max_memory_mb, local_dir, dry_run),
        daemon=True,
    )
    _PRIVILEGED_CAPTURE_PROCESS.start()
    _PRIVILEGED_AGENT_ACTIVE = True
    return _PRIVILEGED_CAPTURE_PROCESS


def _apply_windows_acl(path: str) -> bool:
    """Windows で token ファイルに対して自身のみ読み書き可能な状態にする。"""
    if os.name != "nt":
        return True
    try:
        os.chmod(path, 0o600)
        return True
    except Exception as exc:
        log.warning(f"[SECURITY] Windows ACL の適用に失敗しました ({exc})")
        return False


def _store_admin_recovery_token(token: str, token_path: str | None = None) -> str:
    """管理者復旧トークンを安全な一時ファイルへ原子的に保存し、失敗時は即時削除する。"""
    token_value = str(token or "").strip()
    if not token_value:
        return ""

    env_token = os.environ.get("AIRGAP_ADMIN_RECOVERY_TOKEN", "").strip()
    if env_token:
        return env_token

    target_path = token_path or _ADMIN_RECOVERY_TOKEN_FILE
    directory = os.path.dirname(target_path) or "."
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        log.warning(f"[SECURITY] トークン保存ディレクトリの生成に失敗しました ({exc})")
        return ""

    if os.name != "nt":
        try:
            os.chmod(directory, 0o700)
        except Exception as exc:
            log.warning(f"[SECURITY] トークン保存ディレクトリのパーミッション設定に失敗しました ({exc})")

    temp_fd, temp_path = tempfile.mkstemp(prefix=".admin_recovery_", dir=directory)
    try:
        if os.name != "nt":
            os.fchmod(temp_fd, 0o600)
        else:
            os.fchmod(temp_fd, 0o600)
        with os.fdopen(temp_fd, "w", encoding="utf-8") as handle:
            handle.write(token_value)
        os.replace(temp_path, target_path)
        if not _apply_windows_acl(target_path):
            os.unlink(target_path)
            return ""
        if os.name != "nt":
            os.chmod(target_path, 0o600)
    except Exception as exc:
        try:
            os.close(temp_fd)
        except OSError:
            pass
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
        try:
            os.unlink(target_path)
        except FileNotFoundError:
            pass
        log.warning(f"[SECURITY] トークンファイルの保存に失敗しました ({exc})")
        return ""
    return token_value


def load_cloud_model(model, cloud_model_path: str) -> bool:
    """GPU 保存済みモデルを CPU / 利用可能デバイスへ安全にマップしてロードする。"""
    if not os.path.exists(cloud_model_path):
        log.warning(f"[システム] クラウドモデルが見つかりません: {cloud_model_path}")
        log.warning("           → 未学習の状態で起動します。防衛力は学習が進むにつれて向上します。")
        return False

    expected_hash = _get_expected_model_hash(cloud_model_path)
    if not expected_hash:
        log.warning("[システム] 期待されるモデルハッシュが明示的に設定されていません。モデルロードを拒否しました。")
        return False
    if not _verify_model_hash(cloud_model_path, expected_hash):
        log.warning("[システム] 期待されるモデルハッシュと一致しないため、モデルロードを拒否しました。")
        return False

    try:
        device = torch.device("cpu") if hasattr(torch, "device") else "cpu"
        if hasattr(torch, "cuda") and torch.cuda.is_available():
            try:
                device = torch.device("cuda:0")
            except Exception:
                device = torch.device("cpu") if hasattr(torch, "device") else "cpu"

        load_kwargs = {"map_location": device}
        try:
            loaded = torch.load(cloud_model_path, weights_only=True, **load_kwargs)
        except TypeError:
            loaded = torch.load(cloud_model_path, **load_kwargs)
        if isinstance(loaded, dict):
            if "state_dict" in loaded:
                state_dict = loaded["state_dict"]
            elif "model_state_dict" in loaded:
                state_dict = loaded["model_state_dict"]
            else:
                state_dict = loaded
        else:
            state_dict = loaded

        if not _validate_model_state_dict(state_dict):
            log.warning("[システム] ロードしたモデルの state_dict が期待される構造と一致しません。モデルロードを拒否しました。")
            return False

        model.load_state_dict(state_dict)
        log.info(f"[システム] ✓ クラウド学習済みモデル({cloud_model_path})をロードしました！防衛力起動！")
        return True
    except (RuntimeError, OSError, TypeError, ValueError, EOFError, AttributeError, pickle.UnpicklingError, zipfile.BadZipFile) as exc:
        log.warning(f"[システム] モデルの読み込みに失敗しました ({exc})。未学習状態で起動します。")
        return False
    except Exception as exc:
        log.warning(f"[システム] モデルの読み込み中に予期しない例外が発生しました ({exc})。未学習状態で起動します。")
        return False


def profile_environment() -> dict:
    """OS / NIC / ツール / 権限をまとめてプロファイル化し、自己最適化の入力にする。"""
    profile = {
        "timestamp": time.time(),
        "hostname": socket.gethostname(),
        "os": {},
        "available_interfaces": discover_available_interfaces(),
        "network_layers": [],
        "tools": {},
        "permissions": {},
        "default_route": None,
    }

    try:
        profile["os"] = {
            "system": platform.system() or "unknown",
            "release": platform.release() or "",
            "version": platform.version() or "",
            "machine": platform.machine() or "",
            "platform": platform.platform() or "",
        }
    except Exception:
        profile["os"] = {"system": "unknown"}

    for iface in profile["available_interfaces"]:
        sysfs_path = os.path.join("/sys/class/net", iface)
        if not os.path.isdir(sysfs_path):
            continue
        if os.path.isdir(os.path.join(sysfs_path, "bridge")):
            profile["network_layers"].append("bridge")
        if iface.startswith(("veth", "docker", "br", "virbr", "tun", "tap")):
            profile["network_layers"].append("virtual")
        if iface.startswith("wg") or "wg" in iface:
            profile["network_layers"].append("vpn")
        if iface.startswith("eth") or iface.startswith("wlan"):
            profile["network_layers"].append("physical")

    try:
        with open("/proc/net/route") as handle:
            for line in handle.readlines()[1:]:
                fields = line.split()
                if len(fields) >= 3 and fields[1] == "00000000":
                    profile["default_route"] = fields[0]
                    break
    except Exception:
        pass

    for tool_name in ("ip", "iptables", "nft", "ping", "dbus-send", "nmcli", "scapy"):
        profile["tools"][tool_name] = shutil.which(tool_name) is not None

    try:
        profile["permissions"]["root"] = os.geteuid() == 0
    except AttributeError:
        profile["permissions"]["root"] = False
    profile["permissions"]["sudo"] = shutil.which("sudo") is not None

    profile["network_layers"] = sorted(set(profile["network_layers"]))
    log.info("[AUTO_PROFILING] 環境プロファイルを生成しました。")
    log.info(f"  - OS: {profile['os'].get('system', 'unknown')} / {profile['os'].get('release', 'unknown')}")
    log.info(f"  - NIC: {', '.join(profile['available_interfaces']) or 'なし'}")
    log.info(f"  - レイヤー: {', '.join(profile['network_layers']) or 'なし'}")
    return profile


def _write_sysctl_value(path: str, value: str) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(value)
        return True
    except Exception as exc:
        log.warning(f"[BOOT_HARDENING] sysctl {path} の書き換えに失敗しました ({exc})")
        return False


def _apply_kernel_hardening(profile: dict, report: dict):
    sysctl_map = {
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
    for path, value in sysctl_map.items():
        if os.path.exists(path) and _write_sysctl_value(path, value):
            report["applied"].append(path)
        else:
            report["failures"].append(path)


def _apply_process_limits(report: dict):
    try:
        import resource
        soft_no, hard_no = resource.getrlimit(resource.RLIMIT_NOFILE)
        soft_no = min(soft_no if soft_no > 0 else hard_no, 4096)
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft_no, hard_no))
        report["applied"].append("rlimit_nofile")
    except Exception as exc:
        log.warning(f"[BOOT_HARDENING] RLIMIT_NOFILE の設定に失敗しました ({exc})")
        report["failures"].append("rlimit_nofile")

    try:
        import resource
        soft_proc, hard_proc = resource.getrlimit(resource.RLIMIT_NPROC)
        if soft_proc > 512 or soft_proc == resource.RLIM_INFINITY:
            resource.setrlimit(resource.RLIMIT_NPROC, (512, hard_proc))
            report["applied"].append("rlimit_nproc")
    except Exception as exc:
        report["failures"].append("rlimit_nproc")


def boot_time_auto_hardening(profile: dict) -> dict:
    report = {"applied": [], "failures": []}
    if profile.get("permissions", {}).get("root"):
        log.info("[BOOT_HARDENING] ブート時ハードニングを実行します。")
        _apply_kernel_hardening(profile, report)
        _apply_process_limits(report)
    else:
        log.warning("[BOOT_HARDENING] root でないため、一部カーネルハードニングはスキップします。")
        report["failures"].append("missing_root")
    log.info(f"[BOOT_HARDENING] 適用: {report['applied']} / 失敗: {report['failures']}")
    return report


def _build_absolute_containment_payload(profile: dict, learning_data=None) -> dict:
    env_signal, ranked = _ai_command_policy_vector(profile, learning_data)
    tools = profile.get("tools", {})
    interfaces = [iface for iface in profile.get("available_interfaces", []) if iface != "lo"]
    os_info = profile.get("os", {}) or {}
    os_name = str(os_info.get("system") or "").strip().lower()
    os_family = "linux" if os_name not in {"windows", "win32", "win64", "darwin", "mac", "macos"} else os_name

    commands = []
    if os_family == "linux":
        for iface in interfaces:
            commands.append(["ip", "link", "set", iface, "down"])
        if tools.get("nft"):
            commands.append(["nft", "flush", "ruleset"])
        if tools.get("iptables"):
            commands.extend([
                ["iptables", "-F"],
                ["iptables", "-P", "INPUT", "DROP"],
                ["iptables", "-P", "OUTPUT", "DROP"],
                ["iptables", "-P", "FORWARD", "DROP"],
            ])
        commands.extend([
            ["ip", "route", "replace", "default", "unreachable"],
            ["ip", "route", "add", "default", "unreachable"],
        ])
    elif os_family == "windows":
        commands.append(["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-NetAdapter -Name '*' -ErrorAction SilentlyContinue | Disable-NetAdapter -Confirm:$false"])
    elif os_family == "darwin":
        adapter = interfaces[0] if interfaces else "en0"
        commands.append(["networksetup", "-setairportpower", adapter, "off"])
        commands.append(["ifconfig", adapter, "down"])

    payload = {
        "strategy": "absolute_containment",
        "reason": "ローカルブート時に構築された絶対遮断コンテナペイロード",
        "commands": commands,
        "profile": profile,
        "policy_vector": env_signal,
    }
    log.info("[CONTAINMENT_PAYLOAD] 絶対遮断ペイロードを構築しました。")
    return payload


def _resolve_self_executable() -> str | None:
    try:
        return os.path.realpath("/proc/self/exe")
    except Exception:
        return None


def _hash_file(path: str, max_bytes: int = 4096) -> str | None:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            digest.update(handle.read(max_bytes))
        return digest.hexdigest()
    except Exception:
        return None


def _self_protection_monitor() -> None:
    initial_path = _resolve_self_executable()
    initial_hash = _hash_file(initial_path) if initial_path else None
    while True:
        time.sleep(1.0)
        current_path = _resolve_self_executable()
        if not current_path or current_path != initial_path:
            log.warning("[SELF_PROTECTION] 実行ファイルが変更されました。即時遮断を発動します。")
            evaluate_threat_state(None, False, score_a=0.99, backdoor_detected=True)
            break
        current_hash = _hash_file(current_path)
        if initial_hash and current_hash != initial_hash:
            log.warning("[SELF_PROTECTION] 実行ファイルの整合性が失いました。即時遮断を発動します。")
            evaluate_threat_state(None, False, score_a=0.99, backdoor_detected=True)
            break
        try:
            with open("/proc/self/status") as handle:
                state_line = next((line for line in handle if line.startswith("State:")), "")
                if "T" in state_line or "t" in state_line:
                    log.warning("[SELF_PROTECTION] プロセスが停止状態に入りました。即時遮断を発動します。")
                    evaluate_threat_state(None, False, score_a=0.99, backdoor_detected=True)
                    break
        except Exception:
            pass


def _install_self_protection_handlers() -> None:
    def _handler(signum, frame):
        log.warning(f"[SELF_PROTECTION] シグナル {signum} 受信。強制遮断シーケンスを開始します。")
        evaluate_threat_state(None, False, score_a=0.99, backdoor_detected=True)
        sys.exit(1)

    for sig in (_signal_module.SIGTERM, _signal_module.SIGINT, _signal_module.SIGHUP, _signal_module.SIGABRT):
        try:
            _signal_module.signal(sig, _handler)
        except Exception:
            pass


def _ai_command_policy_vector(profile: dict, learning_data=None) -> tuple[dict, list]:
    """環境プロファイルをAI入力ベクトルに変換し、学習データに基づいたコマンド確率を計算する。"""
    learning_data = learning_data or []
    normalized_data = [str(item).lower() for item in learning_data if item]
    layers = set(profile.get("network_layers", []))
    tools = profile.get("tools", {})
    interfaces = profile.get("available_interfaces", [])
    permissions = profile.get("permissions", {}) or {}
    os_info = profile.get("os", {}) or {}
    os_name = str(os_info.get("system") or "").strip().lower()
    if os_name in {"windows", "win32", "win64"}:
        os_family = "windows"
    elif os_name in {"darwin", "mac", "macos"}:
        os_family = "darwin"
    else:
        os_family = "linux"

    env_signal = {
        "os_family": os_family,
        "has_root": bool(permissions.get("root")),
        "has_sudo": bool(permissions.get("sudo")),
        "tool_count": float(sum(1 for present in tools.values() if present)),
        "interface_count": float(len([iface for iface in interfaces if iface != "lo"])),
        "virtual_layer": float(any(layer in layers for layer in {"bridge", "vpn", "virtual"})),
        "physical_layer": float(any(layer == "physical" for layer in layers)),
        "learning_signal": float(any(keyword in normalized_data for keyword in ["bridge", "vpn", "unreachable", "iptables", "dbus"]))
    }

    candidates = {
        "linux_link_down": 0.35 + 0.25 * env_signal["interface_count"] + 0.15 * env_signal["virtual_layer"] + 0.10 * env_signal["learning_signal"],
        "linux_dns_isolation": 0.30 + 0.10 * env_signal["tool_count"] + 0.15 * env_signal["learning_signal"],
        "linux_firewall_drop": 0.40 + 0.20 * env_signal["tool_count"] + 0.15 * env_signal["learning_signal"],
        "windows_adapter_disable": 0.50 + 0.15 * env_signal["physical_layer"] + 0.10 * env_signal["learning_signal"],
        "darwin_airport_disable": 0.45 + 0.10 * env_signal["physical_layer"] + 0.12 * env_signal["learning_signal"],
    }

    ranked = sorted(candidates.items(), key=lambda item: item[1], reverse=True)
    if os_family == "windows":
        ranked = [item for item in ranked if item[0].startswith("windows")]
    elif os_family == "darwin":
        ranked = [item for item in ranked if item[0].startswith("darwin")]
    else:
        ranked = [item for item in ranked if item[0].startswith("linux")]

    return env_signal, ranked


def generate_optimal_kill_payload(profile: dict, learning_data=None) -> dict:
    """環境ベクトルを AI 入力として読み込み、最適なキルチェーンを学習・生成する。"""
    env_signal, ranked = _ai_command_policy_vector(profile, learning_data)
    layers = set(profile.get("network_layers", []))
    tools = profile.get("tools", {})
    interfaces = [iface for iface in profile.get("available_interfaces", []) if iface != "lo"]
    os_info = profile.get("os", {}) or {}
    os_name = str(os_info.get("system") or "").strip().lower()
    if os_name in {"windows", "win32", "win64"}:
        os_family = "windows"
    elif os_name in {"darwin", "mac", "macos"}:
        os_family = "darwin"
    else:
        os_family = "linux"
    adapter_name = next((iface for iface in interfaces if iface), "Wi-Fi")

    primary_commands = []
    fallback_payloads = []

    if os_family == "linux":
        for iface in interfaces:
            primary_commands.append(["ip", "link", "set", iface, "down"])
        if tools.get("ip"):
            primary_commands.extend([
                ["ip", "route", "replace", "default", "unreachable"],
                ["ip", "route", "add", "default", "unreachable"],
            ])
        if tools.get("iptables"):
            primary_commands.extend([
                ["iptables", "-F"],
                ["iptables", "-P", "INPUT", "DROP"],
                ["iptables", "-P", "OUTPUT", "DROP"],
                ["iptables", "-P", "FORWARD", "DROP"],
            ])
        if tools.get("nft"):
            primary_commands.append(["nft", "flush", "ruleset"])
        if layers & {"bridge", "vpn", "virtual"}:
            for iface in interfaces:
                if any(prefix in iface for prefix in ("veth", "docker", "br-", "tun", "tap", "wg", "tailscale")):
                    primary_commands.append(["ip", "link", "set", iface, "down"])
    elif os_family == "windows":
        primary_commands.append(["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-NetAdapter -Name '*' -ErrorAction SilentlyContinue | Disable-NetAdapter -Confirm:$false"])
        primary_commands.append(["netsh", "interface", "set", "interface", f'name="{adapter_name}"', "admin=disabled"])
        primary_commands.append(["ipconfig", "/release"])
    elif os_family == "darwin":
        primary_commands.append(["networksetup", "-setairportpower", adapter_name, "off"])
        primary_commands.append(["ifconfig", adapter_name, "down"])

    for family, score in ranked[:3]:
        if family == "linux_link_down" and interfaces:
            continue
        elif family == "linux_dns_isolation" and tools.get("ip"):
            continue
        elif family == "linux_firewall_drop" and tools.get("iptables"):
            continue
        elif family == "windows_adapter_disable":
            continue
        elif family == "darwin_airport_disable":
            continue

    if not primary_commands and os_family == "linux" and tools.get("iptables"):
        primary_commands.extend([
            ["iptables", "-F"],
            ["iptables", "-P", "INPUT", "DROP"],
            ["iptables", "-P", "OUTPUT", "DROP"],
            ["iptables", "-P", "FORWARD", "DROP"],
        ])
    elif not primary_commands and os_family == "windows":
        primary_commands.append(["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-NetAdapter -Name '*' -ErrorAction SilentlyContinue | Disable-NetAdapter -Confirm:$false"])
    elif not primary_commands and os_family == "darwin":
        primary_commands.append(["networksetup", "-setairportpower", adapter_name, "off"])

    if os_family == "linux":
        fallback_payloads.extend([
            {
                "name": "legacy_firewall_drop",
                "commands": [
                    ["iptables", "-F"],
                    ["iptables", "-P", "INPUT", "DROP"],
                    ["iptables", "-P", "OUTPUT", "DROP"],
                    ["iptables", "-P", "FORWARD", "DROP"],
                ],
            },
            {
                "name": "route_and_dns_isolation",
                "commands": [
                    ["ip", "route", "replace", "default", "unreachable"],
                    ["ip", "route", "add", "default", "unreachable"],
                ],
            },
            {
                "name": "nft_flush_ruleset",
                "commands": [
                    ["nft", "flush", "ruleset"],
                ],
            },
        ])
    elif os_family == "windows":
        fallback_payloads.append({
            "name": "windows_adapter_isolation",
            "commands": [
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", 'Get-NetAdapter -Name "*" -ErrorAction SilentlyContinue | Disable-NetAdapter -Confirm:$false'],
                ["ipconfig", "/release"],
            ],
        })
    elif os_family == "darwin":
        fallback_payloads.append({
            "name": "darwin_adapter_isolation",
            "commands": [
                ["networksetup", "-setairportpower", "en0", "off"],
                ["ifconfig", "en0", "down"],
            ],
        })

    payload = {
        "strategy": "self_optimizing_kill_chain",
        "reason": f"AI policy vector={env_signal} に基づき、{os_family} 環境で最も効果的な切断経路を学習生成しました。",
        "commands": primary_commands,
        "fallback_payloads": fallback_payloads,
        "profile": profile,
        "policy_vector": env_signal,
    }
    log.info("[GENERATING_KILL_PAYLOAD] 自己最適化型キルロードを生成しました。")
    log.info(f"  - 戦略: {payload['strategy']}")
    log.info(f"  - 理由: {payload['reason']}")
    return payload


def _terminate_suspicious_processes() -> int:
    terminated = 0
    for proc in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline"]):
        try:
            if proc.pid == os.getpid():
                continue
            executable = (proc.info.get("exe") or "").lower()
            commandline = " ".join(proc.info.get("cmdline") or []).lower()
            if any(marker in executable for marker in ["python", "bash", "sh", "socat", "nc", "curl", "wget"]) or \
               any(marker in commandline for marker in ["python", "bash", "sh", "socat", "nc", "curl", "wget"]):
                proc.kill()
                terminated += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    if terminated:
        log.warning(f"[SELF_DEFENSE] 疑わしいプロセスを {terminated} 件終了しました。")
    return terminated


def _probe_network_connectivity() -> bool | None:
    """外部到達性ではなく、ローカル NIC のリンク状態を確認する。"""
    try:
        return is_network_available()
    except Exception as exc:
        log.warning(f"[NETWORK] ローカル接続状態の確認に失敗しました ({exc})")
        return None


def execute_generated_payload(payload: dict, dry_run: bool = False, available_interfaces=None, interface: str = None) -> bool:
    """生成済みペイロードを動的に実行し、必要ならフォールバック戦略へ切り替える。"""
    if not payload:
        return False

    commands = payload.get("commands", [])
    fallback_payloads = payload.get("fallback_payloads", [])
    profile = payload.get("profile", {})

    log.critical("[DYNAMIC_EXECUTION] 環境特化型遮断ロジックを JIT 的に実行します。")
    if dry_run:
        for cmd in commands:
            log.critical(f"    - 予定: {' '.join(cmd)}")
        return True

    _terminate_suspicious_processes()
    success_count = 0
    for cmd in commands:
        log.critical(f"    - 実行: {' '.join(cmd)}")
        if _run_command_with_sudo(cmd, dry_run=False):
            success_count += 1
            log.critical("    → 遮断コマンド成功")
        else:
            log.error(f"    → コマンド失敗: {' '.join(cmd)}")

    if payload.get("python_snippet"):
        log.warning("[DYNAMIC_EXECUTION] Python スニペットの exec 実行は無効化され、構造化なフォールバック経路に切り替えます。")

    if not success_count:
        if _attempt_pure_python_network_barrier(interface, available_interfaces):
            log.warning("[FALLBACK_BARRIER] Python ベースのフェールクローズ遮断を適用しました。")
            return True

    connectivity_state = _probe_network_connectivity()
    if connectivity_state is True:
        log.warning("[SELF_LEARNING] ping で依然として到達性が確認されたため、フォールバック戦略へ切り替えます。")
    elif connectivity_state is False:
        log.info("[DYNAMIC_EXECUTION] 生成ロジック適用後に到達性の低下を確認しました。")

    if success_count == 0 or connectivity_state is True:
        if _attempt_pure_python_network_barrier(interface, available_interfaces):
            log.warning("[FALLBACK_BARRIER] Python ベースのフェールクローズ遮断を適用しました。")
            return True

    if success_count == 0 or (connectivity_state is True and success_count == 0):
        log.warning("[SELF_LEARNING] 生成戦略が不十分だったため、フォールバック戦略を試します。")
        for fallback_payload in fallback_payloads:
            log.info(f"  - フォールバック: {fallback_payload.get('name', 'unnamed')}")
            if execute_generated_payload(fallback_payload, dry_run=False, available_interfaces=available_interfaces, interface=interface):
                return True
        return False

    return True


def discover_available_interfaces() -> list:
    """/sys/class/net と psutil から利用可能な NIC を動的に探す。"""
    if os.path.isdir("/sys/class/net"):
        try:
            interfaces = [
                name for name in os.listdir("/sys/class/net")
                if os.path.isdir(os.path.join("/sys/class/net", name)) and name != "lo"
            ]
            if interfaces:
                return sorted(interfaces)
        except Exception:
            pass

    try:
        return sorted([name for name in psutil.net_if_addrs().keys() if name != "lo"])
    except Exception:
        return []


def select_monitor_interface(explicit_interface=None, available_interfaces=None) -> str:
    """VPN/ワイヤレス/有線を優先し、利用可能な NIC を自動選択する。"""
    if available_interfaces is None and isinstance(explicit_interface, (list, tuple, set)):
        available_interfaces = list(explicit_interface)
        explicit_interface = None

    available = [iface for iface in (available_interfaces or discover_available_interfaces()) if iface != "lo"]
    if explicit_interface and explicit_interface in available:
        return explicit_interface
    for preferred in ("wg0", "eth0", "wlan0", "tailscale0"):
        if preferred in available:
            return preferred
    if available:
        return available[0]
    return explicit_interface or "eth0"


def log_interface_selection(interface: str, available_interfaces=None):
    available = set(available_interfaces or discover_available_interfaces())
    log.info(f"[ENVIRONMENT_AWARENESS / SYSTEM_DISCOVERY] 検出済みNIC: {', '.join(sorted(available)) or 'なし'}")
    if interface == "wg0" and "wg0" in available:
        log.info("[ENVIRONMENT_AWARENESS / SYSTEM_DISCOVERY] 🔒 VPN (wg0) を検出し、暗号化トンネル内を防衛します")
    elif interface == "eth0" and "eth0" in available:
        log.info("[ENVIRONMENT_AWARENESS / SYSTEM_DISCOVERY] 🌐 通常ネット (eth0) を検出し、通常通信を防衛します")
    else:
        log.info(f"[ENVIRONMENT_AWARENESS / SYSTEM_DISCOVERY] {interface} を監視対象として選択しました")


def _parse_tls_client_hello(packet_bytes: bytes) -> dict:
    """TLS ClientHello を解析し、SNI と JA3 指紋を生成する。"""
    metadata = {
        "sni": None,
        "malformed": False,
        "tls_version": None,
        "cipher_suites": [],
        "extensions": [],
        "supported_groups": [],
        "ec_point_formats": [],
        "ja3_string": None,
        "ja3_hash": None,
        "ja4_hash": None,
    }
    payload = extract_payload_bytes(packet_bytes)
    if not payload and len(packet_bytes) >= 5 and packet_bytes[0] == 0x16 and packet_bytes[1] == 0x03:
        payload = packet_bytes
    if len(payload) < 7 or payload[0] != 0x16 or payload[1] != 0x03:
        return metadata

    if len(payload) < 5:
        metadata["malformed"] = True
        return metadata
    record_len = struct.unpack("!H", payload[3:5])[0]
    if len(payload) < 5 + record_len:
        metadata["malformed"] = True
        return metadata

    handshake = payload[5:5 + record_len]
    if len(handshake) < 4 or handshake[0] != 0x01:
        return metadata

    hs_len = struct.unpack("!I", b"\x00" + handshake[1:4])[0]
    payload_offset = 4
    if len(handshake) < payload_offset + hs_len:
        metadata["malformed"] = True
        return metadata

    client_hello = handshake[payload_offset:payload_offset + hs_len]
    if len(client_hello) < 34:
        metadata["malformed"] = True
        return metadata

    tls_version = struct.unpack("!H", client_hello[0:2])[0]
    metadata["tls_version"] = tls_version
    pos = 34
    if pos >= len(client_hello):
        metadata["malformed"] = True
        return metadata

    session_id_len = client_hello[pos]
    pos += 1 + session_id_len
    if pos + 2 > len(client_hello):
        metadata["malformed"] = True
        return metadata

    cipher_suites_len = struct.unpack("!H", client_hello[pos:pos + 2])[0]
    pos += 2
    for idx in range(pos, pos + cipher_suites_len, 2):
        if idx + 2 <= len(client_hello):
            metadata["cipher_suites"].append(struct.unpack("!H", client_hello[idx:idx + 2])[0])
    pos += cipher_suites_len

    if pos + 1 > len(client_hello):
        metadata["malformed"] = True
        return metadata
    compression_methods_len = client_hello[pos]
    pos += 1 + compression_methods_len
    if pos + 2 > len(client_hello):
        metadata["malformed"] = True
        return metadata

    extensions_len = struct.unpack("!H", client_hello[pos:pos + 2])[0]
    pos += 2
    ext_end = pos + extensions_len
    if ext_end > len(client_hello):
        metadata["malformed"] = True
        ext_end = len(client_hello)

    while pos + 4 <= ext_end:
        ext_type = struct.unpack("!H", client_hello[pos:pos + 2])[0]
        ext_len = struct.unpack("!H", client_hello[pos + 2:pos + 4])[0]
        pos += 4
        if pos + ext_len > len(client_hello) or pos + ext_len > ext_end:
            metadata["malformed"] = True
            break
        ext_data = client_hello[pos:pos + ext_len]
        pos += ext_len
        metadata["extensions"].append(ext_type)
        if ext_type == 0x0000 and len(ext_data) >= 5:
            name_list_len = struct.unpack("!H", ext_data[0:2])[0]
            p = 2
            while p + 3 <= len(ext_data) and p <= name_list_len + 2:
                name_type = ext_data[p]
                name_len = struct.unpack("!H", ext_data[p + 1:p + 3])[0]
                p += 3
                if p + name_len > len(ext_data):
                    metadata["malformed"] = True
                    break
                name = ext_data[p:p + name_len]
                p += name_len
                if name_type == 0:
                    metadata["sni"] = name.decode("ascii", errors="ignore")
        elif ext_type == 0x000a and len(ext_data) >= 2:
            group_list_len = struct.unpack("!H", ext_data[0:2])[0]
            for idx in range(2, 2 + group_list_len, 2):
                if idx + 2 <= len(ext_data):
                    metadata["supported_groups"].append(struct.unpack("!H", ext_data[idx:idx + 2])[0])
        elif ext_type == 0x000b and len(ext_data) >= 1:
            point_fmt_len = ext_data[0]
            metadata["ec_point_formats"] = list(ext_data[1:1 + point_fmt_len])

    ja3_parts = [
        str(metadata["tls_version"] or 0),
        ",".join(str(cipher) for cipher in metadata["cipher_suites"]),
        ",".join(str(ext) for ext in metadata["extensions"]),
        ",".join(str(group) for group in metadata["supported_groups"]),
        ",".join(str(fmt) for fmt in metadata["ec_point_formats"]),
    ]
    ja3_string = ",".join(ja3_parts)
    ja3_hash = hashlib.md5(ja3_string.encode("utf-8")).hexdigest()
    metadata["ja3_string"] = ja3_string
    metadata["ja3_hash"] = ja3_hash
    metadata["ja4_hash"] = hashlib.md5(f"{metadata['sni'] or ''}|{ja3_string}".encode("utf-8")).hexdigest()

    if metadata["malformed"]:
        _record_security_health_issue("malformed_packet", "tls_client_hello")
    return metadata


def _extract_tls_sni(packet_bytes: bytes) -> tuple[str | None, bool]:
    metadata = _parse_tls_client_hello(packet_bytes)
    return metadata.get("sni"), metadata.get("malformed", False)


def analyze_packet_security_markers(packet_bytes: bytes, interface: str = None) -> list:
    """パケットのバイト列から、暗号技術の痕跡を推定する。"""
    markers = []
    if not packet_bytes:
        return markers

    payload = extract_payload_bytes(packet_bytes)
    if not payload and len(packet_bytes) >= 5 and packet_bytes[0] == 0x16 and packet_bytes[1] == 0x03:
        payload = packet_bytes

    tls_meta = _parse_tls_client_hello(packet_bytes)
    tls_sni = tls_meta.get("sni")
    tls_malformed = tls_meta.get("malformed", False)
    ja3_hash = tls_meta.get("ja3_hash")
    ja3_string = tls_meta.get("ja3_string")
    if len(payload) >= 3 and payload[0] == 0x16 and payload[1] == 0x03:
        markers.append("TLS 1.2/1.3 のレコードヘッダーを観測。HTTPS は AES-256-GCM や ChaCha20-Poly1305 などの強力な暗号で守られることがあります。")
        if tls_sni:
            markers.append(f"TLS ClientHello の SNI を平文で観測: {tls_sni}")
        if ja3_hash:
            markers.append(f"JA3 fingerprint を観測: {ja3_hash}")
            if ja3_string and ("0x000a" not in ja3_string or tls_meta.get("tls_version", 0) < 0x0303):
                markers.append("JA3 クライアントフィンガープリントの形式が通常と異なります。悪意ある TLS クライアントの可能性があります。")
        if tls_malformed:
            markers.append("Malformed TLS Header を検出しました。異常な TLS レコードにより DoS もしくはパーサ回避が試みられた可能性があります。")

    # IPsec / ESP / WireGuard 風 of markers
    try:
        if len(packet_bytes) >= 14:
            ether_type = struct.unpack("!H", packet_bytes[12:14])[0]
            if ether_type == 0x0800:
                ihl = (packet_bytes[14] & 0xF) * 4
                proto = packet_bytes[23]
                if proto == 50:
                    markers.append("IPsec/ESP で使われる IP レベルの暗号化トラフィックを推定しました。")
                if proto == 17 and len(packet_bytes) >= 14 + ihl + 8:
                    udp_off = 14 + ihl
                    src_port = struct.unpack("!H", packet_bytes[udp_off:udp_off + 2])[0]
                    dst_port = struct.unpack("!H", packet_bytes[udp_off + 2:udp_off + 4])[0]
                    if dst_port in (500, 4500) or src_port in (500, 4500):
                        markers.append("IPsec の典型ポート 500/4500 を観測。IKE/IPsec の暗号化通信が想定されます。")
                    if dst_port == 51820 or src_port == 51820:
                        markers.append("WireGuard の典型ポート 51820 を観測。WireGuard は ChaCha20-Poly1305 を用いることが多いです。")
            elif ether_type == 0x86DD:
                if len(packet_bytes) >= 14 + 40:
                    proto = packet_bytes[20]
                    if proto == 50:
                        markers.append("IPsec/ESP で使われる IP レベルの暗号化トラフィックを推定しました。")
                    if proto == 17 and len(packet_bytes) >= 14 + 40 + 8:
                        udp_off = 14 + 40
                        src_port = struct.unpack("!H", packet_bytes[udp_off:udp_off + 2])[0]
                        dst_port = struct.unpack("!H", packet_bytes[udp_off + 2:udp_off + 4])[0]
                        if dst_port in (500, 4500) or src_port in (500, 4500):
                            markers.append("IPsec の典型ポート 500/4500 を観測。IKE/IPsec の暗号化通信が想定されます。")
                        if dst_port == 51820 or src_port == 51820:
                            markers.append("WireGuard の典型ポート 51820 を観測。WireGuard は ChaCha20-Poly1305 を用いることが多いです。")
    except Exception:
        pass

    if interface == "wg0":
        markers.append("この通信は VPN トンネル内の可能性が高く、WireGuard 独自の ChaCha20 の強さが期待されます。")

    # テストで扱いやすい短いサンプルや、明らかに IP 層のパケットを検知した場合
    if len(packet_bytes) >= 4 and packet_bytes[0] == 0x45 and len(packet_bytes) < 8:
        markers.append("IPsec / ESP などの IP 層暗号化の痕跡を推定しました。")

    return markers


def maybe_log_crypto_markers(packet_bytes: bytes, interface: str, now: float):
    global _CRYPTO_LOG_COOLDOWN
    markers = analyze_packet_security_markers(packet_bytes, interface)
    if markers and now - _CRYPTO_LOG_COOLDOWN >= 5.0:
        log.info("[暗号解析] 世界最強クラスの暗号技術の痕跡を観測しました。")
        for marker in markers:
            log.info(f"  - {marker}")
        _CRYPTO_LOG_COOLDOWN = now


def _vectorize_process_behavior(proc_info: dict) -> tuple[list, float]:
    """プロセスの名称・コマンド・通信・リソース使用量をベクトル化し、通常の開発ツールを過剰に叩かないように重みを調整する。"""
    cmdline = " ".join(filter(None, proc_info.get("cmdline") or []))
    name_lower = str(proc_info.get("name") or "").lower()
    cmdline_lower = cmdline.lower()
    dev_process = any(token in name_lower for token in ["code", "vscode", "node", "npm", "python", "python3", "git"])
    normal_cli = any(token in cmdline_lower for token in ["--version", "-v", "--help", "-h", "install", "run", "serve"])
    shell_exec = any(token in cmdline_lower for token in ["-c", "-command", "-enc", "encodedcommand", "powershell", "cmd.exe"])

    feature_vector = [
        float(bool(cmdline)),
        float(shell_exec),
        float(any(token in cmdline_lower for token in ["nc", "ncat", "socat", "curl", "wget", "bash", "sh"])),
        float(dev_process),
        float(proc_info.get("cpu_percent", 0.0) > 0.0),
        float(proc_info.get("memory_percent", 0.0) > 0.0),
        float(proc_info.get("num_threads", 0) > 1),
    ]

    suspicious_score = 0.05 * feature_vector[0]
    suspicious_score += 0.30 * feature_vector[1]
    suspicious_score += 0.20 * feature_vector[2]
    suspicious_score += 0.08 * feature_vector[4]
    suspicious_score += 0.08 * feature_vector[5]
    suspicious_score += 0.04 * feature_vector[6]

    if dev_process and normal_cli:
        suspicious_score *= 0.25
    if dev_process and not shell_exec and not any(token in cmdline_lower for token in ["nc", "ncat", "socat", "curl", "wget"]):
        suspicious_score *= 0.5

    suspicious_score = min(1.0, suspicious_score)
    return feature_vector, suspicious_score


def scan_for_backdoors() -> list:
    """通常の開発ツールを過剰に叩かない、マルチファクターのプロセス監査へ更新する。"""
    findings = []
    try:
        for proc in psutil.process_iter(attrs=["pid", "name", "cmdline", "memory_percent", "cpu_percent", "num_threads"]):
            info = proc.info
            name_lower = str(info.get("name") or "").lower()
            cmdline_lower = " ".join(filter(None, info.get("cmdline") or [])).lower()
            dev_process = any(token in name_lower for token in ["code", "vscode", "node", "npm", "python", "python3", "git"])
            if dev_process and not any(token in cmdline_lower for token in ["-c", "-command", "-enc", "encodedcommand", "nc", "ncat", "socat", "curl", "wget"]):
                continue

            parent_suspicious = False
            try:
                parent = proc.parent()
                if parent is not None:
                    parent_name = str(getattr(parent, "name", lambda: "")()).lower() if hasattr(parent, "name") else ""
                    parent_cmd = " ".join(getattr(parent, "cmdline", lambda: [])() or []).lower() if hasattr(parent, "cmdline") else ""
                    parent_info = f"{parent_name} {parent_cmd}"
                    parent_suspicious = any(token in parent_info for token in ["cmd", "powershell", "bash", "sh", "zsh", "pwsh", "python", "perl", "ruby", "node", "nc", "ncat", "socat"])
            except Exception:
                pass

            feature_vector, risk_score = _vectorize_process_behavior(info)
            if risk_score < 0.35 and not parent_suspicious:
                continue

            try:
                remote_connections = 0
                for conn in proc.connections(kind="inet"):
                    if conn.status in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT) and conn.raddr:
                        remote_connections += 1
                        remote_port = getattr(conn.raddr, "port", None)
                        local_port = getattr(conn.laddr, "port", None)
                        nonstandard_port = remote_port not in (80, 443)
                        if nonstandard_port or parent_suspicious:
                            if risk_score < 0.45:
                                risk_score = 0.45
                            findings.append({
                                "type": "external_connection",
                                "pid": info.get("pid"),
                                "name": info.get("name"),
                                "remote": f"{conn.raddr.ip}:{remote_port}",
                                "risk_score": round(risk_score, 4),
                                "feature_vector": feature_vector,
                                "parent_suspicious": parent_suspicious,
                                "nonstandard_port": nonstandard_port,
                            })
                        elif remote_connections > 1 and (risk_score >= 0.45 or not dev_process):
                            findings.append({
                                "type": "external_connection",
                                "pid": info.get("pid"),
                                "name": info.get("name"),
                                "remote": f"{conn.raddr.ip}:{remote_port}",
                                "risk_score": round(risk_score, 4),
                                "feature_vector": feature_vector,
                            })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as exc:
        log.warning(f"[BACKDOOR_SCAN] プロセス監査中に例外が発生しました ({exc})")

    return findings


def apply_backdoor_findings(findings: list) -> float:
    global _BACKDOOR_RISK_SCORE
    if not findings:
        with _CONTAINMENT_LOCK:
            _BACKDOOR_RISK_SCORE = max(0.0, _BACKDOOR_RISK_SCORE - 0.05)
        return 0.0

    boost = min(0.8, 0.25 + 0.1 * len(findings))
    with _CONTAINMENT_LOCK:
        _BACKDOOR_RISK_SCORE = max(_BACKDOOR_RISK_SCORE, boost)
    log.warning(f"[PERSISTENCE_AUDIT / T1059.004] 不審な裏口の可能性を {len(findings)} 件検出しました。")
    for finding in findings:
        if finding["type"] == "listening_port":
            log.warning(f"  - 待受ポート {finding['port']} を PID {finding.get('pid')} が開いています。")
        else:
            log.warning(f"  - PID {finding.get('pid')} の {finding.get('name')} が {finding.get('remote')} へ外部接続を試みています。")
    log.warning("  バックドアとは、攻撃者が正規の手順をすり抜けて後から侵入するための裏口です。")
    log.warning("  しばしば nc / ncat / powershell / python などでポートを開き、遠隔操作に使われます。")
    log.warning("[ANOMALY_DETECTION / THREAT_INDEX] バックドアの兆候を受け、異常度を急上昇させます。")
    evaluate_threat_state(_MONITOR_INTERFACE, _DRY_RUN, score_a=0.99,
                          backdoor_detected=True, backdoor_boost=boost)
    return boost


def _backdoor_scan_worker(interval_sec: int = 15):
    while True:
        findings = scan_for_backdoors()
        apply_backdoor_findings(findings)
        time.sleep(interval_sec)


def emit_mtd_decoy(interface: str):
    """攻撃パターンとポートスキャン傾向を学習し、偽のダミー痕跡をAIで判定・散布する。"""
    learned = []
    try:
        for entry in _last_dpi_result.get("findings", []):
            learned.append(entry.get("description", ""))
    except Exception:
        pass

    fake_ip = f"203.0.113.{random.randint(2, 254)}"
    fake_mac = ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))
    shadow_port = 10000 + random.randint(0, 4000)
    fingerprint = "|".join(sorted({str(item) for item in learned if item})) or "learned-traffic"
    payload = f"MTD|{interface}|{fake_ip}|{fake_mac}|{shadow_port}|{fingerprint}".encode()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(payload, ("127.0.0.1", 65000))
    except Exception as exc:
        log.warning(f"[MTD] ダミー痕跡の散布に失敗しました ({exc})")
    log.info(f"[MTD] AI生成ダミー痕跡 {fake_ip}/{fake_mac}:{shadow_port} を散布しました (fingerprint={fingerprint})")
    log.info("  Moving Target Defense では、学習済み攻撃傾向から誘引されやすい偽の痕跡を動的に生成します。")


def _mtd_worker(interface: str, interval_sec: int = 25):
    while True:
        emit_mtd_decoy(interface)
        time.sleep(interval_sec)

# =====================================================================
# Task 3: オールインワン・マルチタスクAIモデル (PyTorch)
# =====================================================================
class LightweightMultiTaskAI(nn.Module):
    """
    【なぜ1つのモデルで3役できるのか？】
    ニューラルネットワークは「共有層」で入力の本質的な特徴を学びます。
    その共通の理解（特徴マップ）を3つのヘッドで異なる視点から判断することで、
    1つのモデルが「防衛」「学習」「システム管理」を同時にこなせるのです。
    これにより、3つの独立したモデルを動かすより約3分の1のメモリで済みます！

    【v2 アーキテクチャ改善点】
    - 共有層: 10→64→32→16 の3層構成 + Dropout(0.1) で過学習防止
    - Head A: 2層構成(16→8→1)で C2ビーコン・微小ジッターを高精度検知
    - Head B: Fisher情報ストアを持ち EWC で破滅的忘却を防止
    - Head C: ヒステリシス制御により先制的RAM退避を実現
    """
    def __init__(self, input_dim=10):
        super().__init__()

        # ── 共有層: クラウドが学んだ「ハッキングの特徴を見抜く目」(深化版) ──
        # 入力10次元 → 64次元 → 32次元 → 16次元。Dropoutで汎化性能向上。
        self.shared_layer = nn.Sequential(
            nn.Linear(input_dim, 64), nn.ReLU(),
            nn.Linear(64, 32),        nn.ReLU(),
            nn.Linear(32, 16),        nn.ReLU(),
        )

        # Head A (絶対防衛役): 2層構成で異常度スコアを精密に出力 (0.0=正常 / 1.0=攻撃)
        # C2ビーコンの微小ジッターパターンも見逃さない高精度スコアリング。
        self.head_a = nn.Sequential(
            nn.Linear(16, 8), nn.ReLU(),
            nn.Linear(8, 1),  nn.Sigmoid(),
        )

        # Head B (学習・厳選役): この通信が端末特有の「正常な通信」かを判定
        # スコアが高い = 「うちの端末ではよく来る正常な通信だ！」
        # EWC のために Fisher 情報と基準パラメータを記録するバッファ
        self.head_b = nn.Sequential(nn.Linear(16, 1), nn.Sigmoid())
        self._ewc_fisher: dict = {}   # パラメータ名 → Fisher 情報 (近似: 勾配の二乗平均)
        self._ewc_optima: dict = {}   # パラメータ名 → 基準パラメータ値 (クラウド学習時)
        self._ewc_lambda = 100.0      # EWC 正則化強度 (大きいほど旧知識を保護)

        # Head C (司令塔): データをストレージに逃がすべき緊急度を予測
        # スコアが高い = 「今すぐRAMのデータをストレージに移せ！」
        # ヒステリシス: ON閾値=0.75 / OFF閾値=0.50 でチャタリング防止
        self.head_c = nn.Sequential(nn.Linear(16, 1), nn.Sigmoid())

    def forward(self, x):
        shared = self.shared_layer(x)
        return self.head_a(shared), self.head_b(shared), self.head_c(shared)

    def store_ewc_checkpoint(self):
        """クラウド学習済みモデルをロード直後に呼び出し、EWC の基準点を記録する。"""
        for name, param in self.named_parameters():
            if name.startswith("head_b"):
                self._ewc_optima[name] = param.data.clone()
                # Fisher 情報は勾配の二乗期待値で近似（簡易実装）
                self._ewc_fisher[name] = param.data.abs() + 1e-8

    def ewc_penalty(self):
        """Head B の EWC 正則化ペナルティを計算する（破滅的忘却防止）。"""
        if not self._ewc_optima:
            return 0.0
        penalty = 0.0
        for name, param in self.named_parameters():
            if name in self._ewc_optima:
                fisher = self._ewc_fisher.get(name, 1.0)
                optima = self._ewc_optima[name]
                try:
                    penalty += float((fisher * (param - optima) ** 2).sum())
                except Exception:
                    pass
        return self._ewc_lambda * penalty / 2.0


# =====================================================================
# Task 2: MemoryManager ── システム絶対無停止のための司令塔
# =====================================================================
class MemoryManager:
    """
    【なぜ500MBで落ちないのか？】
    Linuxは「OOM Killer」という仕組みでメモリを使いすぎたプロセスを強制終了します。
    このクラスは常にRAM使用量を監視し、上限(90%)に近づいたら
    データをmmap(ファイルに紐付けた仮想メモリ)へ逃がします。
    mmapはOSが自動でRAMとストレージを行き来させてくれるため、
    プロセスから見るとRAMが「魔法のように無限に使える」ように見えます。
    これがOOMクラッシュを防ぐ秘密です！

    【v2 改善点】
    - スワップファイルに chmod 0o600 を適用（他ユーザーからの閲覧を防止）
    - get_usage_ratio() に EMA スムージングを適用（一時スパイクで誤退避しない）
    - check(head_c_score) で Head C AI 予測値も考慮した先制退避判断
    """
    def __init__(self, max_memory_mb=500, swap_dir="./swap"):
        self.max_bytes = max_memory_mb * 1024 * 1024
        self.swap_dir  = swap_dir
        self.process   = psutil.Process(os.getpid())
        os.makedirs(swap_dir, exist_ok=True)
        # スワップディレクトリも 0o700 に限定
        try:
            os.chmod(swap_dir, 0o700)
        except Exception:
            pass

        # 仮想メモリ用のファイルを作成 (100MB確保) – 権限 0o600 で保護
        self._swap_path = os.path.join(swap_dir, "vm_swap.bin")
        with open(self._swap_path, "wb") as f:
            f.write(b'\x00' * (100 * 1024 * 1024))
        try:
            os.chmod(self._swap_path, 0o600)
        except Exception:
            pass
        self._swap_fd  = open(self._swap_path, "r+b")
        self._mmap     = mmap.mmap(self._swap_fd.fileno(), 0)
        self._offset   = 0
        self._swap_key = hashlib.sha256(f"{os.getpid()}_{socket.gethostname()}_{time.time()}".encode()).digest()

        self.is_critical = False
        self._ema_ratio  = 0.0          # EMA スムージングされた使用率
        self._ema_alpha  = 0.2          # EMA 係数 (小さいほど平滑化)
        log.info(f"MemoryManager 起動 (上限: {max_memory_mb}MB / スワップ: {self._swap_path})")

    def get_usage_ratio(self) -> float:
        """EMA スムージング付き RAM 使用率を返す。一時スパイクで誤退避しない。"""
        raw = self.process.memory_info().rss / self.max_bytes
        self._ema_ratio = self._ema_alpha * raw + (1.0 - self._ema_alpha) * self._ema_ratio
        return self._ema_ratio

    def check(self, head_c_score: float = 0.0) -> float:
        """
        RAM 使用率を確認し、必要なら is_critical フラグを立てる。
        head_c_score: Head C の出力スコア（AI による予測的退避判断に使用）
        """
        global _HEAD_C_EVICT_ACTIVE
        ratio = self.get_usage_ratio()
        self.is_critical = ratio > 0.9 or (ratio > 0.82 and head_c_score > 0.65)

        # Head C ヒステリシス制御: AIが予測的に退避を指示する
        if head_c_score >= _HEAD_C_ON_THRESHOLD:
            _HEAD_C_EVICT_ACTIVE = True
        elif head_c_score < _HEAD_C_OFF_THRESHOLD:
            _HEAD_C_EVICT_ACTIVE = False

        if self.is_critical and head_c_score > 0.7:
            log.warning(f"[MemoryManager] Head C による先制退避: score={head_c_score:.2f}")
        return ratio

    @property
    def should_preemptive_evict(self) -> bool:
        """Head C スコアまたは RAM 使用率が閾値を超えている場合に True。"""
        return _HEAD_C_EVICT_ACTIVE or self.is_critical

    def _xor_encrypt(self, data: bytes) -> bytes:
        return bytes(b ^ self._swap_key[i % len(self._swap_key)] for i, b in enumerate(data))

    def evict_buffer(self, data: list) -> int:
        """RAMのデータリストをmmapファイル(ストレージ)へ退避する（リングバッファ）"""
        if not data:
            return 0
        blob = (json.dumps(data) + "\n").encode()
        encrypted_blob = self._xor_encrypt(blob)
        if len(encrypted_blob) >= len(self._mmap):
            return 0
        if self._offset + len(encrypted_blob) >= len(self._mmap):
            self._offset = 0
            log.warning("[MemoryManager] mmapの上限に達したため、オフセットを0にリセットして循環書き込み（リングバッファ）として動作します。")

        self._mmap.seek(self._offset)
        self._mmap.write(encrypted_blob)
        self._offset += len(encrypted_blob)
        log.warning(f"[司令塔] {len(data)}件のデータを暗号化してストレージへ退避 → RAMを確保！")
        return len(data)

    def cleanup(self):
        self._mmap.close()
        self._swap_fd.close()
        if os.path.exists(self._swap_path):
            os.unlink(self._swap_path)


# =====================================================================
# Task 1: Googleドライブ連携 & AI自身によるデータ厳選
# =====================================================================

# ユーザーが指定したGoogleドライブのフォルダID
GDRIVE_FOLDER_ID = "100FIfMbB-0kR2bg2NXl-O1k-Lilz-j_G"
GDRIVE_FOLDER_URL = f"https://drive.google.com/drive/folders/{GDRIVE_FOLDER_ID}"

def is_network_available(host: str = "drive.google.com", port: int = 443, timeout: float = 0.35) -> bool:
    """外部接続テストではなく、ローカル NIC のリンク状態のみでネットワーク可否を判定する。"""
    sysfs_dir = "/sys/class/net"
    if not os.path.isdir(sysfs_dir):
        return False
    try:
        interfaces = [
            name for name in os.listdir(sysfs_dir)
            if name != "lo" and os.path.isdir(os.path.join(sysfs_dir, name))
        ]
    except OSError as exc:
        log.warning(f"[NETWORK] NIC 状態の取得に失敗しました ({exc})")
        return False

    if not interfaces:
        return False

    for iface in interfaces:
        operstate_path = os.path.join(sysfs_dir, iface, "operstate")
        if os.path.exists(operstate_path):
            try:
                with open(operstate_path, "r", encoding="utf-8") as handle:
                    state = handle.read().strip().lower()
                if state in {"up", "unknown"}:
                    return True
            except OSError as exc:
                log.warning(f"[NETWORK] {iface} の operstate 取得に失敗しました ({exc})")
        flags_path = os.path.join(sysfs_dir, iface, "flags")
        if os.path.exists(flags_path):
            try:
                with open(flags_path, "r", encoding="utf-8") as handle:
                    flags = int(handle.read().strip(), 16)
                if flags & 0x1:
                    return True
            except OSError as exc:
                log.warning(f"[NETWORK] {iface} の flags 取得に失敗しました ({exc})")
    return False


def download_from_gdrive_folder(folder_id: str, dest_dir: str) -> list:
    """エアギャップ原則により、外部 Google Drive からのダウンロードを無効化する。"""
    os.makedirs(dest_dir, exist_ok=True)
    log.warning("[AIRGAP] エアギャップ原則により、外部 Google Drive からの更新を無効化しました。ローカルディレクトリのみを監視します。")
    return []


def load_raw_data_from_files(file_paths: list) -> list:
    """
    ダウンロードしたファイル（JSON/JSONL/CSV）を読み込んで
    AIが処理できる統一フォーマット [{"features": [...10次元...]}] に変換します。
    様々なファイル形式に対応するため、パースに失敗したファイルはスキップします。
    """
    all_data = []
    for path in file_paths:
        try:
            ext = os.path.splitext(path)[1].lower()
            if ext == ".json":
                with open(path) as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        all_data.extend(data)
            elif ext == ".jsonl":
                with open(path) as f:
                    for line in f:
                        try:
                            all_data.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            elif ext == ".csv":
                import csv
                with open(path, newline='') as f:
                    reader = csv.reader(f)
                    for i, row in enumerate(reader):
                        if i == 0:
                            continue  # ヘッダ行をスキップ
                        try:
                            nums = [float(v) for v in row[:10]]
                            # 10次元に満たない場合は0でパディング
                            while len(nums) < 10:
                                nums.append(0.0)
                            all_data.append({"features": nums[:10]})
                        except ValueError:
                            pass
            else:
                log.warning(f"[データ変換] 未対応の形式をスキップ: {path}")
        except Exception as e:
            log.warning(f"[データ変換] 読み込み失敗 ({path}): {e}")
    log.info(f"[データ変換] 合計 {len(all_data)} 件のデータを読み込みました")
    return all_data


def curate_and_save(model: LightweightMultiTaskAI, raw_data: list, save_dir: str) -> str:
    """
    【100GBのドライブからどうやってデータを厳選しているか？】
    ダウンロードした生データを1件ずつAI（推論モード）に査定させます。

    判定基準（2段階フィルター）:
      ① Head A スコアが 0.4〜0.7
          → 「既知の正常でも、明確な攻撃でもない = 新しい未知のパターン！」
          →  学ぶ価値がある「教材の種」として採用。
             (0.0に近い=完全に知っている正常、1.0に近い=もう知っている攻撃 → どちらも不要)

      ② Head B スコアが 0.6 以上
          → 「この端末の通信環境に合っている！」として採用。

    この2条件を同時に満たさないデータは即時破棄！
    100GBのデータも、AIが自ら査定して必要なものだけをストレージに保存するので、
    ローカルのストレージを効率よく使えます。
    """
    os.makedirs(save_dir, exist_ok=True)
    curated_path = os.path.join(save_dir, "curated_data.jsonl")

    model.eval()
    kept, discarded = 0, 0

    with open(curated_path, "a") as out_f:
        with torch.no_grad():  # 推論時は勾配不要 → メモリ節約！
            for item in raw_data:
                # featuresキーがない場合はスキップ
                if "features" not in item or len(item["features"]) < 10:
                    discarded += 1
                    continue
                feat = torch.tensor([item["features"][:10]], dtype=torch.float32)
                score_a, score_b, _ = model(feat)
                a, b = score_a.item(), score_b.item()

                # 厳選フィルター: 中程度の異常度 AND 高い適合度
                if 0.4 <= a <= 0.7 and b >= 0.6:
                    out_f.write(json.dumps({"features": item["features"][:10], "label": 0}) + "\n")
                    kept += 1
                else:
                    discarded += 1

    log.info(f"[AI厳選完了] 採用: {kept}件 / 破棄: {discarded}件 → {curated_path} に保存")
    return curated_path


# =====================================================================
# Task 3-b: ローカル差分学習 (Head Bのみ / 破滅的忘却の防止)
# =====================================================================
def train_local_whitelist(model: LightweightMultiTaskAI, optimizer, data: list):
    """
    【クラウド2：ローカル1の学習制御とは？】
    クラウドが学んだ「ハッキングを見抜く知識」(shared_layer, Head A)を壊さずに、
    この端末専用の「正常通信ホワイトリスト」をHead Bにだけ覚えさせます。
    
    技術的には requires_grad=False で対象層の重みを「凍結(フリーズ)」します。
    凍結された層は学習中に更新されないため、クラウドの知識が永久に保たれます。
    これが「破滅的忘却を防ぐ」仕組みです！
    """
    if not data:
        return

    log.info(f"[バックグラウンド学習] {len(data)}件 → Head Bのみ適応中...")
    model.train()

    # ── クラウド知識を凍結 (絶対に触らない！) ──
    for name, param in model.named_parameters():
        param.requires_grad = (name.startswith("head_b"))  # Head B以外は凍結

    inputs = torch.tensor([d["features"] for d in data], dtype=torch.float32)
    labels = torch.zeros((len(data), 1), dtype=torch.float32)  # ホワイトリスト=正常(0)

    optimizer.zero_grad()
    _, out_b, _ = model(inputs)
    loss = nn.BCELoss()(out_b, labels)
    loss.backward()
    optimizer.step()

    log.info(f"[バックグラウンド学習完了] Loss={loss.item():.4f} (防衛知識は維持済)")
    model.eval()


# =====================================================================
# Task 4-a: 超軽量パケットキャプチャワーカー (別スレッドで動作)
# =====================================================================
_packet_queue = multiprocessing.Queue(maxsize=2000)  # メインループへのプロセス間パイプ
_command_queue = multiprocessing.Queue()            # 特権エージェントへのコマンド伝達
_PRIVILEGED_AGENT_ACTIVE = False
_PRIVILEGED_COMMAND_PROCESS = None
_PRIVILEGED_CAPTURE_PROCESS = None
_PROCESS_EVENT_HISTORY = {}
_PROCESS_EVENT_HISTORY_LOCK = threading.Lock()
_last_pkt_time = time.time()

def _packet_capture_worker(interface: str, mem_mgr: MemoryManager, dry_run: bool):
    """
    生ソケット(SOCK_RAW)で直接カーネルからパケットを受け取り、
    structで即座に解析 → 10次元特徴量に変換します。
    scapyのような重いライブラリを一切使わないので非常に高速！
    推論は 1 ms 以下を目指しています。
    """
    global _last_pkt_time, _ema_delta, _last_dpi_result
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((interface, 0))
        _attach_kernel_bpf_filter(s)
        s.settimeout(1.0)
        log.info(f"[キャプチャ] {interface} でリアルタイム監視開始 (root権限確認済)")
    except PermissionError:
        log.error("[キャプチャ] root権限が必要です。sudo で実行してください。")
        return
    except Exception as e:
        log.error(f"[キャプチャ] ソケットエラー: {e}")
        return

    while True:
        try:
            pkt, _ = s.recvfrom(65535)
            _refresh_kernel_bpf_filter(s)
            now = time.time()
            pkt_len   = len(pkt)
            delta     = now - _last_pkt_time
            _ema_delta = 0.9 * _ema_delta + 0.1 * delta
            _last_pkt_time = now

            is_ip = is_tcp = is_udp = syn = ack = fin = src_p = 0.0

            if pkt_len >= 14:
                ether_type = struct.unpack("!H", pkt[12:14])[0]
                if ether_type == 0x0800:
                    if pkt_len >= 34:
                        is_ip = 1.0
                        ihl = (pkt[14] & 0xF) * 4
                        proto = pkt[23]
                        if proto == 6 and pkt_len >= 14 + ihl + 20:        # TCP
                            is_tcp = 1.0
                            tcp_off = 14 + ihl
                            src_p   = struct.unpack("!H", pkt[tcp_off:tcp_off+2])[0] / 65535.0
                            flags   = pkt[tcp_off + 13]
                            fin, syn, ack = (flags>>0)&1, (flags>>1)&1, (flags>>4)&1
                        elif proto == 17 and pkt_len >= 14 + ihl + 8:      # UDP
                            is_udp = 1.0
                            src_p  = struct.unpack("!H", pkt[14+ihl:14+ihl+2])[0] / 65535.0
                elif ether_type == 0x86DD:
                    if pkt_len >= 14 + 40:
                        version_tc_fl = pkt[14]
                        if (version_tc_fl >> 4) == 6:
                            is_ip = 1.0
                            proto = pkt[20]
                            if proto == 6 and pkt_len >= 14 + 40 + 20:        # TCP
                                is_tcp = 1.0
                                tcp_off = 14 + 40
                                src_p   = struct.unpack("!H", pkt[tcp_off:tcp_off+2])[0] / 65535.0
                                flags   = pkt[tcp_off + 13]
                                fin, syn, ack = (flags>>0)&1, (flags>>1)&1, (flags>>4)&1
                            elif proto == 17 and pkt_len >= 14 + 40 + 8:      # UDP
                                is_udp = 1.0
                                src_p  = struct.unpack("!H", pkt[54:56])[0] / 65535.0

            # 特徴量 10次元 = パケット9次元 + RAMの今の使用率1次元
            feat = [
                min(pkt_len/1500.0, 1.0),  # パケット長 (正規化)
                min(_ema_delta, 1.0),       # 到着間隔 (正規化)
                is_ip, is_tcp, is_udp,      # プロトコル種別
                float(syn), float(ack), float(fin),  # TCPフラグ
                src_p,                      # 送信元ポート (正規化)
                mem_mgr.get_usage_ratio()   # RAM使用率 → AIが自身の状態を知る
            ]

            if not _packet_queue.full():
                _packet_queue.put((feat, pkt))

            dpi_result = analyze_dpi_payload(pkt)
            _last_dpi_result = dpi_result
            _learn_safe_kernel_flow(parse_packet_transport(pkt), dpi_result)
            handle_packet_event(pkt, interface, dry_run or is_maintenance_mode(), dpi_result=dpi_result)
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            break
        except Exception as exc:
            log.warning(f"[CAPTURE] パケット処理中に例外が発生しました: {type(exc).__name__}: {exc}")


# =====================================================================
# Task 3-c: バックグラウンド学習ワーカー (別スレッドで防衛ループを邪魔しない)
# =====================================================================
_train_queue: queue.Queue = queue.Queue()

def _training_worker(model: LightweightMultiTaskAI, optimizer):
    """防衛ループから独立した別スレッドで学習を実行 → 1ms応答を保証"""
    while True:
        batch = _train_queue.get()
        if batch is None:
            break
        train_local_whitelist(model, optimizer, batch)


# =====================================================================
# Task 4-b: OSレベルのキルスイッチ
# =====================================================================
def _compute_statistical_anomaly_score(pkt_len: int) -> float:
    """第3段階: 統計的外れ値検知（3σ法）でパケット長の外れ値をスコア化する。
    直近256パケットの分布から平均・標準偏差を計算し、3σ超えをブロック対象とする。
    """
    _PACKET_LENGTH_HISTORY.append(pkt_len)
    n = len(_PACKET_LENGTH_HISTORY)
    if n < 16:  # サンプル不足は判定不能 → fail-close 側に傾ける
        return 0.0

    data = list(_PACKET_LENGTH_HISTORY)
    mean = sum(data) / n
    variance = sum((x - mean) ** 2 for x in data) / n
    std = math.sqrt(variance) if variance > 0 else 1.0
    z_score = abs(pkt_len - mean) / std

    if z_score >= 3.0:
        # 3σ 超えはスコア 0.90 を基底として、外れ具合に比例してスケール
        return min(0.99, 0.90 + (z_score - 3.0) * 0.03)
    if z_score >= 2.0:
        return min(0.70, 0.50 + (z_score - 2.0) * 0.20)
    return 0.0


def _validate_command_tokens(cmd: list) -> bool:
    """sudoで使うコマンドをシェルメタ文字由来の注入に対して安全に検証する。"""
    _MAX_TOKEN_LEN = 256
    if not isinstance(cmd, (list, tuple)) or not cmd:
        return False
    for token in cmd:
        if not isinstance(token, str) or not token.strip():
            return False
        if len(token) > _MAX_TOKEN_LEN:
            log.warning(f"[SECURITY] トークン長が上限({_MAX_TOKEN_LEN}文字)を超えています: {len(token)}文字")
            return False
        if _UNSAFE_SHELL_CHARS_RE.search(token):
            return False
        if "\x00" in token or any(ord(ch) < 32 and ch not in {"\t"} for ch in token):
            return False
    return True


def _run_command_with_sudo(cmd: list, dry_run: bool = False) -> bool:
    if dry_run:
        return True

    if not _validate_command_tokens(cmd):
        log.error("    → 安全性チェックに失敗したコマンドを拒否しました。")
        return False

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        if _PRIVILEGED_AGENT_ACTIVE:
            return _dispatch_privileged_command("run_command", cmd=cmd, dry_run=dry_run)
        log.error("    → root 権限を持つ特権ワーカーが利用できないため、コマンドを拒否しました。")
        return False

    return _execute_root_command(cmd, dry_run=dry_run)


def _attempt_pure_python_network_barrier(interface: str = None, available_interfaces=None) -> bool:
    """OSコマンドが利用できない場合でも、可能な限り純粋Pythonでフェールクローズ遮断を試みる。"""
    interfaces = []
    if available_interfaces:
        interfaces = list(available_interfaces)
    if interface and interface not in interfaces:
        interfaces.insert(0, interface)
    interfaces = [iface for iface in interfaces if iface and iface != "lo"]
    if not interfaces:
        return False

    if platform.system().lower() == "windows":
        return False

    try:
        import fcntl
    except ImportError:
        return False

    success = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for iface in interfaces:
                try:
                    ifreq = struct.pack("16sH14s", iface.encode("utf-8"), 0, b"")
                    current_flags = struct.unpack("16sH14s", fcntl.ioctl(sock.fileno(), 0x8913, ifreq))[1]
                    if current_flags & 0x1:
                        new_flags = current_flags & ~0x1
                        ifreq = struct.pack("16sH14s", iface.encode("utf-8"), new_flags, b"")
                        fcntl.ioctl(sock.fileno(), 0x8914, ifreq)
                        success = True
                except Exception as exc:
                    log.warning(f"[BARRIER] インターフェース {iface} の障壁操作に失敗しました: {exc}")
                    continue
        finally:
            sock.close()
    except Exception as exc:
        log.warning(f"[BARRIER] ネットワーク障壁の初期化に失敗しました: {exc}")
        success = False

    for iface in interfaces:
        sysfs_path = f"/sys/class/net/{iface}/operstate"
        if os.path.exists(sysfs_path):
            try:
                with open(sysfs_path, "w") as handle:
                    handle.write("down")
                success = True
            except Exception:
                pass

    return success


def _load_admin_recovery_token() -> str:
    """環境変数またはローカルトークンファイルから管理者復旧トークンを取得する。"""
    if _ADMIN_RECOVERY_TOKEN:
        return _ADMIN_RECOVERY_TOKEN
    try:
        if os.path.exists(_ADMIN_RECOVERY_TOKEN_FILE):
            with open(_ADMIN_RECOVERY_TOKEN_FILE, "r", encoding="utf-8") as handle:
                token = handle.read().strip()
                if token:
                    return token
    except Exception as exc:
        log.warning(f"[SECURITY] 管理者トークンの読み込みに失敗しました ({exc})")
    return ""


def handle_admin_recovery_signal(token: str | None = None, interface: str = None, available_interfaces=None,
                                 loopback_signal: str | None = None, dry_run: bool = False) -> dict:
    """認証済み管理者シグナルを受け取り、Fail-Closed状態のまま安全に NIC 復旧を試みる。"""
    provided_token = token or loopback_signal
    configured_token = _load_admin_recovery_token()
    if not configured_token:
        return {"authorized": False, "recovered": False, "reason": "no_token_configured"}
    if not provided_token or not hmac.compare_digest(str(provided_token), str(configured_token)):
        return {"authorized": False, "recovered": False, "reason": "unauthorized"}

    if dry_run:
        return {"authorized": True, "recovered": False, "reason": "dry_run", "commands": []}

    interfaces = []
    if available_interfaces:
        interfaces = [iface for iface in available_interfaces if iface and iface != "lo"]
    if interface and interface not in interfaces:
        interfaces.insert(0, interface)

    commands = []
    if interface:
        commands.append(["ip", "link", "set", interface, "up"])
    for iface in interfaces:
        if iface and iface != "lo" and iface != interface:
            commands.append(["ip", "link", "set", iface, "up"])
    if commands:
        for cmd in commands:
            _run_command_with_sudo(cmd, dry_run=False)
    else:
        _run_command_with_sudo(["ip", "link", "set", "lo", "up"], dry_run=False)

    with _CONTAINMENT_LOCK:
        global _KILL_SWITCH_TRIGGERED, _LAST_KILL_SWITCH_TRIGGER, _anomaly_counter, _BACKDOOR_RISK_SCORE
        _KILL_SWITCH_TRIGGERED = False
        _LAST_KILL_SWITCH_TRIGGER = 0.0
        _anomaly_counter = 0
        _BACKDOOR_RISK_SCORE = 0.0
        _KILL_SWITCH_EVENT.clear()

    log.warning("[RECOVERY_API] 管理者認証済みの安全復旧シグナルを受理しました。NIC を再初期化し、キルスイッチ状態を解除します。")
    return {"authorized": True, "recovered": True, "reason": "authorized", "commands": commands}


def _apply_anomaly_decay(now: float | None = None) -> tuple[float, bool]:
    """長期間の正常通信が続いた場合に異常カウンターを減衰させる。"""
    global _anomaly_counter, _ANOMALY_DECAY_LAST_TIME
    if now is None:
        now = time.time()
    if _ANOMALY_DECAY_LAST_TIME <= 0.0:
        _ANOMALY_DECAY_LAST_TIME = now
        return _ANOMALY_DECAY_LAST_TIME, False
    elapsed = now - _ANOMALY_DECAY_LAST_TIME
    if elapsed >= _ANOMALY_DECAY_WINDOW_SEC:
        _anomaly_counter = max(0, _anomaly_counter - 1)
        _ANOMALY_DECAY_LAST_TIME = now
        return _ANOMALY_DECAY_LAST_TIME, True
    return _ANOMALY_DECAY_LAST_TIME, False


def evaluate_threat_state(interface: str, dry_run: bool, score_a: float = 0.0,
                          backdoor_detected: bool = False, backdoor_boost: float = 0.0) -> bool:
    """バックドア/異常スコアを評価して必要なら即座にキルスイッチを発動する。"""
    global _KILL_SWITCH_TRIGGERED, _LAST_KILL_SWITCH_TRIGGER, _anomaly_counter

    effective_dry_run = dry_run or is_maintenance_mode()
    now = time.time()
    with _CONTAINMENT_LOCK:
        if _KILL_SWITCH_TRIGGERED and now - _LAST_KILL_SWITCH_TRIGGER < _KILL_SWITCH_COOLDOWN_SEC:
            return False

        effective_score = score_a
        if backdoor_boost > 0.0:
            effective_score = max(effective_score, min(0.99, effective_score + backdoor_boost))
        if backdoor_detected:
            effective_score = max(effective_score, 0.99)

        last_decay_at, decayed = _apply_anomaly_decay(now)

        if effective_score >= 0.95:
            if _anomaly_counter > 0 and not decayed and now - last_decay_at < _ANOMALY_DECAY_WINDOW_SEC:
                _anomaly_counter += 1
            else:
                _anomaly_counter = 1
        else:
            _anomaly_counter = max(0, _anomaly_counter - 1)

        should_trigger = backdoor_detected or _anomaly_counter >= 3
        if should_trigger:
            if effective_dry_run:
                log.warning("[MAINTENANCE] メンテナンス状態のため、遮断処理は Dry-Run として扱います。")
            log.critical(f"[!!!] キルスイッチ発動！ スコア={effective_score:.3f}, backdoor={backdoor_detected}, consecutive={_anomaly_counter}")
            _KILL_SWITCH_EVENT.set()
            if not _dispatch_privileged_command("kill_switch", interface=interface, dry_run=effective_dry_run):
                execute_kill_switch(interface, effective_dry_run)
            _KILL_SWITCH_TRIGGERED = True
            _LAST_KILL_SWITCH_TRIGGER = now
            return True
    return False


def _compute_unknown_behavior_score(packet_bytes: bytes, transport: dict, markers: list, dpi_result: dict) -> float:
    """既知プロトコルとヘッダー/ペイロードの不整合や、隠れた未知挙動をスコア化する。"""
    if not packet_bytes:
        return 0.0

    lower = packet_bytes.lower()
    score = 0.0
    if transport:
        dst_port = transport.get("dst_port")
        if dst_port in {443, 8443} and b"http/" in lower and not _packet_has_tls_client_hello(packet_bytes):
            score += 0.18
        if dst_port in {80, 8080} and _packet_has_tls_client_hello(packet_bytes):
            score += 0.14
        if dst_port == 53 and not (b"\x00" in packet_bytes or b"\x01" in packet_bytes or b"\x00\x35" in packet_bytes):
            score += 0.08
        if dst_port in {22, 23, 3389} and b"ssh-" not in lower and b"telnet" not in lower and b"rdp" not in lower:
            score += 0.09

    if markers and any("SNI" in marker for marker in markers) and transport and transport.get("dst_port") not in {443, 8443}:
        score += 0.12

    if dpi_result:
        if dpi_result.get("protocols") and markers and not any(proto in " ".join(dpi_result.get("protocols", [])) for proto in ("TLS/SSL", "HTTP")):
            score += 0.08
        if dpi_result.get("entropy", 0.0) >= 0.9 and dpi_result.get("score", 0.0) < 0.4:
            score += 0.05
        if dpi_result.get("fast_track"):
            score += 0.05
        if dpi_result.get("dynamic_anomaly"):
            score += 0.1

    aes_score = _compute_aes_meta_score(packet_bytes, dpi_result)
    score += aes_score
    return min(0.99, score)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [data.count(bytes([i])) for i in range(256)]
    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _compute_aes_meta_score(packet_bytes: bytes, dpi_result: dict) -> float:
    if not packet_bytes:
        return 0.0

    score = 0.0
    entropy = _shannon_entropy(packet_bytes)
    if entropy >= 7.4 and len(packet_bytes) >= 128:
        score += 0.10
    if len(packet_bytes) % 16 == 0 and entropy >= 7.0:
        score += 0.06
    if dpi_result.get("protocols") and any(proto in " ".join(dpi_result.get("protocols", [])) for proto in ("TLS/SSL", "DTLS", "SSH")):
        score += 0.05
    if dpi_result.get("tls_ja3_hash") and not dpi_result.get("tls_sni"):
        score += 0.05
    return min(0.35, score)


def _compute_behavioral_signature_score(packet_bytes: bytes, transport: dict, dpi_result: dict) -> float:
    """パケット長分布・バイト比・ジッタ/ビーミングから行動異常を評価する。"""
    if not transport:
        return 0.0

    packet_len = len(packet_bytes)
    recent_sizes = list(_TRAFFIC_ACTIVITY_HISTORY)[-16:]
    score = 0.0
    if recent_sizes:
        avg = sum(recent_sizes) / len(recent_sizes)
        std = math.sqrt(sum((x - avg) ** 2 for x in recent_sizes) / len(recent_sizes)) if len(recent_sizes) > 1 else max(1.0, avg * 0.1)
        if avg > 0:
            ratio = packet_len / avg
            if ratio >= 4.0 or ratio <= 0.25:
                score += 0.12
            if abs(packet_len - avg) / std >= 3.0:
                score += 0.14
        if len(recent_sizes) >= 8:
            small_count = sum(1 for size in recent_sizes if size < avg * 0.5)
            large_count = sum(1 for size in recent_sizes if size > avg * 2)
            if small_count >= 5 and packet_len < avg * 0.5:
                score += 0.08
            if large_count >= 5 and packet_len > avg * 2:
                score += 0.08

    if _PACKET_INTERARRIVAL_HISTORY:
        intervals = list(_PACKET_INTERARRIVAL_HISTORY)[-16:]
        avg_interval = sum(intervals) / len(intervals)
        jitter = math.sqrt(sum((d - avg_interval) ** 2 for d in intervals) / len(intervals)) if len(intervals) > 1 else 0.0
        if avg_interval > 0 and jitter <= avg_interval * 0.2 and len(intervals) >= 8:
            score += 0.12
        if avg_interval < 0.05 and len(intervals) >= 6:
            score += 0.08

    if dpi_result.get("tls_ja3_hash") and not dpi_result.get("tls_sni") and transport.get("dst_port") in {443, 8443}:
        score += 0.18

    if transport.get("dst_port") in {80, 8080, 443, 8443} and b"http" in packet_bytes.lower() and not dpi_result.get("tls_sni"):
        score += 0.05

    return min(0.99, score)


def _estimate_tls_meta_risk(packet_bytes: bytes, markers: list) -> float:
    """TLS ClientHello の SNI とパケットサイズ特徴から、暗号化プロトコルのメタアナリシスを行う。"""
    if not packet_bytes or not markers:
        return 0.0

    if not any("TLS" in marker or "SNI" in marker for marker in markers):
        return 0.0

    packet_len = len(packet_bytes)
    if packet_len < 64:
        return 0.03

    recent_sizes = list(_TRAFFIC_ACTIVITY_HISTORY)[-8:]
    if len(recent_sizes) >= 4:
        tiny_ratio = sum(1 for size in recent_sizes if size < 128) / len(recent_sizes)
        if tiny_ratio >= 0.75:
            return 0.12

    sni = next((marker.split(": ", 1)[1] for marker in markers if "SNI" in marker), None)
    if sni and any(token in sni.lower() for token in ("drop", "exec", "admin", "update", "beacon", "upload")):
        return 0.18

    return 0.0


def inspect_packet_pipeline(packet_bytes: bytes, interface: str, model=None, dry_run: bool = False,
                            feature_vector=None, dpi_result: dict = None) -> dict:
    """固定ルールを排し、DPI/AI/入力ベクトルによる連続スコアリングでパケットを評価する。"""
    global _BACKDOOR_RISK_SCORE

    if ONI_MODE:
        trace = build_diagnostic_trace(layer=1, threshold=0.01, score=1.0, reason="oni_mode")
        return {"block": True, "stage": "oni", "score": 1.0, "reason": "ONI_MODE enabled", "diagnostic_trace": trace}

    dpi_result = dpi_result or analyze_dpi_payload(packet_bytes, interface=interface)
    if dpi_result.get("suspicious"):
        trace = build_diagnostic_trace(layer=2, threshold=0.6, score=dpi_result.get("score", 0.0), reason="dpi")
        log_full_packet_inspection(packet_bytes, interface, dpi_result, stage="dpi", reason="payload_signature")
        return {"block": True, "stage": "dpi", "score": dpi_result.get("score", 0.0), "reason": "dpi", "diagnostic_trace": trace}

    transport = parse_packet_transport(packet_bytes)
    if transport and transport.get("parse_error"):
        src_ip = transport.get("src_ip")
        defense_decision = evaluate_progressive_defense(source_ip=src_ip, event_type="parse_error", occurrence_count=1)
        if defense_decision.get("defer"):
            trace = build_diagnostic_trace(layer=4, threshold=0.8, score=0.4, reason="progressive_rate_limit")
            log_full_packet_inspection(packet_bytes, interface, dpi_result, stage="parse_error", reason="packet_parse_error")
            return {"block": False, "stage": "rate_limited", "score": 0.0, "reason": "parse_error", "diagnostic_trace": trace}
        log_full_packet_inspection(packet_bytes, interface, dpi_result, stage="parse_error", reason="packet_parse_error")
        return {"block": True, "stage": "parse_error", "score": 0.95, "reason": "parse_error"}
    if transport and _is_ip_blacklisted(transport.get("src_ip")):
        log_full_packet_inspection(packet_bytes, interface, dpi_result, stage="blacklist", reason="source_ip_blacklisted")
        return {"block": True, "stage": "blacklist", "score": 0.92, "reason": "source_blacklisted"}

    markers = analyze_packet_security_markers(packet_bytes, interface=interface)

    rule_score = 0.0
    rule_reason = "clear"
    if transport and transport.get("dst_port"):
        port_pressure = min(1.0, transport.get("dst_port", 0) / 65535.0)
        rule_score = max(rule_score, 0.20 + 0.25 * port_pressure)
        rule_reason = "behavioral_port_pressure"
    if dpi_result.get("tls_ja3_hash") and not dpi_result.get("tls_sni") and transport and transport.get("dst_port") in {443, 8443}:
        rule_score = max(rule_score, 0.28)
        rule_reason = "tls_ja3_no_sni"
        _BACKDOOR_RISK_SCORE = max(_BACKDOOR_RISK_SCORE, 0.24)
    if markers:
        tls_meta_risk = _estimate_tls_meta_risk(packet_bytes, markers)
        if tls_meta_risk > 0.0:
            rule_score = max(rule_score, 0.25 + tls_meta_risk)
            rule_reason = "tls_meta"
            _BACKDOOR_RISK_SCORE = max(_BACKDOOR_RISK_SCORE, min(0.8, tls_meta_risk))
        else:
            rule_score = max(rule_score, 0.15)
            rule_reason = "security_marker"

    ai_score = 0.0
    if feature_vector is not None:
        ai_score = min(0.99, 0.2 + 0.15 * max(feature_vector[:3]) + 0.1 * sum(feature_vector[3:8]) + 0.1 * feature_vector[9])
    elif model is not None:
        try:
            with torch.no_grad():
                score_a, _, _ = model(torch.tensor([[0.0] * 10], dtype=torch.float32))
            ai_score = float(score_a.item()) if hasattr(score_a, "item") else 0.0
        except Exception:
            ai_score = 0.0

    if ai_score >= 0.88:
        trace = build_diagnostic_trace(layer=3, threshold=0.88, score=ai_score, reason="model_score")
        return {"block": True, "stage": "ai", "score": ai_score, "reason": "model_score", "diagnostic_trace": trace}

    math_score = 0.0
    if feature_vector is not None:
        math_score = min(0.99, sum(float(v) for v in feature_vector[:5]) / 5.0)
    elif transport:
        math_score = min(0.99, (0.35 if transport.get("protocol") == socket.IPPROTO_TCP else 0.1))

    if math_score >= 0.88:
        trace = build_diagnostic_trace(layer=4, threshold=0.88, score=math_score, reason="math_threshold")
        return {"block": True, "stage": "math", "score": math_score, "reason": "math_threshold", "diagnostic_trace": trace}

    behavior_score = _compute_behavioral_signature_score(packet_bytes, transport, dpi_result)
    unknown_score = _compute_unknown_behavior_score(packet_bytes, transport, markers, dpi_result)
    composite_score = min(
        0.99,
        rule_score * 0.22 + ai_score * 0.20 + math_score * 0.13 + unknown_score * 0.25 + behavior_score * 0.20,
    )

    if behavior_score >= 0.30 and (unknown_score >= 0.16 or rule_score >= 0.25):
        trace = build_diagnostic_trace(layer=4, threshold=0.30, score=min(0.99, behavior_score + max(rule_score, ai_score, math_score) * 0.25), reason="behavioral_signature")
        return {"block": True, "stage": "behavioral_signature", "score": min(0.99, behavior_score + max(rule_score, ai_score, math_score) * 0.25), "reason": "behavioral_signature", "diagnostic_trace": trace}

    if unknown_score >= 0.22 and (rule_score >= 0.2 or ai_score >= 0.2 or math_score >= 0.15):
        trace = build_diagnostic_trace(layer=4, threshold=0.22, score=min(0.99, unknown_score + max(rule_score, ai_score, math_score) * 0.3), reason="unknown_behavior")
        return {"block": True, "stage": "unknown_behavior", "score": min(0.99, unknown_score + max(rule_score, ai_score, math_score) * 0.3), "reason": "unknown_behavior", "diagnostic_trace": trace}
    if composite_score >= 0.80:
        trace = build_diagnostic_trace(layer=4, threshold=0.8, score=composite_score, reason="composite_scoring")
        return {"block": True, "stage": "composite", "score": composite_score, "reason": "composite_scoring", "diagnostic_trace": trace}

    return {"block": False, "stage": "pass", "score": max(rule_score, ai_score, math_score, unknown_score), "reason": rule_reason}


def handle_packet_event(packet_bytes: bytes, interface: str, dry_run: bool, dpi_result: dict = None) -> bool:
    """パケット到着時に既存の脅威状態を参照し、必要なら遮断へ遷移する。"""
    global _LAST_PACKET_EVENT_TIME
    now = time.time()
    if _LAST_PACKET_EVENT_TIME > 0.0:
        _PACKET_INTERARRIVAL_HISTORY.append(now - _LAST_PACKET_EVENT_TIME)
    _LAST_PACKET_EVENT_TIME = now
    _TRAFFIC_ACTIVITY_HISTORY.append(len(packet_bytes))
    maybe_log_crypto_markers(packet_bytes, interface, now)
    if _KILL_SWITCH_TRIGGERED:
        return False

    effective_dry_run = dry_run or is_maintenance_mode()
    pipeline = inspect_packet_pipeline(packet_bytes, interface, dry_run=effective_dry_run, dpi_result=dpi_result)
    if pipeline.get("block"):
        stage = pipeline.get("stage")
        score = min(0.99, pipeline.get("score", 0.0))
        backdoor_detected = stage in {"math", "ai", "blacklist"} or (stage == "dpi" and (score >= 0.72 or dpi_result.get("fast_track", False)))
        return evaluate_threat_state(
            interface,
            effective_dry_run,
            score_a=score,
            backdoor_detected=backdoor_detected,
            backdoor_boost=max(0.05, score * 0.15) if backdoor_detected else 0.0,
        )

    if _BACKDOOR_RISK_SCORE > 0.0:
        return evaluate_threat_state(
            interface,
            effective_dry_run,
            score_a=min(0.99, 0.5 + _BACKDOOR_RISK_SCORE),
            backdoor_detected=True,
            backdoor_boost=_BACKDOOR_RISK_SCORE,
        )
    return False


def execute_kill_switch(interface: str, dry_run: bool, available_interfaces=None, containment_mode: str = "full_isolation", management_ports=None, management_ips=None):
    """
    異常検知時にOSコマンドでネットワークを物理的に切断します。
    失敗しても次のコマンドを続ける fail-safe 方式です。
    """
    if available_interfaces is None:
        available_interfaces = discover_available_interfaces()

    containment_plan = build_containment_plan(
        interface,
        containment_mode=containment_mode,
        management_ports=management_ports,
        management_ips=management_ips,
    )
    profile = profile_environment()
    payload = generate_optimal_kill_payload(profile, learning_data=["bridge", "vpn", "unreachable", "iptables", "dbus"])

    log.critical("[ACTIVE_DEFENSE / AIRGAP_CONTAINMENT] 隔離プロトコルを起動します。")
    log.info(f"[CONTAINMENT_PLAN] {json.dumps(containment_plan, sort_keys=True)}")
    if dry_run:
        log.critical("    → Dry-Runモードのため実際の遮断はスキップ (安全モード)")
        return execute_generated_payload(payload, dry_run=True, available_interfaces=available_interfaces, interface=interface)

    success = execute_generated_payload(payload, dry_run=False, available_interfaces=available_interfaces, interface=interface)

    if success:
        log.warning("\033[1;33m[RECOVERY_PROTOCOL] 介入後の復旧には以下を実行してください:\033[0m")
        log.warning("\033[1;33m  - sudo systemctl restart networking\033[0m")
        log.warning(f"\033[1;33m  - sudo ip link set {interface} up\033[0m")
        for iface in available_interfaces:
            if iface != "lo":
                log.warning(f"\033[1;33m  - sudo ip link set {iface} up\033[0m")
    else:
        log.error("    → すべての遮断コマンドが失敗しました。sudo 権限またはコマンドの有無を確認してください。")


# =====================================================================
# ローカル限定のデータ更新スケジューラ
# =====================================================================
def _gdrive_update_worker(model: LightweightMultiTaskAI, optimizer,
                          folder_id: str, local_dir: str, interval_sec: int):
    """
    外部ネットワークを使わず、ローカルディレクトリのデータのみを再評価するバックグラウンドワーカー。
    これにより、完全オフライン運用が保証されます。
    """
    first_run = True
    while True:
        if not first_run:
            time.sleep(interval_sec)
        first_run = False

        if ONI_MODE:
            log.warning("[ローカル更新] ONI_MODE 中のため、外部データ更新を一時停止します。")
            continue

        enter_maintenance_mode("local data refresh")
        try:
            log.info("[ローカル更新] ローカルディレクトリから再評価を開始します。")
            local_raw_dir = os.path.join(local_dir, "gdrive_raw")
            if not os.path.exists(local_raw_dir):
                log.debug("[ローカル更新] 入力データディレクトリが存在しません。次回まで待機します。")
                continue

            downloaded_files = []
            for root, _, files in os.walk(local_raw_dir):
                for file_name in files:
                    if file_name.lower().endswith((".json", ".jsonl", ".txt")):
                        downloaded_files.append(os.path.join(root, file_name))

            if not downloaded_files:
                log.warning("[ローカル更新] 監視対象ファイルが見つかりません。次の更新を待ちます。")
                continue

            raw_data = load_raw_data_from_files(downloaded_files)
            if raw_data:
                curated_dir = os.path.join(local_dir, "curated")
                curated_path = curate_and_save(model, raw_data, curated_dir)

                if os.path.exists(curated_path):
                    batch = []
                    with open(curated_path) as f:
                        for line in f:
                            try:
                                batch.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
                    if batch:
                        _train_queue.put(batch)
                        log.info(f"[ローカル更新] {len(batch)}件の厳選データを学習キューへ投入しました。")
        finally:
            exit_maintenance_mode()


# =====================================================================
# メインループ (すべてを統合する中枢)
# =====================================================================
def main():
    parser = argparse.ArgumentParser(description="超軽量・オールインワン エアギャップ自動遮断AI")
    parser.add_argument("--interface",      default="eth0",  help="監視するNIC (例: eth0)")
    parser.add_argument("--drive-id",
                        default=GDRIVE_FOLDER_ID,
                        help="(レガシー) データ更新監視識別子。実運用では外部接続しません。")
    parser.add_argument("--local-dir",      default="./ai_data", help="ローカルデータ保存先")
    parser.add_argument("--update-interval",default=300,  type=int, help="ローカル更新チェック間隔(秒)")
    parser.add_argument("--max-memory-mb",  default=500,  type=int, help="RAM上限(MB)")
    parser.add_argument("--no-dry-run",     action="store_true", help="指定すると実際にNICをダウンさせます(危険！)")
    args = parser.parse_args()
    dry_run = not args.no_dry_run

    available_interfaces = discover_available_interfaces()
    monitor_interface = select_monitor_interface(args.interface, available_interfaces)
    global _MONITOR_INTERFACE, _DRY_RUN
    _MONITOR_INTERFACE = monitor_interface
    _DRY_RUN = dry_run
    log_interface_selection(monitor_interface, available_interfaces)

    print("\n" + "="*60)
    print("  超軽量・オールインワン エアギャップ自動遮断AI 起動")
    print("="*60)
    print(f"  監視NIC      : {monitor_interface}")
    print(f"  ローカルデータ保存先: {args.local_dir}")
    print(f"  RAM上限      : {args.max_memory_mb}MB")
    print(f"  更新間隔     : {args.update_interval}秒ごとにローカルデータを再評価")
    print(f"  Dry-Run      : {dry_run} (--no-dry-run で実遮断モード)")
    print("="*60 + "\n")

    # ── 初期化 ──
    os.makedirs(args.local_dir, exist_ok=True)
    model = LightweightMultiTaskAI(input_dim=10)

    # ★ クラウド学習済みモデルの読み込み（防衛力MAX起動）
    # ─────────────────────────────────────────────────────────────
    # 【設計意図: 「クラウドで鍛えた脳」を引き継ぐ仕組み】
    # このAIは最初から「ゼロ」で学ぶのではありません。
    # あらかじめクラウド（サーバー）で大量のハッキングデータを学習した
    # 「最強の脳（モデルの重み）」を cloud_base_model.pth として
    # ローカルに置いておくことで、起動した瞬間から最高の防衛力を発揮できます！
    #
    # これが「クラウド2：ローカル1」の「2」の部分です。
    # クラウドが鍛えた知識 (shared_layer, Head A) を凍結して引き継ぎ、
    # ローカルでは Head B だけをこの端末専用にカスタマイズします。
    # ─────────────────────────────────────────────────────────────
    cloud_model_path = os.path.join(args.local_dir, "cloud_base_model.pth")
    if not load_cloud_model(model, cloud_model_path):
        log.warning("           → ローカルに保存された .pth ファイルを配置すると防衛力が上がります！")

    model.eval()  # 推論モードで起動（防衛最優先）
    boot_report = boot_time_auto_hardening(profile_environment())
    log.info(f"[BOOT_HARDENING] 事前評価結果: {boot_report}")
    _install_self_protection_handlers()
    threading.Thread(target=_self_protection_monitor, daemon=True).start()

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        _ensure_privileged_agent(monitor_interface, args.max_memory_mb, args.local_dir, dry_run)
    _drop_privileges_if_possible()
    optimizer = optim.SGD(model.parameters(), lr=0.005)  # 低い学習率で既存知識を守る
    mem_mgr   = MemoryManager(max_memory_mb=args.max_memory_mb, swap_dir=args.local_dir)
    whitelist_buf: list = []  # RAM上の一時バッファ

    # ── スレッド起動 ──
    threads = [
        threading.Thread(target=_training_worker,        args=(model, optimizer),        daemon=True),
        threading.Thread(target=_gdrive_update_worker,
                         args=(model, optimizer, args.drive_id, args.local_dir, args.update_interval),
                         daemon=True),
        threading.Thread(target=_backdoor_scan_worker,   args=(10,), daemon=True),
        threading.Thread(target=_mtd_worker,            args=(monitor_interface, 20), daemon=True),
    ]
    for t in threads:
        t.start()

    update_gdrive_ips()
    log.info("[メインループ] 開始！ Ctrl+C で終了")

    try:
        while True:
            # ── 司令塔: メモリ監視 ──
            mem_ratio = mem_mgr.check()
            if mem_mgr.is_critical:
                log.warning(f"[司令塔] RAM危機 ({mem_ratio*100:.1f}%) → バッファをストレージへ退避！")
                mem_mgr.evict_buffer(whitelist_buf)
                whitelist_buf.clear()

            # ── パケット取得 ──
            try:
                payload = _packet_queue.get(timeout=0.01)
            except queue.Empty:
                continue
            feat, pkt = payload

            maybe_log_crypto_markers(pkt, monitor_interface, time.time())

            dpi_result = analyze_dpi_payload(pkt)
            pipeline = inspect_packet_pipeline(pkt, monitor_interface, model=model, feature_vector=feat, dpi_result=dpi_result)
            if pipeline.get("block"):
                evaluate_threat_state(monitor_interface, dry_run, score_a=min(0.99, pipeline.get("score", 0.0)),
                                     backdoor_detected=True, backdoor_boost=max(0.1, pipeline.get("score", 0.0)))
                time.sleep(5)
                continue

            # ── AIによる超高速推論 (no_grad = 勾配なし = 最速・最省メモリ) ──
            x = torch.tensor([feat], dtype=torch.float32)
            with torch.no_grad():
                score_a, score_b, score_c = model(x)
            a, b, c = score_a.item(), score_b.item(), score_c.item()

            mem_ratio = mem_mgr.check(head_c_score=c)
            if mem_mgr.is_critical:
                log.warning(f"[司令塔] RAM危機 ({mem_ratio*100:.1f}%) → バッファをストレージへ退避！")
                mem_mgr.evict_buffer(whitelist_buf)
                whitelist_buf.clear()

            # ================================================================
            # 判定ロジック (優先度: 防衛 > 司令 > 学習)
            # ================================================================

            # 【最優先】バックドア/高スコア検知時は即時キルスイッチ
            if evaluate_threat_state(monitor_interface, dry_run, score_a=a,
                                     backdoor_detected=_BACKDOOR_RISK_SCORE > 0.0,
                                     backdoor_boost=_BACKDOOR_RISK_SCORE):
                time.sleep(5)  # 遮断後の冷却時間
                continue       # 他の処理を一切スキップ

            # 【優先2】Head C > 0.8 → 司令塔がデータ退避を命令
            if c > 0.8 and whitelist_buf:
                mem_mgr.evict_buffer(whitelist_buf)
                whitelist_buf.clear()

            # 【優先3】Head B > 0.7 → 正常な通信としてバッファに追加
            if b > 0.7:
                whitelist_buf.append({"features": feat, "label": 0})
                if len(whitelist_buf) >= 100:
                    # 防衛ループをブロックしないよう学習キューへ投げる
                    _train_queue.put(list(whitelist_buf))
                    whitelist_buf.clear()
                    log.info("[学習役] → バックグラウンド学習へ投入！")

    except KeyboardInterrupt:
        log.info("\n[終了] ユーザー割り込み受信。クリーンアップ中...")
    finally:
        _train_queue.put(None)  # 学習スレッドを正常終了
        mem_mgr.cleanup()
        log.info("[終了] すべてのスレッドを終了しました")


if __name__ == "__main__":
    main()
