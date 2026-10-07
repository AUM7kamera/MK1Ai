#!/usr/bin/env python3
"""Read-only, HTTPS-only MK1Ai dashboard with passkey and dual OTP authentication."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import http.cookies
import ipaddress
import json
import logging
import os
import secrets
import smtplib
import sqlite3
import stat
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from email.message import EmailMessage
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from mk1_secure_transport import (
    SecureTransportError,
    require_wireguard_address,
    require_wireguard_full_tunnel,
)
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    parse_authentication_credential_json,
    parse_registration_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


LOGGER = logging.getLogger("mk1.remote")
MAX_REQUEST_BYTES = 65_536
SESSION_IDLE_SECONDS = 15 * 60
SESSION_LIFETIME_SECONDS = 2 * 60 * 60
AUTH_CHALLENGE_SECONDS = 120
OTP_LIFETIME_SECONDS = 300
OTP_MAX_ATTEMPTS = 5
RATE_LIMIT_WINDOW_SECONDS = 300
RATE_LIMIT_REQUESTS = 12
COOKIE_NAME = "mk1_session"


@dataclass(frozen=True)
class DashboardConfig:
    host: str
    port: int
    origin: str
    rp_id: str
    rp_name: str
    wireguard_interface: str
    wireguard_bind_address: str
    status_path: Path
    database_path: Path
    bootstrap_path: Path
    signing_key_path: Path
    admin_email: str
    email_from: str
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_app_password: str
    admin_phone: str
    twilio_account_sid: str
    twilio_auth_token: str
    twilio_from_number: str
    role: str
    owner_profile_path: Path

    @classmethod
    def from_environment(cls, data_directory: Path | None = None) -> DashboardConfig:
        data_dir = data_directory or Path(os.environ.get("MK1_DATA_DIR", "ai_data"))
        try:
            port = int(os.environ.get("MK1_REMOTE_PORT", "8080"))
            smtp_port = int(os.environ.get("MK1_SMTP_PORT", "587"))
        except ValueError as exc:
            raise ValueError("MK1_REMOTE_PORT と MK1_SMTP_PORT は整数で指定してください") from exc
        config = cls(
            host=os.environ.get("MK1_REMOTE_HOST", "127.0.0.1"),
            port=port,
            origin=os.environ.get("MK1_REMOTE_ORIGIN", ""),
            rp_id=os.environ.get("MK1_REMOTE_RP_ID", ""),
            rp_name=os.environ.get("MK1_REMOTE_RP_NAME", "MK1Ai Security Console"),
            wireguard_interface=os.environ.get("MK1_WIREGUARD_INTERFACE", "wg0"),
            wireguard_bind_address=os.environ.get("MK1_WIREGUARD_BIND_ADDRESS", ""),
            status_path=data_dir / "panel-status.txt",
            database_path=data_dir / "remote-dashboard.sqlite3",
            bootstrap_path=data_dir / "remote-bootstrap.token",
            signing_key_path=data_dir / "remote-session.key",
            admin_email=os.environ.get("MK1_ADMIN_EMAIL", ""),
            email_from=os.environ.get("MK1_EMAIL_FROM", ""),
            smtp_host=os.environ.get("MK1_SMTP_HOST", "smtp.gmail.com"),
            smtp_port=smtp_port,
            smtp_username=os.environ.get("MK1_SMTP_USERNAME", ""),
            smtp_app_password=os.environ.get("MK1_SMTP_APP_PASSWORD", ""),
            admin_phone=os.environ.get("MK1_ADMIN_PHONE", ""),
            twilio_account_sid=os.environ.get("MK1_TWILIO_ACCOUNT_SID", ""),
            twilio_auth_token=os.environ.get("MK1_TWILIO_AUTH_TOKEN", ""),
            twilio_from_number=os.environ.get("MK1_TWILIO_FROM_NUMBER", ""),
            role=os.environ.get("MK1_REMOTE_ROLE", "login"),
            owner_profile_path=Path(
                os.environ.get("MK1_OWNER_PROFILE", str(data_dir / "owner_profile.dat"))
            ),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if self.role not in ("enrollment", "login"):
            raise ValueError("MK1_REMOTE_ROLE は enrollment または login を指定してください")
        if not 1 <= self.port <= 65535 or not 1 <= self.smtp_port <= 65535:
            raise ValueError("ポート番号は1〜65535で指定してください")
        try:
            ipaddress.ip_address(self.wireguard_bind_address)
            if not ipaddress.ip_address(self.host).is_loopback:
                raise ValueError
        except ValueError as exc:
            raise ValueError(
                "バックエンドはloopbackに限定し、WireGuard bind IPを設定してください"
            ) from exc
        parsed_origin = urlsplit(self.origin)
        if (
            parsed_origin.scheme != "https"
            or not parsed_origin.hostname
            or parsed_origin.username
            or parsed_origin.password
            or parsed_origin.path not in ("", "/")
            or parsed_origin.query
            or parsed_origin.fragment
        ):
            raise ValueError("MK1_REMOTE_ORIGIN は https://ホスト[:ポート] で指定してください")
        if parsed_origin.hostname.lower() != self.rp_id.lower():
            raise ValueError("MK1_REMOTE_RP_ID は MK1_REMOTE_ORIGIN のホスト名と一致させてください")
        if "@" not in self.admin_email:
            raise ValueError("MK1_ADMIN_EMAIL はメールアドレスで指定してください")
        if self.role == "login":
            if not (
                self.email_from
                and self.smtp_host
                and self.smtp_username
                and self.smtp_app_password
                and self.admin_phone
                and self.twilio_account_sid
                and self.twilio_auth_token
                and self.twilio_from_number
            ):
                raise ValueError(
                    "本番ログイン用のGmail SMTPとTwilio SMS設定が不足しています"
                )
            if "@" not in self.email_from:
                raise ValueError("MK1_EMAIL_FROM はメールアドレスで指定してください")
            if not self.admin_phone.startswith("+"):
                raise ValueError("MK1_ADMIN_PHONE は国番号付きのE.164形式で指定してください")


def _atomic_private_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except OSError:
        temporary_path.unlink(missing_ok=True)
        raise


def _atomic_immutable_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o400)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary_path, path)
        temporary_path.unlink()
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        temporary_path.unlink(missing_ok=True)
        raise


class DashboardState:
    def __init__(self, config: DashboardConfig):
        self.config = config
        config.database_path.parent.mkdir(parents=True, exist_ok=True)
        current_umask = os.umask(0o077)
        try:
            self._initialize_database()
            if not config.signing_key_path.exists():
                _atomic_private_write(config.signing_key_path, secrets.token_bytes(32))
            self.signing_key = config.signing_key_path.read_bytes()
            if len(self.signing_key) != 32:
                raise ValueError("リモート画面の署名鍵ファイルが不正です")
            if config.role == "login":
                self._load_owner_profile()
            elif config.owner_profile_path.exists():
                raise ValueError("登録プロフィールが既にあります。登録専用サービスを起動できません")
        finally:
            os.umask(current_umask)

        self.lock = threading.RLock()
        self.sessions: dict[str, dict[str, Any]] = {}
        self.rate_limits: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self.bootstrap_token: str | None = None
        if config.role == "enrollment" and not self.has_credentials():
            self.bootstrap_token = self._ensure_bootstrap_token()

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.config.database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize_database(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS credentials ("
                "credential_id BLOB PRIMARY KEY, public_key BLOB NOT NULL, "
                "sign_count INTEGER NOT NULL, created_at INTEGER NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value BLOB NOT NULL)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO metadata(key, value) VALUES('user_id', ?)",
                (secrets.token_bytes(32),),
            )
        os.chmod(self.config.database_path, 0o600)

    def _read_owner_profile(self) -> tuple[bytes, list[tuple[bytes, bytes, int]]]:
        try:
            descriptor = os.open(
                self.config.owner_profile_path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            with os.fdopen(descriptor, "rb") as handle:
                metadata = os.fstat(handle.fileno())
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o400
                ):
                    raise ValueError(
                        "owner_profile.dat は mode 0400 の通常ファイルである必要があります"
                    )
                raw_profile = handle.read(65_537)
            if len(raw_profile) > 65_536:
                raise ValueError("owner_profile.dat のサイズが上限を超えています")
            profile = json.loads(raw_profile.decode("ascii"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("owner_profile.dat を読み込めません") from exc
        if (
            not isinstance(profile, dict)
            or set(profile) != {"version", "user_id", "credentials"}
            or isinstance(profile["version"], bool)
            or profile["version"] != 1
            or not isinstance(profile["user_id"], str)
            or not isinstance(profile["credentials"], list)
            or not 1 <= len(profile["credentials"]) <= 10
        ):
            raise ValueError("owner_profile.dat の形式が不正です")

        def decode_field(value: Any, field_name: str, minimum: int, maximum: int) -> bytes:
            if not isinstance(value, str) or len(value) > maximum * 2:
                raise ValueError(f"owner_profile.dat の{field_name}が不正です")
            try:
                decoded = base64.b64decode(
                    value + "=" * (-len(value) % 4), altchars=b"-_", validate=True,
                )
            except (ValueError, binascii.Error) as exc:
                raise ValueError(f"owner_profile.dat の{field_name}が不正です") from exc
            if not minimum <= len(decoded) <= maximum:
                raise ValueError(f"owner_profile.dat の{field_name}長が不正です")
            return decoded

        user_id = decode_field(profile["user_id"], "user_id", 1, 128)
        credentials: list[tuple[bytes, bytes, int]] = []
        seen_ids: set[bytes] = set()
        for item in profile["credentials"]:
            if not isinstance(item, dict) or set(item) != {
                "credential_id", "public_key", "sign_count",
            }:
                raise ValueError("owner_profile.dat の認証情報形式が不正です")
            credential_id = decode_field(item["credential_id"], "credential_id", 1, 1024)
            public_key = decode_field(item["public_key"], "public_key", 1, 4096)
            sign_count = item["sign_count"]
            if (
                credential_id in seen_ids
                or isinstance(sign_count, bool)
                or not isinstance(sign_count, int)
                or not 0 <= sign_count <= 2**32 - 1
            ):
                raise ValueError("owner_profile.dat の認証情報が不正です")
            seen_ids.add(credential_id)
            credentials.append((credential_id, public_key, sign_count))
        return user_id, credentials

    def _load_owner_profile(self) -> None:
        user_id, credentials = self._read_owner_profile()
        profile_keys = {
            (credential_id, public_key)
            for credential_id, public_key, _ in credentials
        }
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT credential_id, public_key FROM credentials"
            ).fetchall()
            existing_keys = {
                (bytes(row["credential_id"]), bytes(row["public_key"]))
                for row in rows
            }
            if existing_keys and existing_keys != profile_keys:
                raise ValueError("ローカル認証DBとowner_profile.datが一致しません")
            if not existing_keys:
                connection.execute(
                    "UPDATE metadata SET value=? WHERE key='user_id'", (user_id,),
                )
                connection.executemany(
                    "INSERT INTO credentials(credential_id, public_key, sign_count, created_at) "
                    "VALUES(?, ?, ?, ?)",
                    [
                        (credential_id, public_key, sign_count, int(time.time()))
                        for credential_id, public_key, sign_count in credentials
                    ],
                )
            else:
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key='user_id'"
                ).fetchone()
                if row is None or bytes(row["value"]) != user_id:
                    raise ValueError("ローカル認証DBのWebAuthnユーザーIDが一致しません")

    def has_credentials(self) -> bool:
        with self._connect() as connection:
            row = connection.execute("SELECT 1 FROM credentials LIMIT 1").fetchone()
        return row is not None

    def _ensure_bootstrap_token(self) -> str:
        if self.config.bootstrap_path.exists():
            return self.config.bootstrap_path.read_text(encoding="ascii").strip()
        token = secrets.token_urlsafe(32)
        _atomic_private_write(self.config.bootstrap_path, token.encode("ascii"))
        return token

    def validate_bootstrap_token(self, provided: str) -> bool:
        expected = self.bootstrap_token
        return bool(expected and hmac.compare_digest(expected, provided))

    def user_id(self) -> bytes:
        with self._connect() as connection:
            row = connection.execute("SELECT value FROM metadata WHERE key='user_id'").fetchone()
        if row is None:
            raise RuntimeError("管理者のWebAuthn識別子がありません")
        return bytes(row["value"])

    def credential_rows(self) -> list[sqlite3.Row]:
        with self._connect() as connection:
            return connection.execute(
                "SELECT credential_id, public_key, sign_count FROM credentials"
            ).fetchall()

    def store_credential(self, credential_id: bytes, public_key: bytes, sign_count: int) -> None:
        if (
            self.config.role != "enrollment"
            or self.config.owner_profile_path.exists()
            or self.has_credentials()
        ):
            raise RuntimeError("初回登録専用モードでのみ登録できます")
        profile = {
            "version": 1,
            "user_id": base64.urlsafe_b64encode(self.user_id()).decode("ascii").rstrip("="),
            "credentials": [{
                "credential_id": base64.urlsafe_b64encode(credential_id).decode("ascii").rstrip("="),
                "public_key": base64.urlsafe_b64encode(public_key).decode("ascii").rstrip("="),
                "sign_count": sign_count,
            }],
        }
        _atomic_immutable_write(
            self.config.owner_profile_path,
            json.dumps(profile, separators=(",", ":"), sort_keys=True).encode("ascii"),
        )
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO credentials(credential_id, public_key, sign_count, created_at) "
                "VALUES(?, ?, ?, ?)",
                (credential_id, public_key, sign_count, int(time.time())),
            )
        self.bootstrap_token = None
        self.config.bootstrap_path.unlink(missing_ok=True)

    def update_sign_count(self, credential_id: bytes, sign_count: int) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE credentials SET sign_count=? WHERE credential_id=?",
                (sign_count, credential_id),
            )
        if cursor.rowcount != 1:
            raise RuntimeError("認証情報のカウンターを更新できません")

    def new_session(self) -> tuple[str, dict[str, Any]]:
        now = time.time()
        session_id = secrets.token_urlsafe(32)
        session = {
            "csrf": secrets.token_urlsafe(32),
            "created_at": now,
            "last_seen": now,
            "stage": "anonymous",
            "challenge": None,
            "challenge_expires": 0.0,
        }
        with self.lock:
            self._purge_sessions_locked(now)
            if len(self.sessions) >= 2048:
                raise RuntimeError("同時セッション数の上限に達しました")
            self.sessions[session_id] = session
        return session_id, session

    def get_session(self, session_id: str | None) -> dict[str, Any] | None:
        if not session_id:
            return None
        now = time.time()
        with self.lock:
            self._purge_sessions_locked(now)
            session = self.sessions.get(session_id)
            if session is not None:
                session["last_seen"] = now
            return session

    def _purge_sessions_locked(self, now: float) -> None:
        expired = [
            session_id for session_id, session in self.sessions.items()
            if now - session["last_seen"] > SESSION_IDLE_SECONDS
            or now - session["created_at"] > SESSION_LIFETIME_SECONDS
        ]
        for session_id in expired:
            self.sessions.pop(session_id, None)

    def allow_request(self, address: str, route: str) -> bool:
        now = time.monotonic()
        with self.lock:
            for rate_key, history in list(self.rate_limits.items()):
                while history and now - history[0] > RATE_LIMIT_WINDOW_SECONDS:
                    history.popleft()
                if not history:
                    self.rate_limits.pop(rate_key, None)
            key = (address, route)
            if key not in self.rate_limits and len(self.rate_limits) >= 4096:
                return False
            requests = self.rate_limits[key]
            while requests and now - requests[0] > RATE_LIMIT_WINDOW_SECONDS:
                requests.popleft()
            if len(requests) >= RATE_LIMIT_REQUESTS:
                return False
            requests.append(now)
            return True

    def code_digest(self, code: str, purpose: str) -> str:
        return hmac.new(
            self.signing_key,
            f"{purpose}:{code}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def status(self) -> dict[str, Any]:
        allowed = {
            "state": str,
            "packets_per_second": float,
            "packets_total": int,
            "threat_score": float,
            "backdoor_score": float,
            "isolation_active": int,
            "mode": str,
            "dry_run": int,
            "alert": str,
            "interface": str,
            "model_sync_status": str,
            "rsi_connection_status": str,
            "training_queue_batches": int,
            "learning_mode": int,
            "ram_used_mb": float,
            "ram_limit_mb": int,
            "swap_used_mb": float,
        }
        result: dict[str, Any] = {"state": "STOPPED", "alert": "NONE"}
        try:
            for line in self.config.status_path.read_text(encoding="ascii").splitlines():
                key, separator, raw_value = line.partition("=")
                if not separator or key not in allowed:
                    continue
                value_type = allowed[key]
                if value_type is str:
                    if raw_value.isascii() and len(raw_value) <= 64:
                        result[key] = raw_value
                elif value_type is int:
                    value = int(raw_value)
                    if 0 <= value <= 2**53:
                        result[key] = value
                else:
                    value = float(raw_value)
                    if 0 <= value <= 1_000_000_000:
                        result[key] = value
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            LOGGER.error("監視状態ファイルを解析できません: %s", type(exc).__name__)
        result["sampled_at"] = int(time.time())
        return result

    def send_email_code(self, code: str) -> None:
        require_wireguard_full_tunnel(self.config.wireguard_interface)
        message = EmailMessage()
        message["Subject"] = "MK1Ai security-console verification code"
        message["From"] = self.config.email_from
        message["To"] = self.config.admin_email
        message.set_content(
            f"Your MK1Ai verification code is {code}.\n"
            f"It expires in {OTP_LIFETIME_SECONDS // 60} minutes. "
            "If you did not request it, ignore this email."
        )
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        with smtplib.SMTP(
            self.config.smtp_host, self.config.smtp_port, timeout=10,
        ) as client:
            client.ehlo()
            client.starttls(context=context)
            client.ehlo()
            client.login(self.config.smtp_username, self.config.smtp_app_password)
            client.send_message(message)

    def send_sms_code(self, code: str) -> None:
        require_wireguard_full_tunnel(self.config.wireguard_interface)
        endpoint = (
            "https://api.twilio.com/2010-04-01/Accounts/"
            f"{urllib.parse.quote(self.config.twilio_account_sid, safe='')}/Messages.json"
        )
        body = urllib.parse.urlencode({
            "To": self.config.admin_phone,
            "From": self.config.twilio_from_number,
            "Body": f"MK1Ai verification code: {code}. Expires in 5 minutes.",
        }).encode("ascii")
        credentials = base64.b64encode(
            f"{self.config.twilio_account_sid}:{self.config.twilio_auth_token}".encode("utf-8")
        ).decode("ascii")
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        with urllib.request.urlopen(request, timeout=10, context=context) as response:
            if response.status not in (200, 201, 202):
                raise RuntimeError(f"SMSプロバイダーがHTTP {response.status}を返しました")
            response.read(4096)

    def issue_otp(self, session: dict[str, Any]) -> None:
        email_code = f"{secrets.randbelow(1_000_000):06d}"
        sms_code = f"{secrets.randbelow(1_000_000):06d}"
        while hmac.compare_digest(email_code, sms_code):
            sms_code = f"{secrets.randbelow(1_000_000):06d}"
        session.update({
            "stage": "otp",
            "email_code_digest": self.code_digest(email_code, "email"),
            "sms_code_digest": self.code_digest(sms_code, "sms"),
            "otp_expires": time.time() + OTP_LIFETIME_SECONDS,
            "otp_attempts": 0,
        })
        delivery_errors: list[Exception] = []
        with ThreadPoolExecutor(max_workers=2) as executor:
            deliveries = (
                executor.submit(self.send_email_code, email_code),
                executor.submit(self.send_sms_code, sms_code),
            )
            for delivery in deliveries:
                try:
                    delivery.result()
                except (OSError, smtplib.SMTPException, urllib.error.URLError, RuntimeError) as exc:
                    delivery_errors.append(exc)
        if delivery_errors:
            session["stage"] = "failed"
            session.pop("email_code_digest", None)
            session.pop("sms_code_digest", None)
            LOGGER.error(
                "認証コードを両方のチャネルへ送信できません: %s",
                type(delivery_errors[0]).__name__,
            )
            raise RuntimeError("メールとSMSの両方へ認証コードを送信できませんでした") from delivery_errors[0]


class RemoteDashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    dashboard_state: DashboardState

    def __init__(self, config: DashboardConfig):
        config.validate()
        try:
            require_wireguard_full_tunnel(config.wireguard_interface)
            require_wireguard_address(
                config.wireguard_interface, config.wireguard_bind_address,
            )
        except SecureTransportError as exc:
            raise ValueError(f"WireGuardの必須確認に失敗しました: {exc}") from exc
        self.dashboard_state = DashboardState(config)
        super().__init__((config.host, config.port), DashboardHandler)


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "MK1Ai"
    sys_version = ""

    @property
    def state(self) -> DashboardState:
        return cast(RemoteDashboardServer, self.server).dashboard_state

    def log_message(self, format_string: str, *args: Any) -> None:
        del format_string
        status = args[3] if len(args) > 3 else "request"
        LOGGER.info("remote-dashboard %s %s", self.client_address[0], status)

    def _headers(self, content_type: str = "application/json; charset=utf-8") -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'",
        )

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str = "application/json; charset=utf-8",
        cookie: str | None = None,
    ) -> None:
        self.send_response(status)
        self._headers(content_type)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(
        self,
        status: int,
        body: dict[str, Any],
        cookie: str | None = None,
    ) -> None:
        payload = json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        self._send_bytes(status, payload, cookie=cookie)

    def _error(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _check_host_and_origin(self, require_origin: bool = False) -> bool:
        expected_authority = urlsplit(self.state.config.origin).netloc.lower()
        host = self.headers.get("Host", "").lower()
        if host != expected_authority:
            self._error(HTTPStatus.FORBIDDEN, "Host header is not allowed")
            return False
        origin = self.headers.get("Origin")
        if (require_origin and origin != self.state.config.origin) or (
            origin is not None and origin != self.state.config.origin
        ):
            self._error(HTTPStatus.FORBIDDEN, "Origin is not allowed")
            return False
        return True

    def _request_session(self) -> tuple[str | None, dict[str, Any] | None]:
        cookie_header = self.headers.get("Cookie", "")
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(cookie_header)
        except http.cookies.CookieError:
            return None, None
        morsel = cookie.get(COOKIE_NAME)
        session_id = morsel.value if morsel else None
        return session_id, self.state.get_session(session_id)

    def _authorized_session(self, require_csrf: bool = False) -> tuple[str | None, dict[str, Any] | None]:
        session_id, session = self._request_session()
        if session is None or session.get("stage") != "authenticated":
            self._error(HTTPStatus.UNAUTHORIZED, "Authentication required")
            return None, None
        if require_csrf and not hmac.compare_digest(
            str(session["csrf"]), self.headers.get("X-CSRF-Token", ""),
        ):
            self._error(HTTPStatus.FORBIDDEN, "CSRF verification failed")
            return None, None
        return session_id, session

    def _read_json_body(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length", "")
        if not raw_length.isascii() or not raw_length.isdigit():
            raise ValueError("Content-Length is required")
        content_length = int(raw_length)
        if content_length < 2 or content_length > MAX_REQUEST_BYTES:
            raise ValueError("Request body size is invalid")
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Content-Type must be application/json")
        payload = json.loads(self.rfile.read(content_length))
        if not isinstance(payload, dict):
            raise ValueError("JSON body must be an object")
        return payload

    def _check_rate_limit(self, route: str) -> bool:
        if self.state.allow_request(self.client_address[0], route):
            return True
        self._error(HTTPStatus.TOO_MANY_REQUESTS, "Too many requests")
        return False

    def do_GET(self) -> None:
        if not self._check_host_and_origin():
            return
        if self.path == "/":
            page = REGISTER_HTML if self.state.config.role == "enrollment" else LOGIN_HTML
            self._send_bytes(HTTPStatus.OK, page, "text/html; charset=utf-8")
        elif self.path == "/register" and self.state.config.role == "enrollment":
            self._send_bytes(HTTPStatus.OK, REGISTER_HTML, "text/html; charset=utf-8")
        elif self.path == "/register.js" and self.state.config.role == "enrollment":
            self._send_bytes(HTTPStatus.OK, REGISTER_JS, "text/javascript; charset=utf-8")
        elif self.path == "/app.css":
            self._send_bytes(HTTPStatus.OK, APP_CSS, "text/css; charset=utf-8")
        elif self.path == "/app.js":
            self._send_bytes(
                HTTPStatus.OK,
                APP_JS,
                "text/javascript; charset=utf-8",
            )
        elif self.path == "/api/status":
            if self.state.config.role != "login":
                self._error(HTTPStatus.NOT_FOUND, "Not found")
                return
            _, session = self._authorized_session()
            if session is not None:
                self._send_json(HTTPStatus.OK, self.state.status())
        elif self.path == "/api/session":
            _, session = self._request_session()
            self._send_json(HTTPStatus.OK, {
                "authenticated": bool(session and session.get("stage") == "authenticated"),
                "csrf": session["csrf"] if session else None,
                "stage": session.get("stage", "anonymous") if session else "anonymous",
                "can_enroll": (
                    self.state.config.role == "enrollment"
                    and not self.state.has_credentials()
                ),
            })
        else:
            self._error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        if not self._check_host_and_origin(require_origin=True):
            return
        if not self._check_rate_limit(self.path):
            return
        registration_route = self.path in ("/api/register/options", "/api/register/verify")
        if (self.state.config.role == "enrollment") != registration_route:
            self._error(HTTPStatus.NOT_FOUND, "Not found")
            return
        try:
            payload = self._read_json_body()
            if self.path == "/api/register/options":
                self._registration_options(payload)
            elif self.path == "/api/register/verify":
                self._registration_verify(payload)
            elif self.path == "/api/auth/options":
                self._authentication_options()
            elif self.path == "/api/auth/verify":
                self._authentication_verify(payload)
            elif self.path == "/api/otp/verify":
                self._otp_verify(payload)
            elif self.path == "/api/logout":
                self._logout(payload)
            else:
                self._error(HTTPStatus.NOT_FOUND, "Not found")
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            LOGGER.info("認証リクエストを拒否しました: %s", type(exc).__name__)
            self._error(HTTPStatus.BAD_REQUEST, "Invalid request")
        except Exception as exc:
            LOGGER.error("認証処理に失敗しました: %s", type(exc).__name__)
            self._error(HTTPStatus.UNAUTHORIZED, "Authentication failed")

    def _set_session_cookie(self, session_id: str) -> str:
        return (
            f"{COOKIE_NAME}={session_id}; Path=/; Max-Age={SESSION_LIFETIME_SECONDS}; "
            "Secure; HttpOnly; SameSite=Strict"
        )

    def _registration_options(self, payload: dict[str, Any]) -> None:
        if (
            self.state.config.role != "enrollment"
            or self.state.has_credentials()
            or self.state.config.owner_profile_path.exists()
        ):
            self._error(HTTPStatus.CONFLICT, "Administrator passkey is already registered")
            return
        token = payload.get("bootstrap_token")
        if not isinstance(token, str) or not self.state.validate_bootstrap_token(token):
            self._error(HTTPStatus.FORBIDDEN, "Invalid local enrollment token")
            return
        session_id, session = self.state.new_session()
        options = generate_registration_options(
            rp_id=self.state.config.rp_id,
            rp_name=self.state.config.rp_name,
            user_id=self.state.user_id(),
            user_name=self.state.config.admin_email,
            user_display_name="MK1Ai Administrator",
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=bytes(row["credential_id"]))
                for row in self.state.credential_rows()
            ],
        )
        session.update({
            "stage": "registration",
            "challenge": options.challenge,
            "challenge_expires": time.time() + AUTH_CHALLENGE_SECONDS,
        })
        self._send_json(
            HTTPStatus.OK,
            {"options": json.loads(options_to_json(options)), "csrf": session["csrf"]},
            cookie=self._set_session_cookie(session_id),
        )

    def _registration_verify(self, payload: dict[str, Any]) -> None:
        session_id, session = self._request_session()
        if (
            session_id is None
            or session is None
            or session.get("stage") != "registration"
            or not hmac.compare_digest(session["csrf"], str(payload.get("csrf", "")))
        ):
            self._error(HTTPStatus.FORBIDDEN, "Registration session is invalid")
            return
        if session["challenge_expires"] < time.time():
            self._error(HTTPStatus.GONE, "Registration challenge expired")
            return
        verification = verify_registration_response(
            credential=parse_registration_credential_json(payload["credential"]),
            expected_challenge=session["challenge"],
            expected_origin=self.state.config.origin,
            expected_rp_id=self.state.config.rp_id,
            require_user_verification=True,
        )
        self.state.store_credential(
            verification.credential_id,
            verification.credential_public_key,
            verification.sign_count,
        )
        session.pop("challenge", None)
        session["stage"] = "complete"
        self._send_json(HTTPStatus.OK, {
            "stage": "complete",
            "message": "Passkey registered. Shut down this enrollment service and transfer owner_profile.dat.",
            "csrf": session["csrf"],
        })

    def _authentication_options(self) -> None:
        credentials = self.state.credential_rows()
        if not credentials:
            self._error(HTTPStatus.CONFLICT, "Administrator passkey has not been enrolled")
            return
        session_id, session = self.state.new_session()
        options = generate_authentication_options(
            rp_id=self.state.config.rp_id,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=bytes(row["credential_id"]))
                for row in credentials
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        session.update({
            "stage": "authentication",
            "challenge": options.challenge,
            "challenge_expires": time.time() + AUTH_CHALLENGE_SECONDS,
        })
        self._send_json(
            HTTPStatus.OK,
            {"options": json.loads(options_to_json(options)), "csrf": session["csrf"]},
            cookie=self._set_session_cookie(session_id),
        )

    def _authentication_verify(self, payload: dict[str, Any]) -> None:
        _, session = self._request_session()
        if (
            session is None
            or session.get("stage") != "authentication"
            or not hmac.compare_digest(session["csrf"], str(payload.get("csrf", "")))
        ):
            self._error(HTTPStatus.FORBIDDEN, "Authentication session is invalid")
            return
        if session["challenge_expires"] < time.time():
            self._error(HTTPStatus.GONE, "Authentication challenge expired")
            return
        credential_json = payload["credential"]
        credential = parse_authentication_credential_json(credential_json)
        credential_id = credential.raw_id
        row = next(
            (
                item for item in self.state.credential_rows()
                if hmac.compare_digest(bytes(item["credential_id"]), credential_id)
            ),
            None,
        )
        if row is None:
            raise ValueError("Unknown passkey")
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=session["challenge"],
            expected_origin=self.state.config.origin,
            expected_rp_id=self.state.config.rp_id,
            credential_public_key=bytes(row["public_key"]),
            credential_current_sign_count=int(row["sign_count"]),
            require_user_verification=True,
        )
        self.state.update_sign_count(credential_id, verification.new_sign_count)
        session.pop("challenge", None)
        self.state.issue_otp(session)
        self._send_json(HTTPStatus.OK, {
            "stage": "otp",
            "message": "Passkey verified. Enter both verification codes.",
            "csrf": session["csrf"],
        })

    def _otp_verify(self, payload: dict[str, Any]) -> None:
        _, session = self._request_session()
        if (
            session is None
            or session.get("stage") != "otp"
            or not hmac.compare_digest(session["csrf"], str(payload.get("csrf", "")))
        ):
            self._error(HTTPStatus.FORBIDDEN, "Verification session is invalid")
            return
        if session["otp_expires"] < time.time():
            session["stage"] = "expired"
            self._error(HTTPStatus.GONE, "Verification codes expired")
            return
        session["otp_attempts"] += 1
        if session["otp_attempts"] > OTP_MAX_ATTEMPTS:
            session["stage"] = "locked"
            self._error(HTTPStatus.TOO_MANY_REQUESTS, "Verification session locked")
            return
        email_code = payload.get("email_code")
        sms_code = payload.get("sms_code")
        if not isinstance(email_code, str) or not isinstance(sms_code, str):
            self._error(HTTPStatus.BAD_REQUEST, "Both verification codes are required")
            return
        expected_email = session["email_code_digest"]
        expected_sms = session["sms_code_digest"]
        if not (
            hmac.compare_digest(self.state.code_digest(email_code, "email"), expected_email)
            and hmac.compare_digest(self.state.code_digest(sms_code, "sms"), expected_sms)
        ):
            self._error(HTTPStatus.UNAUTHORIZED, "Verification codes are invalid")
            return
        session["stage"] = "authenticated"
        session["authenticated_at"] = time.time()
        session.pop("email_code_digest", None)
        session.pop("sms_code_digest", None)
        self._send_json(HTTPStatus.OK, {"authenticated": True})

    def _logout(self, payload: dict[str, Any]) -> None:
        session_id, session = self._authorized_session(require_csrf=True)
        if session_id is None or session is None:
            return
        if not hmac.compare_digest(session["csrf"], str(payload.get("csrf", ""))):
            self._error(HTTPStatus.FORBIDDEN, "CSRF verification failed")
            return
        with self.state.lock:
            self.state.sessions.pop(session_id, None)
        cookie = (
            f"{COOKIE_NAME}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
        )
        self._send_json(HTTPStatus.OK, {"logged_out": True}, cookie=cookie)


REGISTER_HTML = Path(__file__).with_name("register.html").read_bytes()
REGISTER_JS = Path(__file__).with_name("register.js").read_bytes()

LOGIN_HTML = """<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>MK1Ai Security Console</title><link rel="stylesheet" href="/app.css"></head>
<body><main class="shell"><header><div class="brand">MK1<span>AI</span></div><span class="secure">TLS / MFA</span></header>
<section id="login" class="card"><p class="eyebrow">SECURITY OPERATIONS</p><h1>MK1Ai Security Console</h1>
<p class="muted">閲覧専用の監視ダッシュボードです。アクセスには登録済みPasskeyとメール・SMSのコードが必要です。</p>
<label id="bootstrap-row" hidden>初回登録トークン<input id="bootstrap-token" autocomplete="off"></label>
<button id="register" class="button secondary" hidden>管理者Passkeyを登録</button>
<button id="authenticate" class="button">Passkeyで認証</button>
<section id="otp" hidden><h2>追加確認</h2><p>登録済みメールとSMSに送信された6桁のコードを両方入力してください。</p>
<label>メールコード<input id="email-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6"></label>
<label>SMSコード<input id="sms-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6"></label>
<button id="verify-otp" class="button">確認</button></section><p id="login-message" role="status"></p></section>
<section id="dashboard" hidden><div class="title-row"><div><p class="eyebrow">LIVE MONITORING</p><h1>セキュリティ状況</h1></div>
<button id="logout" class="button secondary">ログアウト</button></div>
<div id="alert-banner" class="alert" hidden></div><div class="grid">
<article class="metric"><span>監視状態</span><strong id="state">—</strong></article>
<article class="metric"><span>処理パケット / 秒</span><strong id="pps">—</strong></article>
<article class="metric"><span>累計パケット</span><strong id="packets">—</strong></article>
<article class="metric"><span>脅威スコア</span><strong id="threat">—</strong></article>
<article class="metric"><span>バックドアリスク</span><strong id="backdoor">—</strong></article>
<article class="metric"><span>モード</span><strong id="mode">—</strong></article>
<article class="metric"><span>モデル同期</span><strong id="model">—</strong></article>
<article class="metric"><span>RSI接続</span><strong id="rsi">—</strong></article>
<article class="metric"><span>学習キュー</span><strong id="training">—</strong></article>
<article class="metric"><span>監視NIC</span><strong id="interface">—</strong></article>
<article class="metric"><span>RAM使用量 / 基準</span><strong id="ram">—</strong></article>
<article class="metric"><span>退避swap</span><strong id="swap">—</strong></article>
</div><p class="muted foot">最終更新: <time id="sampled">—</time> · リモート画面は参照のみ。遮断・停止・コマンド実行はできません。</p></section>
<footer>MK1Ai · Read-only remote console</footer></main><script src="/app.js" defer></script></body></html>""".encode("utf-8")

APP_CSS = b"""*{box-sizing:border-box}body{margin:0;background:#0b1220;color:#e8edf7;font:16px system-ui,-apple-system,sans-serif}.shell{max-width:1120px;margin:auto;padding:24px}header,.title-row{display:flex;align-items:center;justify-content:space-between;margin:12px 0 28px}.brand{font-size:22px;font-weight:800;letter-spacing:.12em}.brand span{color:#55d6be}.secure,.eyebrow{color:#55d6be;font-size:12px;font-weight:700;letter-spacing:.14em}.card,.metric{background:#131e30;border:1px solid #26364f;border-radius:14px;padding:24px}.card{max-width:520px;margin:8vh auto}.metric{display:flex;flex-direction:column;gap:14px;min-height:112px}.metric span,.muted{color:#aab7cc}.metric strong{font-size:23px;overflow-wrap:anywhere}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}h1{font-size:clamp(26px,4vw,38px);margin:6px 0 18px}h2{font-size:20px}label{display:block;margin:18px 0;color:#c9d5e8}input{display:block;width:100%;margin-top:8px;padding:12px;border-radius:8px;border:1px solid #40516c;background:#0b1220;color:#fff;font-size:18px}.button{background:#42cdb5;border:0;border-radius:8px;padding:12px 18px;font-weight:700;cursor:pointer;color:#071712}.button.secondary{background:#26364f;color:#e8edf7}.alert{padding:18px;margin:0 0 18px;background:#592b23;border:1px solid #f08159;border-radius:10px;font-weight:700}.foot{margin-top:20px}footer{text-align:center;color:#74849e;padding:32px}#login-message{min-height:24px;color:#ffb191}@media(max-width:600px){.shell{padding:16px}.card{padding:20px}.title-row{align-items:flex-start;gap:12px}}"""

APP_JS = """const byId=id=>document.getElementById(id);let csrf=null;
async function api(path,data){const response=await fetch(path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf||''},body:JSON.stringify(data||{})});const value=await response.json();if(!response.ok)throw new Error(value.error||'Request failed');return value}
function decode64(value){const text=value.replace(/-/g,'+').replace(/_/g,'/');const binary=atob(text+'='.repeat((4-text.length%4)%4));return Uint8Array.from(binary,c=>c.charCodeAt(0))}
function encode64(value){return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')}
function prepareOptions(options){for(const key of ['challenge'])if(options[key])options[key]=decode64(options[key]);if(options.user&&options.user.id)options.user.id=decode64(options.user.id);for(const key of ['allowCredentials','excludeCredentials'])if(options[key])options[key]=options[key].map(item=>({...item,id:decode64(item.id)}));return options}
function serializeCredential(credential){const result={id:credential.id,rawId:encode64(credential.rawId),type:credential.type,response:{}};for(const key of ['clientDataJSON','authenticatorData','signature','userHandle','attestationObject'])if(credential.response[key])result.response[key]=encode64(credential.response[key]);if(credential.response.getTransports)result.response.transports=credential.response.getTransports();result.clientExtensionResults=credential.getClientExtensionResults();if(credential.authenticatorAttachment)result.authenticatorAttachment=credential.authenticatorAttachment;return result}
async function refreshSession(){const response=await fetch('/api/session',{credentials:'same-origin'});const session=await response.json();csrf=session.csrf;if(session.authenticated){byId('login').hidden=true;byId('dashboard').hidden=false;refreshStatus();setInterval(refreshStatus,3000)}}
async function refreshStatus(){try{const response=await fetch('/api/status',{credentials:'same-origin'});if(response.status===401){location.reload();return}const value=await response.json();for(const [id,key] of [['state','state'],['pps','packets_per_second'],['packets','packets_total'],['threat','threat_score'],['backdoor','backdoor_score'],['mode','mode'],['model','model_sync_status'],['rsi','rsi_connection_status'],['training','training_queue_batches'],['interface','interface']])byId(id).textContent=value[key]??'—';byId('ram').textContent=value.ram_used_mb!==undefined?`${value.ram_used_mb} MB / ${value.ram_limit_mb} MB`:'—';byId('swap').textContent=value.swap_used_mb!==undefined?`${value.swap_used_mb} MB`:'—';const alert=byId('alert-banner');alert.hidden=!value.alert||value.alert==='NONE';alert.textContent=alert.hidden?'':`警告: ${value.alert} · 隔離状態: ${value.isolation_active?'発動':'未発動'} · Dry-Run: ${value.dry_run?'有効':'無効'}`;byId('sampled').textContent=new Date(value.sampled_at*1000).toLocaleString()}catch(error){byId('login-message').textContent='状態を取得できません。'} }
async function startAuthentication(){byId('login-message').textContent='';try{const result=await api('/api/auth/options',{});csrf=result.csrf;const credential=await navigator.credentials.get({publicKey:prepareOptions(result.options)});const verified=await api('/api/auth/verify',{csrf,credential:serializeCredential(credential)});csrf=verified.csrf||csrf;byId('otp').hidden=false;byId('authenticate').hidden=true;byId('login-message').textContent=verified.message}catch(error){byId('login-message').textContent=error.message}}
async function registerPasskey(){byId('login-message').textContent='';try{const result=await api('/api/register/options',{bootstrap_token:byId('bootstrap-token').value});csrf=result.csrf;const credential=await navigator.credentials.create({publicKey:prepareOptions(result.options)});const verified=await api('/api/register/verify',{csrf,credential:serializeCredential(credential)});csrf=verified.csrf;byId('otp').hidden=false;byId('register').hidden=true;byId('login-message').textContent=verified.message}catch(error){byId('login-message').textContent=error.message}}
byId('authenticate').addEventListener('click',startAuthentication);byId('register').addEventListener('click',registerPasskey);
byId('verify-otp').addEventListener('click',async()=>{try{await api('/api/otp/verify',{csrf,email_code:byId('email-code').value,sms_code:byId('sms-code').value});location.reload()}catch(error){byId('login-message').textContent=error.message}});
byId('logout').addEventListener('click',async()=>{try{await api('/api/logout',{csrf});location.reload()}catch(error){byId('login-message').textContent=error.message}});
if(!window.PublicKeyCredential){byId('authenticate').disabled=true;byId('login-message').textContent='このブラウザーはPasskeyに対応していません。'}
fetch('/api/session',{credentials:'same-origin'}).then(r=>r.json()).then(session=>{csrf=session.csrf;if(session.stage==='otp'){byId('otp').hidden=false;byId('authenticate').hidden=true;byId('register').hidden=true}else if(session.stage==='anonymous'&&session.can_enroll){byId('bootstrap-row').hidden=false;byId('register').hidden=false}else if(session.stage==='anonymous'){byId('register').hidden=true}if(session.authenticated){byId('login').hidden=true;byId('dashboard').hidden=false;refreshStatus();setInterval(refreshStatus,3000)}}).catch(()=>{});""".encode("utf-8")


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    try:
        config = DashboardConfig.from_environment()
        server = RemoteDashboardServer(config)
    except (OSError, ValueError, sqlite3.Error) as exc:
        LOGGER.error("HTTPSダッシュボードを起動できません: %s", exc)
        return 2
    if server.dashboard_state.bootstrap_token:
        print(
            "初回Passkey登録トークンはローカル端末の "
            f"{config.bootstrap_path} にのみ保存しました。",
            file=sys.stderr,
        )
    print(f"MK1Ai read-only dashboard: {config.origin}", file=sys.stderr)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        LOGGER.info("ダッシュボードを停止します")
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
