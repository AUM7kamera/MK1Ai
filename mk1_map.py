"""Asynchronous, loopback-only threat-map event delivery."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import logging
import os
import queue
import re
import select
import socket
import threading
import time
from collections.abc import Iterable
from enum import IntEnum
from pathlib import Path
from typing import Any


LOGGER = logging.getLogger("mk1.map")
MAP_QUEUE_CAPACITY = 256
MAX_LOCAL_CACHE_BYTES = 5 * 1024 * 1024
MAX_CLIENTS = 8
MAX_HANDSHAKE_BYTES = 8192
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
EXTENSION_ORIGIN_PATTERN = re.compile(r"chrome-extension://[A-Za-z0-9_-]{8,64}")


class MapMode(IntEnum):
    OFF = 0
    CHROME = 1
    LOCAL = 2


def build_threat_map_event(
    ip_address: str,
    *,
    reason: str,
    threat_score: float,
    timestamp_us: int | None = None,
) -> dict[str, Any] | None:
    """Build a privacy-preserving event; non-global addresses have no map point."""
    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        return None
    if not address.is_global:
        return None
    if not isinstance(reason, str) or not reason or len(reason) > 64:
        return None
    if isinstance(threat_score, bool) or not isinstance(threat_score, (int, float)):
        return None
    if not 0.0 <= threat_score <= 1.0:
        return None
    if timestamp_us is None:
        timestamp_us = time.time_ns() // 1000
    if isinstance(timestamp_us, bool) or not isinstance(timestamp_us, int) or timestamp_us < 0:
        return None

    return {
        "ip_address": str(address),
        "location": {
            "country_code": "",
            "region_name": "",
            "city_name": "",
            "latitude": None,
            "longitude": None,
        },
        "estimated_dist": None,
        "os_type": "unknown",
        "timestamp_us": timestamp_us,
        "reason": reason,
        "threat_score": round(float(threat_score), 4),
    }


def _websocket_frame(payload: bytes) -> bytes:
    length = len(payload)
    if length < 126:
        return b"\x81" + bytes((length,)) + payload
    if length < 65536:
        return b"\x81\x7e" + length.to_bytes(2, "big") + payload
    return b"\x81\x7f" + length.to_bytes(8, "big") + payload


def _read_handshake(client: socket.socket) -> bytes:
    request = bytearray()
    client.settimeout(1.0)
    while b"\r\n\r\n" not in request and len(request) < MAX_HANDSHAKE_BYTES:
        chunk = client.recv(1024)
        if not chunk:
            return b""
        request.extend(chunk)
    return bytes(request)


def _accept_websocket(
    client: socket.socket,
    expected_host: str,
    allowed_origins: frozenset[str] = frozenset(),
) -> bool:
    try:
        request = _read_handshake(client)
        lines = request.decode("latin-1").split("\r\n")
        if not lines or lines[0] != "GET /map HTTP/1.1":
            return False
        headers = {}
        for line in lines[1:]:
            if not line:
                break
            if ":" not in line:
                return False
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
        origin = headers.get("origin", "")
        key = headers.get("sec-websocket-key", "")
        try:
            decoded_key = base64.b64decode(key, validate=True)
        except (ValueError, binascii.Error):
            return False
        if (
            headers.get("upgrade", "").lower() != "websocket"
            or "upgrade" not in headers.get("connection", "").lower()
            or headers.get("host", "").lower() != expected_host.lower()
            or headers.get("sec-websocket-version") != "13"
            or len(decoded_key) != 16
            or not EXTENSION_ORIGIN_PATTERN.fullmatch(origin)
            or (allowed_origins and origin not in allowed_origins)
        ):
            return False
        accept = base64.b64encode(
            hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()  # nosec B303,B324 - RFC6455 Sec-WebSocket-Accept 規定のSHA-1
        ).decode("ascii")
        client.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode("ascii")
        )
        client.setblocking(False)
        return True
    except (OSError, UnicodeError):
        return False


class MapVisualizationService:
    """Runs no map worker in OFF mode and bounds producer-side work and memory."""

    def __init__(
        self,
        local_directory: str | Path,
        host: str = "127.0.0.1",
        port: int = 9001,
        allowed_origins: Iterable[str] | None = None,
    ) -> None:
        if host != "127.0.0.1":
            raise ValueError("Map WebSocket must bind to 127.0.0.1")
        if allowed_origins is None:
            allowed_origins = [
                item.strip()
                for item in os.environ.get("MK1_MAP_EXTENSION_ORIGIN", "").split(",")
                if item.strip()
            ]
        self.allowed_origins = frozenset(allowed_origins)
        if not all(EXTENSION_ORIGIN_PATTERN.fullmatch(item) for item in self.allowed_origins):
            raise ValueError("Map extension origin must look like chrome-extension://<id>")
        if not self.allowed_origins:
            LOGGER.warning(
                "MK1_MAP_EXTENSION_ORIGIN is not set; any local Chrome extension may "
                "connect to the loopback map socket",
            )
        if not 0 <= port <= 65535:
            raise ValueError("Map WebSocket port is invalid")
        self.local_directory = Path(local_directory)
        self.host = host
        self.port = port
        self.mode = MapMode.OFF
        self._events: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=MAP_QUEUE_CAPACITY)
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None
        self._listener: socket.socket | None = None
        self._address: tuple[str, int] | None = None
        self._dropped_events = 0
        self._reported_dropped_events = 0

    @property
    def address(self) -> tuple[str, int] | None:
        return self._address

    @property
    def dropped_events(self) -> int:
        return self._dropped_events

    def set_mode(self, mode: MapMode | int) -> None:
        if isinstance(mode, bool):
            raise ValueError("Map mode must be OFF (0), CHROME (1), or LOCAL (2)")
        try:
            requested = MapMode(mode)
        except ValueError as exc:
            raise ValueError("Map mode must be OFF (0), CHROME (1), or LOCAL (2)") from exc
        if requested == self.mode:
            return
        self.stop()
        self.mode = requested
        if requested == MapMode.OFF:
            return
        if requested == MapMode.CHROME:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((self.host, self.port))
                listener.listen(MAX_CLIENTS)
                listener.settimeout(0.1)
            except OSError:
                listener.close()
                self.mode = MapMode.OFF
                raise
            self._listener = listener
            self._address = listener.getsockname()
        self._stop_event.clear()
        target = self._run_chrome if requested == MapMode.CHROME else self._run_local
        self._worker = threading.Thread(target=target, name="mk1-map", daemon=True)
        self._worker.start()

    def publish(self, event: dict[str, Any]) -> bool:
        if self.mode == MapMode.OFF:
            return False
        try:
            self._events.put_nowait(event)
        except queue.Full:
            self._dropped_events += 1
            return False
        return True

    def stop(self) -> None:
        self._stop_event.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            listener.close()
        worker, self._worker = self._worker, None
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=2.0)
            if worker.is_alive():
                raise RuntimeError("Map visualization worker did not stop")
        self._address = None
        while True:
            try:
                self._events.get_nowait()
            except queue.Empty:
                break

    def close(self) -> None:
        self.stop()
        self.mode = MapMode.OFF

    def _next_event(self) -> dict[str, Any] | None:
        try:
            return self._events.get(timeout=0.05)
        except queue.Empty:
            return None

    def _run_local(self) -> None:
        descriptor = -1
        try:
            self.local_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            events_path = self.local_directory / "map-events.jsonl"
            descriptor = os.open(
                events_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600,
            )
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "a", encoding="utf-8") as output:
                descriptor = -1
                while not self._stop_event.is_set():
                    event = self._next_event()
                    if event is not None:
                        if output.tell() >= MAX_LOCAL_CACHE_BYTES:
                            output.seek(0)
                            output.truncate()
                        serialized = self._serialize_event(event)
                        if serialized is not None:
                            output.write(serialized + "\n")
                            output.flush()
                    self._report_dropped_events()
        except OSError:
            LOGGER.exception("Local map event cache could not be written")
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _run_chrome(self) -> None:
        listener = self._listener
        address = self._address
        if listener is None or address is None:
            return
        expected_host = f"{self.host}:{address[1]}"
        clients: set[socket.socket] = set()
        try:
            while not self._stop_event.is_set():
                event = self._next_event()
                if event is not None:
                    serialized = self._serialize_event(event)
                    if serialized is not None:
                        frame = _websocket_frame(serialized.encode("utf-8"))
                        for client in tuple(clients):
                            try:
                                if client.send(frame) != len(frame):
                                    raise BlockingIOError("WebSocket client is not keeping up")
                            except OSError:
                                clients.discard(client)
                                client.close()
                self._report_dropped_events()
                try:
                    readable, _, _ = select.select(
                        [listener, *clients], [], [], 0.05,
                    )
                except (OSError, ValueError):
                    if self._stop_event.is_set():
                        break
                    raise
                for ready in readable:
                    if ready is listener:
                        try:
                            client, _ = listener.accept()
                        except OSError:
                            if self._stop_event.is_set():
                                break
                            raise
                        if len(clients) >= MAX_CLIENTS or not _accept_websocket(
                            client, expected_host, self.allowed_origins,
                        ):
                            client.close()
                        else:
                            clients.add(client)
                    else:
                        try:
                            incoming = ready.recv(4096)
                        except OSError:
                            incoming = b""
                        if not incoming or (incoming[0] & 0x0F) == 0x8:
                            clients.discard(ready)
                            ready.close()
        except OSError:
            LOGGER.exception("Map WebSocket server stopped after an I/O error")
        finally:
            for client in clients:
                client.close()

    def _report_dropped_events(self) -> None:
        dropped = self._dropped_events
        if dropped > self._reported_dropped_events:
            LOGGER.warning(
                "Map event queue overflow dropped %d event(s)",
                dropped - self._reported_dropped_events,
            )
            self._reported_dropped_events = dropped

    @staticmethod
    def _serialize_event(event: dict[str, Any]) -> str | None:
        try:
            return json.dumps(
                event, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
            )
        except (TypeError, ValueError):
            LOGGER.warning("Discarded an invalid map event")
            return None
