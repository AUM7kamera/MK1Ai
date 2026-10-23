#!/usr/bin/env python3
"""Measure local MK1Ai components without implying network throughput."""

from __future__ import annotations

import argparse
import hashlib
import hashlib
import hmac
import importlib.metadata
import json
import logging
import os
import platform
import resource
import socket
import socketserver
import struct
import sys
import tempfile
import time
import logging
from pathlib import Path
from typing import Callable
from threading import Barrier, Event, Lock, Thread

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem.ml_kem_768 import CIPHERTEXT_SIZE, PUBLIC_KEY_SIZE, decaps, encaps, keygen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import airgap_ai_defender as defender


DEFAULT_FRAME_SIZES = (64, 128, 256, 512, 1024, 1518)
DEFAULT_CONNECTION_COUNTS = (1, 8, 32)
LATENCY_SAMPLE_COUNT = 250
LOOPBACK_LATENCY_SAMPLE_LIMIT = 250
RESOURCE_SAMPLE_INTERVAL_SECONDS = 0.01


def current_process_rss_bytes() -> int:
    if platform.system() != "Linux":
        raise RuntimeError("per-scenario RSS sampling currently requires Linux")
    for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    raise RuntimeError("/proc/self/status did not report VmRSS")


def percentiles(samples_us: list[float]) -> dict[str, float]:
    ordered = sorted(samples_us)

    def percentile(fraction: float) -> float:
        position = (len(ordered) - 1) * fraction
        lower = int(position)
        upper = min(lower + 1, len(ordered) - 1)
        weight = position - lower
        return ordered[lower] * (1.0 - weight) + ordered[upper] * weight

    return {
        "mean_us": sum(ordered) / len(ordered),
        "p95_us": percentile(0.95),
        "p99_us": percentile(0.99),
        "samples": len(ordered),
    }


def measure(
    operation: Callable[[], None],
    duration_seconds: float,
    *,
    input_bytes_per_operation: int = 0,
) -> dict[str, object]:
    started = time.perf_counter()
    cpu_started = time.process_time()
    operations = 0
    while time.perf_counter() - started < duration_seconds:
        operation()
        operations += 1
    elapsed = time.perf_counter() - started
    cpu_seconds = time.process_time() - cpu_started

    samples_us: list[float] = []
    for _ in range(LATENCY_SAMPLE_COUNT):
        sample_started = time.perf_counter_ns()
        operation()
        samples_us.append((time.perf_counter_ns() - sample_started) / 1000.0)

    byte_rate = operations * input_bytes_per_operation / elapsed
    return {
        "operations": operations,
        "elapsed_seconds": elapsed,
        "operations_per_second": operations / elapsed,
        "input_bytes_per_second": byte_rate,
        "input_gbps": byte_rate * 8 / 1_000_000_000,
        "cpu_percent_of_one_core": cpu_seconds / elapsed * 100.0,
        "latency": percentiles(samples_us),
        "latency_excluded_from_rate_measurement": True,
    }


def build_tcp_frame(frame_bytes: int, identification: int = 1) -> bytes:
    if frame_bytes < 54 or frame_bytes > 65_549:
        raise ValueError("frame size must fit an Ethernet/IPv4/TCP frame")
    payload = b"A" * (frame_bytes - 54)
    source_ip = socket.inet_aton("192.0.2.10")
    destination_ip = socket.inet_aton("198.51.100.20")
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40 + len(payload),
        identification & 0xFFFF,
        0x4000,
        64,
        socket.IPPROTO_TCP,
        0,
        source_ip,
        destination_ip,
    )
    tcp_header = struct.pack(
        "!HHIIHHHH",
        40000 + (identification % 20000),
        443,
        identification,
        0,
        (5 << 12) | 0x10,
        64240,
        0,
        0,
    )
    frame = b"\x00" * 12 + b"\x08\x00" + ip_header + tcp_header + payload
    if len(frame) != frame_bytes:
        raise AssertionError("synthetic frame builder returned an incorrect length")
    return frame


def benchmark_aes_gcm(frame_bytes: int, duration_seconds: float) -> dict[str, object]:
    key = AESGCM.generate_key(bit_length=256)
    cipher = AESGCM(key)
    plaintext = b"x" * frame_bytes
    aad = b"MK1Ai local component benchmark v1"
    last_envelope: tuple[bytes, bytes] | None = None

    def encrypt() -> None:
        nonlocal last_envelope
        nonce = os.urandom(12)
        last_envelope = (nonce, cipher.encrypt(nonce, plaintext, aad))

    encrypt()
    if last_envelope is None:
        raise RuntimeError("AES-GCM encryption did not produce an envelope")
    valid_nonce, valid_ciphertext = last_envelope

    def decrypt_and_authenticate() -> None:
        recovered = cipher.decrypt(valid_nonce, valid_ciphertext, aad)
        if recovered != plaintext:
            raise RuntimeError("AES-GCM round trip returned different plaintext")

    tampered = bytearray(valid_ciphertext)
    tampered[-1] ^= 1
    try:
        cipher.decrypt(valid_nonce, bytes(tampered), aad)
    except InvalidTag:
        tamper_rejected = True
    else:
        raise RuntimeError("AES-GCM accepted a tampered authentication tag")

    return {
        "payload_bytes": frame_bytes,
        "ciphertext_bytes_including_tag": len(valid_ciphertext),
        "authentication_tag_tamper_rejected": tamper_rejected,
        "encrypt": measure(
            encrypt, duration_seconds, input_bytes_per_operation=frame_bytes,
        ),
        "decrypt_with_tag_verification": measure(
            decrypt_and_authenticate,
            duration_seconds,
            input_bytes_per_operation=frame_bytes,
        ),
    }


def benchmark_pqc(duration_seconds: float) -> dict[str, object]:
    public_key, private_key = keygen()

    def exchange_and_verify() -> None:
        ciphertext, sender_secret = encaps(public_key)
        receiver_secret = decaps(private_key, ciphertext)
        if sender_secret != receiver_secret:
            raise RuntimeError("ML-KEM encapsulation/decapsulation mismatch")

    result = measure(exchange_and_verify, duration_seconds)
    result["shared_secret_match_verified"] = True
    result["keypair_generation_included"] = False
    result["remote_key_pin_and_user_authentication_included"] = False
    return result


def benchmark_packet_pipeline(
    frame_bytes: int,
    duration_seconds: float,
    *,
    model: object | None,
) -> dict[str, object]:
    frames = [build_tcp_frame(frame_bytes, index) for index in range(512)]
    next_frame = 0

    def inspect() -> None:
        nonlocal next_frame
        frame = frames[next_frame]
        next_frame = (next_frame + 1) % len(frames)
        payload = frame[54:]
        dpi_result = defender.analyze_dpi_payload(b"", payload=payload)
        defender.inspect_packet_pipeline(
            frame, "component-benchmark", model=model, dry_run=True,
            dpi_result=dpi_result,
        )

    return measure(
        inspect, duration_seconds, input_bytes_per_operation=frame_bytes,
    )


def benchmark_inspection_logging(
    frame_bytes: int,
    duration_seconds: float,
) -> dict[str, object]:
    frame = build_tcp_frame(frame_bytes)
    dpi_result = {
        "entropy": 0.0,
        "attack_signatures": [],
        "protocols": [],
        "findings": [],
    }
    previous_flag = defender.FULL_PACKET_INSPECTION
    previous_log_level = defender.log.level

    try:
        with tempfile.TemporaryDirectory(prefix="mk1-throughput-log-") as directory:
            log_path = Path(directory) / "synthetic-inspection.jsonl"
            defender.FULL_PACKET_INSPECTION = True
            defender.log.setLevel(logging.CRITICAL)

            def write_inspection_record() -> None:
                defender.log_full_packet_inspection(
                    frame,
                    "component-benchmark",
                    dpi_result,
                    stage="benchmark",
                    reason="synthetic_forced_full_inspection",
                    log_path=str(log_path),
                )

            result = measure(
                write_inspection_record,
                duration_seconds,
                input_bytes_per_operation=frame_bytes,
            )
            file_bytes = log_path.stat().st_size
            written_records = result["operations"] + LATENCY_SAMPLE_COUNT
            if file_bytes == 0 or written_records <= 0:
                raise RuntimeError("Full inspection logging produced no records")
            record_bytes = file_bytes / written_records
            result["inspection_records_including_latency_samples"] = written_records
            result["log_file_bytes_including_latency_samples"] = file_bytes
            result["average_log_record_bytes"] = record_bytes
            result["timed_log_bytes_per_second"] = (
                record_bytes * result["operations"] / result["elapsed_seconds"]
            )
            result["file_flush_or_fsync"] = False
            result["logger_warning_output_suppressed"] = True
            result["temporary_synthetic_log_removed"] = True
            return result
    finally:
        defender.FULL_PACKET_INSPECTION = previous_flag
        defender.log.setLevel(previous_log_level)


def _recv_exact(connection: socket.socket, length: int) -> bytes:
    parts = bytearray()
    while len(parts) < length:
        chunk = connection.recv(length - len(parts))
        if not chunk:
            raise EOFError("loopback benchmark connection closed mid-record")
        parts.extend(chunk)
    return bytes(parts)


def _recv_record_length(connection: socket.socket) -> int | None:
    prefix = bytearray()
    while len(prefix) < 4:
        chunk = connection.recv(4 - len(prefix))
        if not chunk:
            if not prefix:
                return None
            raise EOFError("loopback benchmark closed mid-record length")
        prefix.extend(chunk)
    return struct.unpack("!I", prefix)[0]


def _record_nonce(session_id: int, direction: int, sequence: int) -> bytes:
    return struct.pack("!III", session_id, direction, sequence)


def _record_aad(header: bytes, direction: int) -> bytes:
    return b"MK1 loopback diagnostic v1\0" + bytes((direction,)) + header


def benchmark_loopback_transport(
    payload_bytes: int,
    connection_count: int,
    duration_seconds: float,
    *,
    model: object | None = None,
    include_secure_pipeline: bool = False,
) -> dict[str, object]:
    key = AESGCM.generate_key(bit_length=256)
    server_cipher = AESGCM(key)
    payload = build_tcp_frame(payload_bytes)
    auth_token = os.urandom(32) if include_secure_pipeline else b""
    kem_public_key: bytes | None = None
    kem_private_key: bytes | None = None
    expected_server_key_pin: str | None = None
    if include_secure_pipeline:
        kem_public_key, kem_private_key = keygen()
        expected_server_key_pin = hashlib.sha256(kem_public_key).hexdigest()
    log_directory = tempfile.TemporaryDirectory(
        prefix="mk1-throughput-secure-",
    ) if include_secure_pipeline else None
    log_path = (
        Path(log_directory.name) / "authenticated-inspection.jsonl"
        if log_directory is not None else None
    )
    previous_inspection_flag = defender.FULL_PACKET_INSPECTION
    previous_log_level = defender.log.level
    if include_secure_pipeline:
        defender.FULL_PACKET_INSPECTION = True
        defender.log.setLevel(logging.CRITICAL)
    state_lock = Lock()
    seen_sessions: set[int] = set()
    authenticated_requests = 0
    request_failures = 0
    inspection_records = 0
    pqc_handshakes = 0
    handshake_durations_us: list[float] = []
    server_errors: list[str] = []
    client_errors: list[str] = []

    def derive_session_cipher(shared_secret: bytes, ciphertext: bytes) -> AESGCM:
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(
                b"MK1 diagnostic ML-KEM loopback session v1\0" + ciphertext,
            ).digest(),
            info=b"MK1 benchmark-only AES-256-GCM key",
        ).derive(shared_secret)
        return AESGCM(session_key)

    class LoopbackHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            nonlocal authenticated_requests, request_failures
            nonlocal inspection_records, pqc_handshakes
            session_id = None
            expected_sequence = 0
            try:
                session_cipher = server_cipher
                if include_secure_pipeline:
                    if kem_public_key is None or kem_private_key is None:
                        raise RuntimeError("ML-KEM server keypair is unavailable")
                    started = time.perf_counter_ns()
                    self.request.sendall(
                        struct.pack("!I", len(kem_public_key)) + kem_public_key,
                    )
                    ciphertext_length = struct.unpack(
                        "!I", _recv_exact(self.request, 4),
                    )[0]
                    if ciphertext_length != CIPHERTEXT_SIZE:
                        raise ValueError("ML-KEM ciphertext length is invalid")
                    kem_ciphertext = _recv_exact(self.request, ciphertext_length)
                    shared_secret = decaps(kem_private_key, kem_ciphertext)
                    session_cipher = derive_session_cipher(
                        shared_secret, kem_ciphertext,
                    )
                    del shared_secret
                    with state_lock:
                        pqc_handshakes += 1
                        handshake_durations_us.append(
                            (time.perf_counter_ns() - started) / 1000.0,
                        )
                while True:
                    length = _recv_record_length(self.request)
                    if length is None:
                        return
                    plaintext_length = payload_bytes + len(auth_token)
                    if length != 8 + 12 + plaintext_length + 16:
                        raise ValueError(f"invalid loopback record length: {length}")
                    header = _recv_exact(self.request, 8)
                    record_session, sequence = struct.unpack("!II", header)
                    nonce = _recv_exact(self.request, 12)
                    ciphertext = _recv_exact(self.request, plaintext_length + 16)
                    if nonce != _record_nonce(record_session, 0, sequence):
                        raise ValueError("client record nonce is invalid")
                    if session_id is None:
                        session_id = record_session
                        if session_id >= connection_count:
                            raise ValueError("loopback session id is outside the configured range")
                        with state_lock:
                            if session_id in seen_sessions:
                                raise ValueError("duplicate loopback session id")
                            seen_sessions.add(session_id)
                    elif record_session != session_id:
                        raise ValueError("loopback session id changed on an established connection")
                    if sequence != expected_sequence:
                        raise ValueError("loopback record was replayed or arrived out of order")
                    plaintext = session_cipher.decrypt(
                        nonce, ciphertext, _record_aad(header, 0),
                    )
                    request_frame = payload
                    if include_secure_pipeline:
                        received_token = plaintext[:len(auth_token)]
                        request_frame = plaintext[len(auth_token):]
                        if not hmac.compare_digest(received_token, auth_token):
                            raise ValueError("synthetic API-token authentication failed")
                        if request_frame != payload:
                            raise ValueError("loopback request frame did not match")
                        dpi_result = defender.analyze_dpi_payload(
                            request_frame, interface="component-benchmark",
                        )
                        pipeline_result = defender.inspect_packet_pipeline(
                            request_frame,
                            "component-benchmark",
                            model=model,
                            dry_run=True,
                            dpi_result=dpi_result,
                        )
                        if pipeline_result.get("block"):
                            raise ValueError(
                                "synthetic benign frame was rejected by the inspection pipeline",
                            )
                        if log_path is None:
                            raise RuntimeError("synthetic inspection log path is unavailable")
                        with state_lock:
                            defender.log_full_packet_inspection(
                                request_frame,
                                "component-benchmark",
                                dpi_result,
                                stage="benchmark",
                                reason="authenticated_synthetic_full_inspection",
                                log_path=str(log_path),
                            )
                            inspection_records += 1
                    elif plaintext != payload:
                        raise ValueError("loopback request plaintext did not match")
                    with state_lock:
                        authenticated_requests += 1
                    response_header = header
                    response_nonce = _record_nonce(session_id, 1, sequence)
                    response_ciphertext = session_cipher.encrypt(
                        response_nonce,
                        request_frame,
                        _record_aad(response_header, 1),
                    )
                    response_body = response_header + response_nonce + response_ciphertext
                    self.request.sendall(struct.pack("!I", len(response_body)) + response_body)
                    expected_sequence += 1
            except (OSError, EOFError, ValueError, InvalidTag, RuntimeError) as exc:
                with state_lock:
                    request_failures += 1
                    server_errors.append(f"{type(exc).__name__}: {exc}")

    class LoopbackServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
        block_on_close = False

    server: LoopbackServer | None = None
    server_thread: Thread | None = None
    connections: list[socket.socket] = []
    clients_ready = Barrier(connection_count + 1)
    client_threads: list[Thread] = []
    client_stats: list[dict[str, object]] = [
        {"responses": 0, "samples_us": []}
        for _ in range(connection_count)
    ]
    resource_monitor_stop = Event()
    resource_monitor_thread: Thread | None = None
    rss_samples: list[int] = []
    resource_sampling_errors: list[str] = []
    process_cpu_seconds = 0.0
    deadline = 0.0

    def client_worker(session_id: int, connection: socket.socket) -> None:
        cipher = AESGCM(key)
        stats = client_stats[session_id]
        sequence = 0
        try:
            clients_ready.wait(timeout=10)
            if include_secure_pipeline:
                if expected_server_key_pin is None:
                    raise RuntimeError("expected ML-KEM public-key pin is unavailable")
                public_key_length = struct.unpack(
                    "!I", _recv_exact(connection, 4),
                )[0]
                if public_key_length != PUBLIC_KEY_SIZE:
                    raise ValueError("ML-KEM public-key length is invalid")
                public_key = _recv_exact(connection, public_key_length)
                public_key_pin = hashlib.sha256(public_key).hexdigest()
                if not hmac.compare_digest(public_key_pin, expected_server_key_pin):
                    raise ValueError("synthetic ML-KEM public-key pin did not match")
                kem_ciphertext, shared_secret = encaps(public_key)
                connection.sendall(
                    struct.pack("!I", len(kem_ciphertext)) + kem_ciphertext,
                )
                cipher = derive_session_cipher(shared_secret, kem_ciphertext)
                del shared_secret
            while time.perf_counter() < deadline:
                header = struct.pack("!II", session_id, sequence)
                nonce = _record_nonce(session_id, 0, sequence)
                request_plaintext = (
                    auth_token + payload if include_secure_pipeline else payload
                )
                ciphertext = cipher.encrypt(
                    nonce, request_plaintext, _record_aad(header, 0),
                )
                body = header + nonce + ciphertext
                operation_started = time.perf_counter_ns()
                connection.sendall(struct.pack("!I", len(body)) + body)
                response_length = struct.unpack("!I", _recv_exact(connection, 4))[0]
                if response_length != 8 + 12 + payload_bytes + 16:
                    raise ValueError("loopback response length is invalid")
                response_header = _recv_exact(connection, 8)
                response_session, response_sequence = struct.unpack("!II", response_header)
                response_nonce = _recv_exact(connection, 12)
                response_ciphertext = _recv_exact(
                    connection, payload_bytes + 16,
                )
                if (
                    response_session != session_id
                    or response_sequence != sequence
                    or response_nonce != _record_nonce(session_id, 1, sequence)
                ):
                    raise ValueError("loopback response session, sequence, or nonce is invalid")
                response_plaintext = cipher.decrypt(
                    response_nonce,
                    response_ciphertext,
                    _record_aad(response_header, 1),
                )
                if response_plaintext != payload:
                    raise ValueError("loopback response plaintext did not match")
                stats["responses"] += 1
                if len(stats["samples_us"]) < LOOPBACK_LATENCY_SAMPLE_LIMIT and sequence % 16 == 0:
                    stats["samples_us"].append(
                        (time.perf_counter_ns() - operation_started) / 1000.0,
                    )
                sequence += 1
        except (OSError, EOFError, ValueError, InvalidTag, RuntimeError) as exc:
            client_errors.append(f"session {session_id}: {type(exc).__name__}: {exc}")

    def monitor_process_rss() -> None:
        try:
            while not resource_monitor_stop.is_set():
                rss_samples.append(current_process_rss_bytes())
                resource_monitor_stop.wait(RESOURCE_SAMPLE_INTERVAL_SECONDS)
        except (OSError, RuntimeError, ValueError) as exc:
            resource_sampling_errors.append(f"{type(exc).__name__}: {exc}")
            resource_monitor_stop.set()

    try:
        server = LoopbackServer(("127.0.0.1", 0), LoopbackHandler)
        server.timeout = 0.05
        server_thread = Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        server_thread.start()
        address = server.server_address
        for session_id in range(connection_count):
            connection = socket.create_connection(address, timeout=10)
            connection.settimeout(10)
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            connections.append(connection)
            client_threads.append(
                Thread(target=client_worker, args=(session_id, connection), daemon=True),
            )
        for thread in client_threads:
            thread.start()
        resource_monitor_thread = Thread(target=monitor_process_rss, daemon=True)
        resource_monitor_thread.start()
        process_cpu_started = time.process_time()
        wall_started = time.perf_counter()
        deadline = wall_started + duration_seconds
        clients_ready.wait(timeout=10)
        for thread in client_threads:
            thread.join(timeout=15)
        elapsed = time.perf_counter() - wall_started
        process_cpu_seconds = time.process_time() - process_cpu_started
        resource_monitor_stop.set()
        resource_monitor_thread.join(timeout=2)
        if resource_monitor_thread.is_alive():
            raise RuntimeError("process resource sampler did not stop within 2 seconds")
        if resource_sampling_errors:
            raise RuntimeError(
                "process resource sampling failed: " + "; ".join(resource_sampling_errors),
            )
        if any(thread.is_alive() for thread in client_threads):
            raise RuntimeError("loopback benchmark clients did not stop within 15 seconds")
        if client_errors or server_errors:
            raise RuntimeError(
                "loopback benchmark failed: "
                + "; ".join(client_errors + server_errors[:4]),
            )
        response_count = sum(int(stats["responses"]) for stats in client_stats)
        latency_samples = [
            sample
            for stats in client_stats
            for sample in stats["samples_us"]
        ]
        if response_count == 0 or not latency_samples:
            raise RuntimeError("loopback benchmark completed without authenticated records")
        if not rss_samples:
            raise RuntimeError("loopback benchmark completed without RSS samples")
        if authenticated_requests != response_count:
            raise RuntimeError(
                "loopback request/response count mismatch: "
                f"authenticated={authenticated_requests}, responses={response_count}",
            )
        return {
            "payload_bytes_per_direction": payload_bytes,
            "connection_count": connection_count,
            "authenticated_request_records": authenticated_requests,
            "authenticated_response_records": response_count,
            "failed_request_records": request_failures,
            "elapsed_seconds_including_client_shutdown": elapsed,
            "request_goodput_bps": response_count * payload_bytes * 8 / elapsed,
            "request_packets_per_second": response_count / elapsed,
            "process_cpu_time_seconds": process_cpu_seconds,
            "process_cpu_percent_of_one_core": process_cpu_seconds / elapsed * 100.0,
            "process_rss_bytes": {
                "start": rss_samples[0],
                "mean_sampled": round(sum(rss_samples) / len(rss_samples)),
                "peak_sampled": max(rss_samples),
                "end": rss_samples[-1],
                "samples": len(rss_samples),
                "sample_interval_ms": RESOURCE_SAMPLE_INTERVAL_SECONDS * 1000,
                "scope": "whole probe process, including server, clients, model, and sampler",
            },
            "sum_of_request_and_response_payload_bps": (
                response_count * payload_bytes * 16 / elapsed
            ),
            "request_response_rtt": percentiles(latency_samples),
            "latency_samples_per_connection": [
                len(stats["samples_us"]) for stats in client_stats
            ],
            "wireguard_or_tls_included": False,
            "remote_peer_authentication_included": False,
            "key_exchange_included": include_secure_pipeline,
            "tcp_loopback_only": True,
            "server_bind_host": address[0],
            "client_nonce_sequences_unique_per_session_and_direction": True,
            "secure_pipeline_enabled": include_secure_pipeline,
            "synthetic_api_token_authentication_included": include_secure_pipeline,
            "token_authentication_scope": (
                "locally generated test token checked after AEAD decryption"
                if include_secure_pipeline else "not included"
            ),
            "ml_kem_768_server_keypair_generation_included": False,
            "ml_kem_768_handshake_count": pqc_handshakes,
            "ml_kem_768_handshake_latency": (
                percentiles(handshake_durations_us)
                if handshake_durations_us else None
            ),
            "ml_kem_public_key_pin_verified": (
                include_secure_pipeline and pqc_handshakes == connection_count
            ),
            "dpi_pipeline_included": include_secure_pipeline,
            "ai_model_diagnostic": (
                include_secure_pipeline
                and model is not None
                and defender.TORCH_AVAILABLE
            ),
            "forced_full_inspection_logging_included": include_secure_pipeline,
            "inspection_log_records": inspection_records,
            "inspection_log_file_bytes": (
                log_path.stat().st_size
                if log_path is not None and log_path.exists() else 0
            ),
            "inspection_log_fsync": False,
            "temporary_inspection_log_removed_after_measurement": (
                include_secure_pipeline
            ),
        }
    finally:
        resource_monitor_stop.set()
        if resource_monitor_thread is not None:
            resource_monitor_thread.join(timeout=2)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        if server is not None:
            server.shutdown()
            server.server_close()
        if server_thread is not None:
            server_thread.join(timeout=2)
        if log_directory is not None:
            log_directory.cleanup()
        defender.FULL_PACKET_INSPECTION = previous_inspection_flag
        defender.log.setLevel(previous_log_level)


def evidence_provenance() -> dict[str, object]:
    repository_root = Path(__file__).resolve().parents[1]
    source_files = (
        Path(__file__),
        repository_root / "airgap_ai_defender.py",
        repository_root / "mk1_secure_transport.py",
        repository_root / "mk1_tunnel.c",
    )
    source_hashes = {}
    for source_path in source_files:
        digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
        source_hashes[str(source_path.relative_to(repository_root))] = digest
    package_versions = {}
    for package in ("cryptography", "pqcrypto", "torch"):
        try:
            package_versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            package_versions[package] = "not installed"
    return {
        "source_sha256": source_hashes,
        "package_versions": package_versions,
    }


def machine_info() -> dict[str, object]:
    cpu_model = None
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass

    interfaces = []
    for index, name in socket.if_nameindex():
        entry: dict[str, object] = {"index": index, "name": name}
        sysfs_path = Path("/sys/class/net") / name
        for attribute in ("mtu", "speed"):
            try:
                entry[attribute] = (sysfs_path / attribute).read_text().strip()
            except OSError:
                entry[attribute] = "unavailable"
        entry["device_sysfs_link_present"] = (sysfs_path / "device").exists()
        interfaces.append(entry)

    max_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if platform.system() == "Linux":
        max_rss *= 1024
    return {
        "system": platform.platform(),
        "python": sys.version.split()[0],
        "cpu_model": cpu_model,
        "logical_cpu_count": os.cpu_count(),
        "process_max_rss_bytes": max_rss,
        "interfaces": interfaces,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--duration-seconds",
        type=float,
        default=0.25,
        help="minimum timed duration per component scenario (0.05-5 seconds)",
    )
    parser.add_argument(
        "--frame-sizes",
        type=int,
        nargs="+",
        default=DEFAULT_FRAME_SIZES,
        help="synthetic Ethernet frame sizes for inspection and AES-GCM",
    )
    parser.add_argument(
        "--connection-counts",
        type=int,
        nargs="+",
        default=DEFAULT_CONNECTION_COUNTS,
        help="simultaneous localhost TCP sessions for the synthetic AEAD record test",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="optional path for the JSON report; stdout is always emitted",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 0.05 <= args.duration_seconds <= 5:
        raise SystemExit("--duration-seconds must be between 0.05 and 5")
    if not args.frame_sizes or any(size < 64 or size > 65_549 for size in args.frame_sizes):
        raise SystemExit("--frame-sizes must contain values from 64 through 65549")
    if len(set(args.frame_sizes)) != len(args.frame_sizes):
        raise SystemExit("--frame-sizes must not contain duplicates")
    if (
        not args.connection_counts
        or any(count < 1 or count > 128 for count in args.connection_counts)
        or len(set(args.connection_counts)) != len(args.connection_counts)
    ):
        raise SystemExit("--connection-counts must be unique values from 1 through 128")

    ai_status = "unavailable: PyTorch is not installed"
    ai_model = None
    if defender.TORCH_AVAILABLE:
        torch = defender.torch
        torch.manual_seed(0)
        torch.set_num_threads(1)
        ai_model = defender.LightweightMultiTaskAI(input_dim=10).eval()
        ai_status = "randomly initialized diagnostic model; no reviewed checkpoint loaded"

    results = {
        "aes_256_gcm": [
            benchmark_aes_gcm(size, args.duration_seconds)
            for size in args.frame_sizes
        ],
        "localhost_tcp_aead_transport": [
            {
                "payload_bytes": size,
                "connections": [
                    benchmark_loopback_transport(
                        size, count, args.duration_seconds,
                    )
                    for count in args.connection_counts
                ],
            }
            for size in args.frame_sizes
        ],
        "synthetic_packet_pipeline_ai_disabled": [
            {
                "frame_bytes": size,
                "processing": benchmark_packet_pipeline(
                    size, args.duration_seconds, model=None,
                ),
            }
            for size in args.frame_sizes
        ],
        "synthetic_packet_pipeline_ai_diagnostic": (
            [
                {
                    "frame_bytes": size,
                    "processing": benchmark_packet_pipeline(
                        size, args.duration_seconds, model=ai_model,
                    ),
                }
                for size in args.frame_sizes
            ]
            if ai_model is not None else None
        ),
        "synthetic_forced_full_inspection_log": [
            {
                "frame_bytes": size,
                "logging": benchmark_inspection_logging(
                    size, args.duration_seconds,
                ),
            }
            for size in args.frame_sizes
        ],
        "localhost_tcp_secure_pipeline": [
            {
                "frame_bytes": size,
                "connections": [
                    benchmark_loopback_transport(
                        size,
                        count,
                        args.duration_seconds,
                        model=ai_model,
                        include_secure_pipeline=True,
                    )
                    for count in args.connection_counts
                ],
            }
            for size in args.frame_sizes
        ],
        "ml_kem_768_sequential_session_establishment": benchmark_pqc(
            args.duration_seconds,
        ),
    }
    report: dict[str, object] = {
        "schema_version": 1,
        "classification": "local component microbenchmark; not network throughput",
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "evidence_provenance": evidence_provenance(),
        "machine": machine_info(),
        "test_configuration": {
            "duration_seconds_minimum_per_scenario": args.duration_seconds,
            "latency_samples_per_scenario": LATENCY_SAMPLE_COUNT,
            "frame_sizes_bytes": args.frame_sizes,
            "loopback_connection_counts": args.connection_counts,
            "worker_count": 1,
            "network_traffic_generated": False,
            "live_nic_or_end_to_end_path_measured": False,
            "full_packet_inspection_logging_configured": defender.FULL_PACKET_INSPECTION,
            "ai_model_status": ai_status,
        },
        "limitations": [
            "No physical NIC traffic, remote peer, or WireGuard tunnel was measured; the localhost AEAD transport is synthetic.",
            "AES-GCM component rates and localhost AEAD goodput are not physical link throughput.",
            "The standalone ML-KEM rate result covers sequential encapsulation and decapsulation only; the combined localhost scenario also performs a test-only session handshake and same-process key-pin comparison.",
            "Synthetic DPI pipeline rates exclude packet capture, multiprocessing queues, and production traffic distributions.",
            "AI-on results, when available, use random initialization and are diagnostic only, not a reviewed production model.",
            "No network packet loss, one-way latency, or fabric capacity was measured.",
            "Loopback AEAD record framing is diagnostic test code, not a production or interoperable MK1Ai protocol.",
            "The combined localhost secure-pipeline test uses an in-process synthetic API token and an expected ML-KEM key pin; it does not implement or validate the deployed remote authentication protocol.",
            "The combined localhost test omits WireGuard/TLS, durable log flush/fsync, NIC capture, and process-boundary overhead; reported CPU and RSS are sampled process-wide diagnostics, not NIC dataplane utilization.",
        ],
        "results": results,
    }
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
