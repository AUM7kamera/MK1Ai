import fcntl
import json
import os
import pathlib
import pty
import re
import select
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
from statistics import mean

import torch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import airgap_ai_defender as defender


def percentiles(samples_ms):
    ordered = sorted(samples_ms)

    def percentile(fraction):
        position = (len(ordered) - 1) * fraction
        lower = int(position)
        upper = min(lower + 1, len(ordered) - 1)
        weight = position - lower
        return ordered[lower] * (1.0 - weight) + ordered[upper] * weight

    return {
        "mean_ms": mean(ordered),
        "p95_ms": percentile(0.95),
        "p99_ms": percentile(0.99),
        "samples": len(ordered),
    }


def packet(dst_port, *, payload=b"", flags=0x02, identification=1):
    source_ip = socket.inet_aton("192.0.2.10")
    destination_ip = socket.inet_aton("198.51.100.20")
    tcp_header = struct.pack(
        "!HHIIHHHH", 40000, dst_port, 1, 0, (5 << 12) | flags, 64240, 0, 0,
    )
    total_length = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_length, identification, 0x4000, 64,
        socket.IPPROTO_TCP, 0, source_ip, destination_ip,
    )
    ethernet = b"\x00" * 12 + b"\x08\x00"
    return ethernet + ip_header + tcp_header + payload


def benchmark_panel():
    status_path = pathlib.Path("ai_data/panel-status.txt")
    status_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    log_path = pathlib.Path("ai_data/panel.log")
    log_path.write_text("INFO synthetic telemetry benchmark\n", encoding="utf-8")
    latencies = []
    output_bytes = 0
    output_times = []
    update_times = {}

    def update_status():
        for index in range(24):
            update_times[index + 1] = time.perf_counter()
            status_path.write_text(
                "state=RUNNING\nalert=NONE\n"
                f"packets_per_second={index + 1}.0\npackets_total={index + 1}\n"
                "threat_score=0.1\nbackdoor_score=0.0\n"
                "ram_used_mb=100\nram_limit_mb=512\nswap_used_mb=0\n"
                "isolation_active=0\nsecure_tunnel_active=0\nmemory_guard_active=0\ndry_run=1\n",
                encoding="utf-8",
            )
            time.sleep(0.1)

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
    environment = dict(os.environ, TERM="xterm", MK1_PANEL_LAUNCHER="explicit-command")
    process = subprocess.Popen(
        [".build/mk1-panel"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=environment,
    )
    os.close(slave)
    writer = threading.Thread(target=update_status, daemon=True)
    writer.start()
    started = time.perf_counter()
    terminal_output = bytearray()
    display_times = {}
    while time.perf_counter() - started < 2.8:
        readable, _, _ = select.select([master], [], [], 0.1)
        if readable:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if chunk:
                now = time.perf_counter()
                output_times.append(now)
                output_bytes += len(chunk)
                terminal_output.extend(chunk)
                screen_text = re.sub(
                    rb"\x1b\[[0-?]*[ -/]*[@-~]", b"",
                    bytes(terminal_output),
                )
                for match in re.finditer(rb"total:\s*(\d+)", screen_text):
                    value = int(match.group(1))
                    if value in update_times and value not in display_times:
                        display_times[value] = now
    os.write(master, b"q")
    process.wait(timeout=5)
    writer.join(timeout=1)
    os.close(master)
    if process.returncode != 0:
        raise RuntimeError(f"ncurses panel exited with status {process.returncode}")
    for value, displayed_at in display_times.items():
        latencies.append((displayed_at - update_times[value]) * 1000.0)
    output_bursts = []
    for output_time in output_times:
        if not output_bursts or output_time - output_bursts[-1] > 0.05:
            output_bursts.append(output_time)
        else:
            output_bursts[-1] = output_time
    redraw_intervals = [
        (current - previous) * 1000.0
        for previous, current in zip(output_bursts, output_bursts[1:])
    ]
    return {
        "configured_worker_poll_ms": 500,
        "configured_ui_loop_sleep_ms": 250,
        "status_write_to_display_ms": percentiles(latencies) if latencies else None,
        "matched_status_values": len(latencies),
        "terminal_redraw_burst_intervals_ms": (
            percentiles(redraw_intervals) if redraw_intervals else None
        ),
        "terminal_redraw_bursts": len(output_bursts),
        "captured_terminal_output_bytes": output_bytes,
        "exit_status": process.returncode,
    }


def main():
    torch.manual_seed(0)
    torch.set_num_threads(1)
    model = defender.LightweightMultiTaskAI(input_dim=10).eval()
    vector = torch.tensor([[0.1] * 10], dtype=torch.float32)
    with torch.inference_mode():
        for _ in range(100):
            model(vector)
        inference = []
        for _ in range(3000):
            started = time.perf_counter_ns()
            model(vector)
            inference.append((time.perf_counter_ns() - started) / 1_000_000)

    model_ms = percentiles(inference)
    packet_latencies = []
    with torch.inference_mode():
        for index in range(500):
            sample = packet(443, payload=b"GET /health HTTP/1.1\r\n\r\n", identification=index)
            started = time.perf_counter_ns()
            defender.inspect_packet_pipeline(sample, "eth0", model=model, dry_run=True)
            packet_latencies.append((time.perf_counter_ns() - started) / 1_000_000)

    memory = defender.MemoryManager(max_memory_mb=512, swap_dir="/tmp/mk1-bench-swap")
    batch = [{"index": index, "sample": "synthetic-" + ("x" * 1000)} for index in range(64)]
    payload_bytes = len(json.dumps(batch).encode())
    memory_samples = []
    total_bytes = 0
    try:
        for _ in range(128):
            started = time.perf_counter_ns()
            saved = memory.evict_buffer(batch)
            elapsed = (time.perf_counter_ns() - started) / 1_000_000
            if saved != len(batch) or elapsed <= 0:
                raise RuntimeError(f"MemoryManager evict failed: saved={saved}")
            memory_samples.append(elapsed)
            total_bytes += payload_bytes
        total_seconds = sum(memory_samples) / 1000.0
        encrypted_bytes = memory._offset
    finally:
        swap_path = memory._swap_path
        memory.cleanup()

    scenarios = []
    labeled_groups = {
        "benign": (False, [packet(443, payload=b"GET /index HTTP/1.1\r\n\r\n", identification=i) for i in range(20)]),
        "port_scan": (True, [packet(port, identification=100 + port) for port in range(1, 21)]),
        "bad_payload": (
            True,
            [
                packet(
                    8080,
                    payload=b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n<script>alert(1)</script>",
                    identification=200 + i,
                )
                for i in range(10)
            ],
        ),
        "oversized_frame": (True, [packet(8443, payload=b"x" * 9000, identification=300 + i) for i in range(10)]),
    }
    confusion = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for label, (expected_threat, packets) in labeled_groups.items():
        for sample in packets:
            result = defender.inspect_packet_pipeline(sample, "eth0", model=model, dry_run=True)
            predicted = bool(result.get("block"))
            confusion[
                "tp" if expected_threat and predicted else
                "fn" if expected_threat else
                "fp" if predicted else "tn"
            ] += 1
            scenarios.append({
                "label": label,
                "expected_threat": expected_threat,
                "blocked": predicted,
                "score": round(float(result.get("score", 0.0)), 6),
                "stage": result.get("stage"),
                "reason": result.get("reason"),
            })

    malicious_payload = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n<script>alert(1)</script>"
    explicit_payload_packet = packet(9911, identification=9911)
    embedded_payload_packet = packet(9912, payload=malicious_payload, identification=9912)
    explicit_dpi = defender.analyze_dpi_payload(
        explicit_payload_packet, payload=malicious_payload, interface="eth0",
    )
    embedded_dpi = defender.analyze_dpi_payload(
        embedded_payload_packet, interface="eth0",
    )
    print(json.dumps({
        "torch_version": torch.__version__,
        "cpu_threads": torch.get_num_threads(),
        "model_weights": "fresh random initialization; no production checkpoint loaded",
        "model_forward_ms": model_ms,
        "packet_pipeline_ms": percentiles(packet_latencies),
        "panel": benchmark_panel(),
        "memory_manager": {
            "aesgcm_available": defender.AESGCM is not None,
            "records": len(memory_samples),
            "input_bytes": total_bytes,
            "encrypted_mmap_bytes": encrypted_bytes,
            "elapsed_ms_mean": mean(memory_samples),
            "encrypted_mmap_MB_per_s": encrypted_bytes / (1024 * 1024) / total_seconds,
            "serialized_input_MB_per_s": total_bytes / (1024 * 1024) / total_seconds,
            "swap_file_removed": not __import__("os").path.exists(swap_path),
            "durable_flush": False,
        },
        "synthetic_verdicts": {
            "confusion": confusion,
            "false_positive_rate": confusion["fp"] / max(1, confusion["fp"] + confusion["tn"]),
            "false_negative_rate": confusion["fn"] / max(1, confusion["fn"] + confusion["tp"]),
            "scenario_counts": {label: len(items[1]) for label, items in labeled_groups.items()},
            "results": scenarios,
        },
        "detector_diagnostics": {
            "embedded_payload_extracted": defender.extract_payload_bytes(
                embedded_payload_packet,
            ).decode("latin-1", errors="replace"),
            "explicit_payload_dpi": {
                "suspicious": explicit_dpi.get("suspicious"),
                "score": explicit_dpi.get("score"),
                "attack_signatures": explicit_dpi.get("attack_signatures"),
            },
            "embedded_payload_dpi": {
                "suspicious": embedded_dpi.get("suspicious"),
                "score": embedded_dpi.get("score"),
                "attack_signatures": embedded_dpi.get("attack_signatures"),
            },
        },
    }, sort_keys=True))


if __name__ == "__main__":
    main()
