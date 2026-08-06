import hashlib
import importlib.util
import json
import os
import pathlib
import queue
import shutil
import socket
import struct
import tempfile
import time
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "airgap_ai_defender.py"

spec = importlib.util.spec_from_file_location("airgap_ai_defender", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AirgapSecurityHelpersTest(unittest.TestCase):
    def test_select_monitor_interface_prefers_wg0(self):
        self.assertEqual(module.select_monitor_interface(["eth0", "wg0"]), "wg0")
        self.assertEqual(module.select_monitor_interface(["eth0", "wlan0"]), "eth0")

    def test_discover_available_interfaces_excludes_loopback(self):
        with mock.patch.object(module.os.path, "isdir", return_value=True), \
             mock.patch.object(module.os, "listdir", return_value=["lo", "eth0", "wg0"]):
            interfaces = module.discover_available_interfaces()
            self.assertEqual(interfaces, ["eth0", "wg0"])

    def test_analyze_packet_security_markers_detects_tls_and_ipsec(self):
        tls_packet = b"\x16\x03\x03\x00\x01\x01"
        markers = module.analyze_packet_security_markers(tls_packet, interface="eth0")
        self.assertTrue(any("TLS" in marker for marker in markers))

        ipsec_packet = b"\x45\x00\x00\x00"
        markers = module.analyze_packet_security_markers(ipsec_packet, interface="wg0")
        self.assertTrue(any("IPsec" in marker for marker in markers))

    def test_evaluate_threat_state_triggers_kill_switch_on_backdoor(self):
        with mock.patch.object(module, "execute_kill_switch") as kill_switch:
            module._KILL_SWITCH_TRIGGERED = False
            module._BACKDOOR_RISK_SCORE = 0.8
            module.evaluate_threat_state("eth0", dry_run=True, score_a=0.1, backdoor_detected=True)
            kill_switch.assert_called_once_with("eth0", True)

    def test_handle_packet_event_triggers_kill_switch_when_threat_active(self):
        with mock.patch.object(module, "execute_kill_switch") as kill_switch:
            module._KILL_SWITCH_TRIGGERED = False
            module._BACKDOOR_RISK_SCORE = 0.9
            module.handle_packet_event(b"\x00", "eth0", dry_run=True)
            kill_switch.assert_called_once_with("eth0", True)

    def test_is_google_drive_whitelisted_packet_never_bypasses_traffic(self):
        gdrive_packet = self._build_ipv4_tcp_packet("1.2.3.4", "8.8.8.8", 443)
        non_gdrive_packet = self._build_ipv4_tcp_packet("1.2.3.4", "8.8.4.4", 443)
        self.assertFalse(module.is_google_drive_whitelisted_packet(gdrive_packet))
        self.assertFalse(module.is_google_drive_whitelisted_packet(non_gdrive_packet))

    def test_http_packets_are_not_whitelisted_during_download(self):
        packet = self._build_ipv4_tcp_packet("1.2.3.4", "8.8.8.8", 80)
        self.assertFalse(module.is_google_drive_whitelisted_packet(packet))

    def test_gdrive_domains_are_no_longer_used_for_allowlisting(self):
        self.assertFalse(hasattr(module, "_GDRIVE_DOMAINS"))

    def test_evaluate_threat_state_requires_three_consecutive_anomalies(self):
        original_triggered = module._KILL_SWITCH_TRIGGERED
        original_last_trigger = module._LAST_KILL_SWITCH_TRIGGER
        original_counter = module._anomaly_counter
        try:
            module._KILL_SWITCH_TRIGGERED = False
            module._LAST_KILL_SWITCH_TRIGGER = 0.0
            module._anomaly_counter = 0
            with mock.patch.object(module, "execute_kill_switch") as kill_switch:
                self.assertFalse(module.evaluate_threat_state("eth0", True, score_a=0.96))
                self.assertFalse(module.evaluate_threat_state("eth0", True, score_a=0.96))
                self.assertTrue(module.evaluate_threat_state("eth0", True, score_a=0.96))
                self.assertEqual(kill_switch.call_count, 1)
        finally:
            module._KILL_SWITCH_TRIGGERED = original_triggered
            module._LAST_KILL_SWITCH_TRIGGER = original_last_trigger
            module._anomaly_counter = original_counter

    def test_packet_capture_worker_uses_ema_for_interarrival_feature(self):
        class DummySocket:
            def __init__(self):
                self.calls = 0
            def settimeout(self, timeout):
                pass
            def bind(self, *args, **kwargs):
                return None
            def recvfrom(self, *args, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    return self._build_packet(), None
                raise KeyboardInterrupt

            @staticmethod
            def _build_packet() -> bytes:
                ethernet_header = b"\x00" * 12 + struct.pack("!H", 0x0800)
                ip_header = struct.pack(
                    "!BBHHHBBH4s4s",
                    0x45,
                    0,
                    20,
                    0,
                    0,
                    0,
                    6,
                    0,
                    socket.inet_aton("1.1.1.1"),
                    socket.inet_aton("2.2.2.2"),
                )
                tcp_header = struct.pack("!HHIIHHHH", 12345, 80, 0, 0, 5, 2, 0, 0)
                return ethernet_header + ip_header + tcp_header

        class DummyMemMgr:
            @staticmethod
            def get_usage_ratio():
                return 0.25

        q = queue.Queue(maxsize=10)
        original_queue = module._packet_queue
        original_last_pkt_time = module._last_pkt_time
        original_ema_delta = module._ema_delta
        try:
            module._packet_queue = q
            module._last_pkt_time = 100.0
            module._ema_delta = 0.1
            with mock.patch.object(module.socket, "socket", return_value=DummySocket()), \
                 mock.patch.object(module, "handle_packet_event"), \
                 mock.patch.object(module.time, "time", side_effect=[100.2, 100.2]):
                module._packet_capture_worker("eth0", DummyMemMgr(), True)
            feat, _ = q.get_nowait()
            self.assertAlmostEqual(feat[1], 0.11, places=5)
        finally:
            module._packet_queue = original_queue
            module._last_pkt_time = original_last_pkt_time
            module._ema_delta = original_ema_delta

    def test_maintenance_mode_forces_dry_run_on_threat_state(self):
        original_maintenance = module._MAINTENANCE_ACTIVE
        original_triggered = module._KILL_SWITCH_TRIGGERED
        original_last_trigger = module._LAST_KILL_SWITCH_TRIGGER
        original_counter = module._anomaly_counter
        try:
            module._MAINTENANCE_ACTIVE = True
            module._KILL_SWITCH_TRIGGERED = False
            module._LAST_KILL_SWITCH_TRIGGER = 0.0
            module._anomaly_counter = 0
            with mock.patch.object(module, "execute_kill_switch") as kill_switch:
                module.evaluate_threat_state("eth0", dry_run=False, score_a=0.99, backdoor_detected=True)
                kill_switch.assert_called_once_with("eth0", True)
        finally:
            module._MAINTENANCE_ACTIVE = original_maintenance
            module._KILL_SWITCH_TRIGGERED = original_triggered
            module._LAST_KILL_SWITCH_TRIGGER = original_last_trigger
            module._anomaly_counter = original_counter

    def test_load_cloud_model_uses_cpu_map_location(self):
        class DummyModel:
            def __init__(self):
                self.loaded_state = None
            def load_state_dict(self, state_dict):
                self.loaded_state = state_dict

        with mock.patch.object(module.os.path, "exists", return_value=True), \
             mock.patch.object(module.torch, "load", return_value={"weights": [1, 2, 3]}) as load_mock, \
             mock.patch.object(module, "log") as log_mock, \
             mock.patch.dict(module.os.environ, {"AIRGAP_MODEL_HASH": "deadbeef"}, clear=False), \
             mock.patch.object(module, "_verify_model_hash", return_value=True):
            model = DummyModel()
            self.assertTrue(module.load_cloud_model(model, "/tmp/cloud_base_model.pth"))
            self.assertEqual(load_mock.call_args.kwargs["map_location"], module.torch.device("cpu"))
            self.assertTrue(load_mock.call_args.kwargs.get("weights_only", False))
            self.assertEqual(model.loaded_state, {"weights": [1, 2, 3]})
            self.assertTrue(log_mock.info.called or log_mock.warning.called)

    def test_load_cloud_model_rejects_mismatched_hash(self):
        class DummyModel:
            def load_state_dict(self, state_dict):
                raise AssertionError("must not load")

        with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
            handle.write(b"model-bytes")
            temp_path = handle.name
        try:
            with mock.patch.object(module.os.path, "exists", return_value=True), \
                 mock.patch.dict(module.os.environ, {"AIRGAP_MODEL_HASH": hashlib.sha256(b"expected").hexdigest()}), \
                 mock.patch.object(module.torch, "load", side_effect=AssertionError("torch.load should not run")) as load_mock:
                model = DummyModel()
                self.assertFalse(module.load_cloud_model(model, temp_path))
                load_mock.assert_not_called()
        finally:
            pathlib.Path(temp_path).unlink(missing_ok=True)

    def test_run_command_with_sudo_dispatches_to_privileged_worker_on_non_root(self):
        with mock.patch.object(module.os, "geteuid", return_value=1000), \
             mock.patch.object(module, "_validate_command_tokens", return_value=True), \
             mock.patch.object(module, "_dispatch_privileged_command", return_value=True) as dispatch:
            module._PRIVILEGED_AGENT_ACTIVE = True
            try:
                self.assertTrue(module._run_command_with_sudo(["ip", "link", "set", "eth0", "down"], dry_run=False))
                dispatch.assert_called_once_with("run_command", cmd=["ip", "link", "set", "eth0", "down"], dry_run=False)
            finally:
                module._PRIVILEGED_AGENT_ACTIVE = False

    def test_is_suspicious_process_command_detects_deleted_executable(self):
        with mock.patch.object(module.os, "readlink", return_value="/tmp/malware (deleted)"), \
             mock.patch.object(module.os.path, "realpath", return_value="/tmp/malware"):
            self.assertTrue(module._is_suspicious_process_command(1234, "malware"))

    def test_store_admin_recovery_token_sets_restrictive_permissions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            token_path = pathlib.Path(temp_dir) / "admin_recovery.token"
            with mock.patch.object(module, "_ADMIN_RECOVERY_TOKEN_FILE", str(token_path)):
                self.assertEqual(module._store_admin_recovery_token("secret-token"), "secret-token")
            self.assertEqual(token_path.read_text(encoding="utf-8").strip(), "secret-token")
            self.assertEqual(oct(token_path.stat().st_mode & 0o777), oct(0o600))

    def test_evaluate_threat_state_decays_anomaly_counter_after_cooldown(self):
        original_counter = module._anomaly_counter
        original_last_time = getattr(module, "_ANOMALY_DECAY_LAST_TIME", None)
        original_window = getattr(module, "_ANOMALY_DECAY_WINDOW_SEC", None)
        original_triggered = module._KILL_SWITCH_TRIGGERED
        original_last_trigger = module._LAST_KILL_SWITCH_TRIGGER
        try:
            module._anomaly_counter = 2
            module._ANOMALY_DECAY_LAST_TIME = 100.0
            module._ANOMALY_DECAY_WINDOW_SEC = 30.0
            module._KILL_SWITCH_TRIGGERED = False
            module._LAST_KILL_SWITCH_TRIGGER = 0.0
            with mock.patch.object(module, "execute_kill_switch") as kill_switch, \
                 mock.patch.object(module.time, "time", return_value=131.0):
                self.assertFalse(module.evaluate_threat_state("eth0", True, score_a=0.96))
                self.assertEqual(module._anomaly_counter, 1)
                kill_switch.assert_not_called()
        finally:
            module._anomaly_counter = original_counter
            if original_last_time is None:
                delattr(module, "_ANOMALY_DECAY_LAST_TIME")
            else:
                module._ANOMALY_DECAY_LAST_TIME = original_last_time
            if original_window is None:
                delattr(module, "_ANOMALY_DECAY_WINDOW_SEC")
            else:
                module._ANOMALY_DECAY_WINDOW_SEC = original_window
            module._KILL_SWITCH_TRIGGERED = original_triggered
            module._LAST_KILL_SWITCH_TRIGGER = original_last_trigger

    def _build_ipv4_tcp_packet(self, src_ip: str, dst_ip: str, dst_port: int) -> bytes:
        ethernet_header = b"\x00" * 12 + struct.pack("!H", 0x0800)
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            40,
            0,
            0,
            0,
            6,
            0,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )
        tcp_header = struct.pack("!HHIIHHHH", 12345, dst_port, 0, 0, 5, 2, 0, 0)
        return ethernet_header + ip_header + tcp_header

    def test_execute_kill_switch_runs_all_commands_when_some_fail(self):
        with mock.patch.object(module, "_run_command_with_sudo", side_effect=[False, True, True, True, True, True, True, True]) as run_cmd, \
             mock.patch.object(module, "discover_available_interfaces", return_value=["eth0"]), \
             mock.patch("shutil.which", return_value="/usr/bin/mocked_path"):
            module._KILL_SWITCH_TRIGGERED = False
            module.execute_kill_switch("eth0", dry_run=False, available_interfaces=["eth0"])
            self.assertGreaterEqual(run_cmd.call_count, 6)

            executed_commands = [call.args[0] for call in run_cmd.call_args_list]
            self.assertIn(["ip", "route", "replace", "default", "unreachable"], executed_commands)
            self.assertIn(["ip", "route", "add", "default", "unreachable"], executed_commands)

    def test_build_containment_plan_preserves_management_sessions(self):
        plan = module.build_containment_plan(
            "eth0",
            containment_mode="management_safe_harbor",
            management_ports=[22],
            management_ips=["127.0.0.1"],
        )
        self.assertEqual(plan["mode"], "management_safe_harbor")
        self.assertTrue(plan["preserve_management"])
        self.assertEqual(plan["allowed_ports"], [22])
        self.assertIn("127.0.0.1", plan["allowed_ips"])

    def test_progressive_defense_defers_repeated_parse_errors(self):
        decision = module.evaluate_progressive_defense(source_ip="10.0.0.5", event_type="parse_error", occurrence_count=3)
        self.assertTrue(decision["defer"])
        self.assertEqual(decision["action"], "rate_limit")

    def test_dynamic_load_shedding_switches_to_lightweight_scan(self):
        mode = module.select_scan_mode_for_load(packet_rate_per_sec=12000, cpu_pressure=0.92)
        self.assertEqual(mode, "lightweight")

    def test_build_diagnostic_trace_includes_layer_and_threshold(self):
        trace = module.build_diagnostic_trace(layer=2, threshold=0.6, score=0.72, reason="dpi")
        self.assertEqual(trace["layer"], 2)
        self.assertEqual(trace["threshold"], 0.6)
        self.assertIn("trace_id", trace)

    def test_load_cloud_model_rejects_sidecar_without_explicit_hash(self):
        class DummyModel:
            def load_state_dict(self, state_dict):
                raise AssertionError("should not load")

        with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
            handle.write(b"model-bytes")
            temp_path = handle.name
        sidecar_path = pathlib.Path(temp_path + ".sha256")
        sidecar_path.write_text(hashlib.sha256(b"model-bytes").hexdigest(), encoding="utf-8")
        try:
            with mock.patch.object(module.os.path, "exists", return_value=True), \
                 mock.patch.dict(module.os.environ, {}, clear=True), \
                 mock.patch.object(module.torch, "load", side_effect=AssertionError("torch.load should not run")) as load_mock:
                model = DummyModel()
                self.assertFalse(module.load_cloud_model(model, temp_path))
                load_mock.assert_not_called()
        finally:
            pathlib.Path(temp_path).unlink(missing_ok=True)
            sidecar_path.unlink(missing_ok=True)

    def test_boot_time_auto_hardening_reports_missing_root(self):
        profile = {"permissions": {"root": False}}
        result = module.boot_time_auto_hardening(profile)
        self.assertIn("missing_root", result["failures"])

    def test_generate_optimal_kill_payload_includes_nft_flush_when_available(self):
        profile = {
            "os": {"system": "Linux"},
            "available_interfaces": ["eth0"],
            "tools": {"ip": True, "iptables": True, "nft": True},
            "permissions": {"root": True},
            "network_layers": ["physical"],
        }
        payload = module.generate_optimal_kill_payload(profile, learning_data=["vpn"])
        self.assertTrue(any(cmd[:2] == ["nft", "flush"] for cmd in payload["commands"]))

    def test_memory_manager_check_considers_head_c_score(self):
        temp_swap_dir = "./test_swap"
        mgr = module.MemoryManager(max_memory_mb=1, swap_dir=temp_swap_dir)
        try:
            mock_rss = mock.Mock(rss=2 * 1024 * 1024)
            with mock.patch.object(mgr.process, "memory_info", return_value=mock_rss):
                ratio = mgr.check(head_c_score=0.9)
                self.assertTrue(mgr.is_critical)
                self.assertGreater(ratio, 1.0)
        finally:
            mgr.cleanup()
            if os.path.exists(temp_swap_dir):
                shutil.rmtree(temp_swap_dir)

    def test_load_cloud_model_fails_without_explicit_hash_configuration(self):
        class DummyModel:
            def load_state_dict(self, state_dict):
                raise AssertionError("should not load")

        with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
            handle.write(b"model-bytes")
            temp_path = handle.name
        try:
            with mock.patch.object(module.os.path, "exists", return_value=True), \
                 mock.patch.dict(module.os.environ, {}, clear=True), \
                 mock.patch.object(module.torch, "load", side_effect=AssertionError("torch.load should not run")) as load_mock:
                model = DummyModel()
                self.assertFalse(module.load_cloud_model(model, temp_path))
                load_mock.assert_not_called()
        finally:
            pathlib.Path(temp_path).unlink(missing_ok=True)

    def test_profile_environment_collects_profile_data(self):
        profile = module.profile_environment()
        self.assertIn("os", profile)
        self.assertIn("available_interfaces", profile)
        self.assertIn("tools", profile)
        self.assertIn("permissions", profile)

    def test_profile_environment_uses_platform_module_for_os(self):
        with mock.patch.object(module.platform, "system", return_value="Windows"), \
             mock.patch.object(module.platform, "release", return_value="11"), \
             mock.patch.object(module.platform, "version", return_value="10.0"), \
             mock.patch.object(module.platform, "machine", return_value="AMD64"), \
             mock.patch.object(module.platform, "platform", return_value="Windows-11"):
            profile = module.profile_environment()
            self.assertEqual(profile["os"]["system"], "Windows")
            self.assertEqual(profile["os"]["release"], "11")

    def test_generate_optimal_kill_payload_uses_environment_insights(self):
        profile = {
            "os": {"platform": "linux"},
            "available_interfaces": ["eth0", "wg0"],
            "tools": {"ip": True, "iptables": True, "dbus": True},
            "permissions": {"root": False},
            "network_layers": ["bridge", "vpn"],
        }
        payload = module.generate_optimal_kill_payload(profile, learning_data=["bridge", "unreachable"])
        self.assertEqual(payload["strategy"], "self_optimizing_kill_chain")
        self.assertTrue(payload["commands"])
        self.assertTrue(payload["fallback_payloads"])

    def test_generate_optimal_kill_payload_uses_os_specific_windows_commands(self):
        profile = {
            "os": {"system": "Windows", "release": "11"},
            "available_interfaces": ["Wi-Fi"],
            "tools": {"ip": False, "iptables": False, "dbus": False},
            "permissions": {"root": False},
            "network_layers": ["physical"],
        }
        payload = module.generate_optimal_kill_payload(profile, learning_data=["windows"])
        self.assertTrue(any(command[:1] == ["powershell"] for command in payload["commands"]))

    def test_execute_generated_payload_falls_back_when_primary_fails(self):
        payload = {
            "commands": [["ip", "link", "set", "eth0", "down"]],
            "fallback_payloads": [{"commands": [["echo", "fallback"]]}],
        }
        with mock.patch.object(module, "_run_command_with_sudo", side_effect=[False, True]) as run_cmd:
            module.execute_generated_payload(payload, dry_run=False)
            self.assertGreaterEqual(run_cmd.call_count, 2)

    def test_handle_admin_recovery_signal_requires_authorized_token(self):
        original_token = getattr(module, "_ADMIN_RECOVERY_TOKEN", None)
        try:
            module._ADMIN_RECOVERY_TOKEN = "secret-token"
            with mock.patch.object(module, "_run_command_with_sudo", return_value=True) as run_cmd:
                result = module.handle_admin_recovery_signal("wrong-token", interface="eth0", available_interfaces=["eth0"])
            self.assertFalse(result["authorized"])
            self.assertFalse(result["recovered"])
            run_cmd.assert_not_called()
        finally:
            module._ADMIN_RECOVERY_TOKEN = original_token

    def test_packet_inspection_pipeline_blocks_immediately_in_oni_mode(self):
        original_oni_mode = module.ONI_MODE
        try:
            module.ONI_MODE = True
            result = module.inspect_packet_pipeline(b"\x00", "eth0", model=None, dry_run=True)
            self.assertTrue(result["block"])
            self.assertEqual(result["stage"], "oni")
        finally:
            module.ONI_MODE = original_oni_mode

    def test_analyze_dpi_payload_detects_suspicious_payload(self):
        payload = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n<script>alert(1)</script>"
        result = module.analyze_dpi_payload(payload)
        self.assertTrue(result["suspicious"])
        self.assertGreaterEqual(result["score"], 0.5)
        self.assertIn("XSS", " ".join(result["attack_signatures"]))

    def test_analyze_dpi_payload_detects_signature_in_tail_region(self):
        payload = b"A" * 600 + b"<script>alert(1)</script>"
        result = module.analyze_dpi_payload(payload)
        self.assertTrue(result["suspicious"])
        self.assertTrue(any(item["offset"] >= 600 for item in result.get("findings", [])))

    def test_analyze_dpi_payload_keeps_json_payload_from_false_positive(self):
        payload = b'{"method":"GET","headers":{"Content-Type":"application/json"},"items":[1,2,3]}'
        result = module.analyze_dpi_payload(payload)
        self.assertFalse(result["suspicious"])
        self.assertLess(result["score"], 0.5)

    def test_analyze_dpi_payload_detects_masked_obfuscation_in_json(self):
        payload = b'{"method":"POST","payload":"\\x89\\x50\\x4e\\x47\\x0d\\x0a\\x1a\\x0aZGVjb2RlKGV2YWwoY29kZSkp"}'
        result = module.analyze_dpi_payload(payload)
        self.assertTrue(result["suspicious"])
        self.assertGreaterEqual(result["score"], 0.7)

    def test_analyze_dpi_payload_detects_utf16le_obfuscated_exec_marker(self):
        payload = "powershell -NoProfile".encode("utf-16le")
        result = module.analyze_dpi_payload(payload)
        self.assertTrue(result["suspicious"])
        self.assertGreaterEqual(result["score"], 0.5)

    def test_analyze_packet_security_markers_extracts_tls_sni(self):
        name = b"example.com"
        sni_extension_data = struct.pack("!H", 3 + len(name)) + b"\x00" + struct.pack("!H", len(name)) + name
        extension_block = struct.pack("!H", 0x0000) + struct.pack("!H", len(sni_extension_data)) + sni_extension_data
        client_hello = (
            b"\x03\x03" + b"\x00" * 32 + b"\x00" +
            struct.pack("!H", 2) + b"\x00\x2f" +
            b"\x01\x00" +
            struct.pack("!H", len(extension_block)) + extension_block
        )
        hs_len = len(client_hello)
        handshake = b"\x01" + struct.pack("!I", hs_len)[1:] + client_hello
        record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
        packet = self._build_ipv4_tcp_packet("1.1.1.1", "2.2.2.2", 443) + record
        markers = module.analyze_packet_security_markers(packet, interface="eth0")
        self.assertTrue(any("SNI" in marker for marker in markers))

    def test_analyze_dpi_payload_ignores_benign_data_url_base64_in_json(self):
        payload = b'{"image":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAF"}'
        result = module.analyze_dpi_payload(payload)
        self.assertFalse(result["suspicious"])
        self.assertLess(result["score"], 0.5)

    def test_analyze_dpi_payload_ignores_benign_jwt_token_shape(self):
        payload = b'{"authorization":"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature","request_id":"abc123"}'
        result = module.analyze_dpi_payload(payload)
        self.assertFalse(result["suspicious"])
        self.assertLess(result["score"], 0.5)

    def test_inspect_packet_pipeline_blocks_on_dpi_suspicious_payload(self):
        packet = self._build_ipv4_tcp_packet("1.1.1.1", "2.2.2.2", 80)
        suspicious_payload = b"eval(cmd)"
        dpi_result = module.analyze_dpi_payload(packet + suspicious_payload)
        result = module.inspect_packet_pipeline(packet + suspicious_payload, "eth0", dpi_result=dpi_result)
        self.assertTrue(result["block"])
        self.assertEqual(result["stage"], "dpi")

    def test_memory_manager_circular_buffer(self):
        temp_swap_dir = "./test_swap"
        mgr = module.MemoryManager(max_memory_mb=10, swap_dir=temp_swap_dir)
        try:
            # Check normal write
            data = [{"key": "val"}]
            count = mgr.evict_buffer(data)
            self.assertEqual(count, 1)

            # Test ring buffer wrap around
            mgr._offset = len(mgr._mmap) - 5
            count2 = mgr.evict_buffer(data)
            self.assertEqual(count2, 1)
            self.assertEqual(mgr._offset, len((json.dumps(data) + "\n").encode()))
        finally:
            mgr.cleanup()
            if os.path.exists(temp_swap_dir):
                shutil.rmtree(temp_swap_dir)

    def test_ipv6_packet_parsing_and_markers(self):
        # 14 bytes ethernet + 40 bytes IPv6 header + TCP header
        # Next header for TCP is 6
        ethernet_header = struct.pack("!6s6sH", b"\x00"*6, b"\x00"*6, 0x86DD)
        # IPv6: version=6 (tc=0, fl=0), payload_len=20, next_hdr=6, hop_limit=64
        # Src IP: ::1, Dst IP: ::1
        src_ip_bytes = socket.inet_pton(socket.AF_INET6, "::1")
        dst_ip_bytes = socket.inet_pton(socket.AF_INET6, "::1")
        ipv6_header = struct.pack("!IHBB16s16s", 0x60000000, 20, 6, 64, src_ip_bytes, dst_ip_bytes)
        tcp_header = struct.pack("!HHIIHHHH", 12345, 80, 0, 0, 5, 2, 0, 0)
        packet = ethernet_header + ipv6_header + tcp_header + b"GET / HTTP/1.1\r\n\r\n"

        transport = module.parse_packet_transport(packet)
        self.assertEqual(transport.get("src_ip"), "::1")
        self.assertEqual(transport.get("dst_ip"), "::1")
        self.assertEqual(transport.get("src_port"), 12345)
        self.assertEqual(transport.get("dst_port"), 80)
        self.assertEqual(transport.get("protocol"), 6)

        payload = module.extract_payload_bytes(packet)
        self.assertEqual(payload, b"GET / HTTP/1.1\r\n\r\n")

    def test_flow_cache_force_full_scan_thresholds(self):
        packet = self._build_ipv4_tcp_packet("1.1.1.1", "2.2.2.2", 80) + b"data"
        flow_state = {
            "sample_counter": 0,
            "last_payload_len": 4,
            "last_result": {"block": False, "score": 0.01, "rules": []},
            "last_seen": time.time(),
            "last_scan_time": time.time(),
            "last_flags": 2,
            "cumulative_bytes": 0,
            "packets_since_last_scan": 0,
        }

        # Packet count trigger
        flow_state["packets_since_last_scan"] = 19
        self.assertTrue(module._should_force_full_scan(packet, flow_state))

        # Reset count but exceed payload trigger
        flow_state["packets_since_last_scan"] = 0
        flow_state["cumulative_bytes"] = 10240
        self.assertTrue(module._should_force_full_scan(packet, flow_state))


if __name__ == "__main__":
    unittest.main()
