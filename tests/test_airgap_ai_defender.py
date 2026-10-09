import hashlib
import builtins
import importlib.util
import io
import json
import logging
import os
import pathlib
import queue
import runpy
import shutil
import socket
import struct
import tempfile
import time
import unittest
import warnings
from typing import Any
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "airgap_ai_defender.py"

spec = importlib.util.spec_from_file_location("airgap_ai_defender", MODULE_PATH)
assert spec is not None and spec.loader is not None, "Failed to load spec or loader"
module: Any = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AirgapSecurityHelpersTest(unittest.TestCase):
    def test_torch_stub_never_uses_pickle_fallback(self):
        original_import = builtins.__import__

        def without_torch(name, *args, **kwargs):
            if name == "torch" or name.startswith("torch."):
                raise ImportError("torch deliberately unavailable in this test")
            return original_import(name, *args, **kwargs)

        fallback_spec = importlib.util.spec_from_file_location(
            "airgap_ai_defender_without_torch", MODULE_PATH,
        )
        assert fallback_spec is not None and fallback_spec.loader is not None
        fallback_module: Any = importlib.util.module_from_spec(fallback_spec)
        with mock.patch("builtins.__import__", side_effect=without_torch):
            fallback_spec.loader.exec_module(fallback_module)

        with mock.patch.object(
            fallback_module.pickle, "load", side_effect=AssertionError("pickle.load called"),
        ), mock.patch.object(
            fallback_module.pickle, "dump", side_effect=AssertionError("pickle.dump called"),
        ):
            with self.assertRaisesRegex(RuntimeError, "PyTorch"):
                fallback_module.torch.load(io.BytesIO(b"unsafe"), weights_only=True)
            with self.assertRaisesRegex(RuntimeError, "PyTorch"):
                fallback_module.torch.load(io.BytesIO(b"unsafe"), weights_only=False)
            with self.assertRaisesRegex(RuntimeError, "PyTorch"):
                fallback_module.torch.save({}, io.BytesIO())

    def test_ignore_model_hash_is_refused_without_torch(self):
        with mock.patch.object(module, "TORCH_AVAILABLE", False), \
             mock.patch.object(module, "_merge_runtime_config", return_value={}), \
             mock.patch("sys.argv", ["airgap_ai_defender.py", "--ignore-model-hash"]):
            with self.assertRaises(SystemExit) as error:
                module.main()
        self.assertEqual(error.exception.code, 2)

    def test_capset_rejects_ids_outside_its_v3_abi(self):
        with mock.patch.object(module.platform, "system", return_value="Linux"):
            self.assertFalse(module._set_linux_capabilities(permitted={64}))

    def test_privilege_drop_stops_when_capability_restriction_fails(self):
        account = mock.Mock(pw_uid=65534, pw_gid=65534)
        with mock.patch.object(module.platform, "system", return_value="Linux"), \
             mock.patch.object(module.pwd, "getpwnam", return_value=account), \
             mock.patch.object(module.os, "geteuid", return_value=0), \
             mock.patch.object(module.os, "setgroups"), \
             mock.patch.object(module.os, "setgid"), \
             mock.patch.object(module.os, "setuid"), \
             mock.patch.object(module, "_call_prctl", return_value=0) as prctl, \
             mock.patch.object(
                 module, "_set_linux_capabilities", side_effect=[False, True],
             ) as capset:
            self.assertFalse(
                module._drop_to_user("nobody", preserve_caps={module._CAP_NET_RAW}),
            )

        self.assertEqual(capset.call_count, 2)
        self.assertEqual(prctl.call_args_list[-1], mock.call(8, 0, 0, 0, 0))

    def test_runtime_config_sets_parser_defaults_and_cli_can_override(self):
        config = {
            "interface": "wg0",
            "ram_limit": 1500,
            "drive_id": "local-folder",
            "colab_endpoint": "https://colab.example.test/rsi",
            "ignore_model_hash": True,
            "compact_log": True,
            "mode": "RSI",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = pathlib.Path(temp_dir) / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            loaded = module._load_runtime_config(str(config_path))

        args = module._build_argument_parser(loaded).parse_args([])
        self.assertEqual(args.interface, "wg0")
        self.assertEqual(args.max_memory_mb, 1500)
        self.assertEqual(args.drive_id, "local-folder")
        self.assertTrue(args.ignore_model_hash)
        self.assertTrue(args.compact_log)
        self.assertEqual(args.mode, "RSI")

        overridden = module._build_argument_parser(loaded).parse_args([
            "--interface", "eth0", "--ram-limit", "900",
            "--no-ignore-model-hash", "--no-compact-log", "--mode", "normal",
        ])
        self.assertEqual(overridden.interface, "eth0")
        self.assertEqual(overridden.max_memory_mb, 900)
        self.assertFalse(overridden.ignore_model_hash)
        self.assertFalse(overridden.compact_log)

    def test_panel_config_overrides_runtime_config_without_discarding_other_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_path = pathlib.Path(temp_dir) / "config.json"
            panel_path = pathlib.Path(temp_dir) / "panel-config.json"
            runtime_path.write_text(json.dumps({
                "interface": "eth0",
                "drive_id": "folder-id",
                "colab_endpoint": "https://colab.example.test/rsi",
            }), encoding="utf-8")
            panel_path.write_text(json.dumps({
                "interface": "wg0",
                "ram_limit": 900,
            }), encoding="utf-8")

            config = module._merge_runtime_config(str(runtime_path), str(panel_path))

        self.assertEqual(config["interface"], "wg0")
        self.assertEqual(config["ram_limit"], 900)
        self.assertEqual(config["drive_id"], "folder-id")
        self.assertEqual(config["colab_endpoint"], "https://colab.example.test/rsi")

    def test_map_mode_config_accepts_only_the_three_supported_modes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = pathlib.Path(temp_dir) / "panel-config.json"
            for mode in (0, 1, 2):
                config_path.write_text(json.dumps({"map_mode": mode}), encoding="utf-8")
                self.assertEqual(module._load_runtime_config(str(config_path))["map_mode"], mode)

            config_path.write_text(json.dumps({"map_mode": True}), encoding="utf-8")
            self.assertNotIn("map_mode", module._load_runtime_config(str(config_path)))

    def test_usb_guard_config_accepts_only_integer_toggle_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = pathlib.Path(temp_dir) / "panel-config.json"
            for enabled in (0, 1):
                config_path.write_text(json.dumps({"usb_guard_enabled": enabled}), encoding="utf-8")
                self.assertEqual(
                    module._load_runtime_config(str(config_path))["usb_guard_enabled"],
                    enabled,
                )

            for invalid in (True, 2, "1"):
                config_path.write_text(json.dumps({"usb_guard_enabled": invalid}), encoding="utf-8")
                self.assertNotIn(
                    "usb_guard_enabled",
                    module._load_runtime_config(str(config_path)),
                )

    def test_secure_tunnel_config_accepts_only_integer_toggle_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = pathlib.Path(temp_dir) / "panel-config.json"
            for enabled in (0, 1):
                config_path.write_text(
                    json.dumps({"secure_tunnel_enabled": enabled}), encoding="utf-8",
                )
                self.assertEqual(
                    module._load_runtime_config(str(config_path))["secure_tunnel_enabled"],
                    enabled,
                )

            for invalid in (True, 2, "1"):
                config_path.write_text(
                    json.dumps({"secure_tunnel_enabled": invalid}), encoding="utf-8",
                )
                self.assertNotIn(
                    "secure_tunnel_enabled",
                    module._load_runtime_config(str(config_path)),
                )

    def test_memory_guard_config_accepts_only_integer_toggle_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = pathlib.Path(temp_dir) / "panel-config.json"
            for enabled in (0, 1):
                config_path.write_text(
                    json.dumps({"memory_guard_enabled": enabled}), encoding="utf-8",
                )
                self.assertEqual(
                    module._load_runtime_config(str(config_path))["memory_guard_enabled"],
                    enabled,
                )

            for invalid in (True, 2, "1"):
                config_path.write_text(
                    json.dumps({"memory_guard_enabled": invalid}), encoding="utf-8",
                )
                self.assertNotIn(
                    "memory_guard_enabled",
                    module._load_runtime_config(str(config_path)),
                )

    def test_usb_guest_threat_uses_iproute2_barrier_but_scan_error_does_not(self):
        device = mock.Mock(device_id="1-2", vendor_id="1234", product_id="abcd")
        interfaces = ["eth0", "wlan0"]
        with mock.patch.object(module, "discover_available_interfaces", return_value=interfaces), \
             mock.patch.object(module, "disable_network_interfaces", return_value=True) as barrier, \
             mock.patch.object(
                 module.mk1_secure_transport, "request_transport_state", return_value=True,
             ) as key_wipe:
            module._usb_scan_threat_response(device, "error", interfaces)
            barrier.assert_not_called()

            module._usb_scan_threat_response(device, "threat", interfaces, "/tmp/tunnel.sock")

        barrier.assert_called_once_with(interfaces)
        key_wipe.assert_called_once_with("/tmp/tunnel.sock", False)

    def test_usb_guard_is_a_separate_privileged_worker_only_in_full_isolation(self):
        processes = [mock.Mock(), mock.Mock(), mock.Mock()]
        with mock.patch.object(module, "_PRIVILEGED_AGENT_ACTIVE", False), \
             mock.patch.object(module, "_PRIVILEGED_STOP_EVENT", mock.Mock()), \
             mock.patch.object(module, "_PRIVILEGED_COMMAND_PROCESS", None), \
             mock.patch.object(module, "_PRIVILEGED_CAPTURE_PROCESS", None), \
             mock.patch.object(module, "_PRIVILEGED_USB_PROCESS", None), \
             mock.patch.object(module, "_PANEL_FULL_ISOLATION", True), \
             mock.patch.object(module.platform, "system", return_value="Linux"), \
             mock.patch.object(module.os, "geteuid", return_value=0), \
             mock.patch.object(module, "discover_available_interfaces", return_value=["eth0"]), \
             mock.patch.object(module.multiprocessing, "Process", side_effect=processes) as process_factory:
            module._ensure_privileged_agent(
                "eth0", 500, "/tmp/mk1", False, panel_config_path="ai_data/panel-config.json",
            )

        self.assertEqual(process_factory.call_count, 3)
        self.assertIs(process_factory.call_args_list[2].kwargs["target"], module._usb_guard_process_main)
        self.assertEqual(processes[2].start.call_count, 1)

    def test_threat_map_telemetry_runs_after_the_defense_decision(self):
        call_order = []
        with mock.patch.object(module, "_KILL_SWITCH_TRIGGERED", False), \
             mock.patch.object(module, "_BACKDOOR_RISK_SCORE", 0.0), \
             mock.patch.object(module, "maybe_log_crypto_markers"), \
             mock.patch.object(module, "inspect_packet_pipeline", return_value={
                 "block": True, "stage": "dpi", "score": 0.9,
             }), \
             mock.patch.object(
                 module, "evaluate_threat_state",
                 side_effect=lambda *args, **kwargs: call_order.append("defense") or True,
             ), \
             mock.patch.object(
                 module, "_publish_threat_map_event",
                 side_effect=lambda *args, **kwargs: call_order.append("map"),
             ):
            module.handle_packet_event(
                b"packet", "eth0", dry_run=True, dpi_result={"suspicious": True},
            )

        self.assertEqual(call_order, ["defense", "map"])

    def test_panel_status_is_atomic_private_and_reports_isolation_alert(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(module, "_BACKDOOR_RISK_SCORE", 0.8), \
             mock.patch.object(module, "_LAST_THREAT_SCORE", 0.99), \
             mock.patch.object(module, "_KILL_SWITCH_TRIGGERED", True), \
             mock.patch.object(module.mk1_memory_guard, "is_enabled", return_value=True):
            module._write_panel_status(
                temp_dir, 12.5, 42, "Normal", True, state="STOPPED",
            )
            status_path = pathlib.Path(temp_dir) / "panel-status.txt"
            content = status_path.read_text(encoding="ascii")
            status_mode = status_path.stat().st_mode & 0o777
            remaining_temporary_files = list(pathlib.Path(temp_dir).glob(".panel-status.*.tmp"))

        self.assertIn("state=STOPPED\n", content)
        self.assertIn("packets_per_second=12.50\n", content)
        self.assertIn("packets_total=42\n", content)
        self.assertIn("isolation_active=1\n", content)
        self.assertIn("memory_guard_active=1\n", content)
        self.assertIn("alert=AIRGAP\n", content)
        self.assertEqual(status_mode, 0o600)
        self.assertEqual(remaining_temporary_files, [])

    def test_airgap_closes_only_the_panel_process_in_its_ancestry(self):
        ancestor = mock.Mock(pid=4321)
        process = mock.Mock()
        process.parents.return_value = [ancestor]
        with mock.patch.object(module, "_PANEL_PARENT_PID", 4321), \
             mock.patch.object(module.psutil, "Process", return_value=process), \
             mock.patch.object(module.os, "kill") as kill:
            module._close_panel_after_airgap()

        kill.assert_called_once_with(4321, module._signal_module.SIGTERM)

        process.parents.return_value = [mock.Mock(pid=1234)]
        with mock.patch.object(module, "_PANEL_PARENT_PID", 4321), \
             mock.patch.object(module.psutil, "Process", return_value=process), \
             mock.patch.object(module.os, "kill") as kill:
            module._close_panel_after_airgap()

        kill.assert_not_called()

    def test_panel_full_isolation_requires_every_network_interface_to_stop(self):
        with mock.patch.object(module.platform, "system", return_value="Linux"), \
             mock.patch.object(module, "_run_command_with_sudo", return_value=True) as run_command:
            self.assertTrue(module._disable_all_network_interfaces(["eth0", "wlan0", "lo"]))

        self.assertEqual(
            [call.args[0] for call in run_command.call_args_list],
            [
                ["ip", "link", "set", "dev", "eth0", "down"],
                ["ip", "link", "set", "dev", "wlan0", "down"],
            ],
        )

        with mock.patch.object(module.platform, "system", return_value="Linux"), \
             mock.patch.object(module, "_run_command_with_sudo", side_effect=[True, False]) as run_command:
            self.assertFalse(module._disable_all_network_interfaces(["eth0", "wlan0"]))

        self.assertEqual(run_command.call_count, 2)

    def test_panel_full_isolation_stops_all_nics_before_other_containment_work(self):
        with mock.patch.object(module, "_PANEL_FULL_ISOLATION", True), \
             mock.patch.object(module, "_disable_all_network_interfaces", return_value=True) as stop_all, \
             mock.patch.object(module, "_close_panel_after_airgap") as close_panel, \
             mock.patch.object(module, "profile_environment", side_effect=AssertionError("slow follow-up must not run")), \
             mock.patch.object(module, "execute_generated_payload", side_effect=AssertionError("fallback must not run")):
            module.execute_kill_switch("eth0", dry_run=False, available_interfaces=["eth0", "wlan0"])

        stop_all.assert_called_once_with(["eth0", "wlan0"])
        close_panel.assert_called_once_with()

    def test_root_privilege_drop_uses_sudo_invoking_user(self):
        passwd_entry = mock.Mock(pw_name="workspace-user")
        with mock.patch.object(module.platform, "system", return_value="Linux"), \
             mock.patch.object(module.os, "geteuid", return_value=0), \
             mock.patch.object(module.pwd, "getpwuid", return_value=passwd_entry), \
             mock.patch.dict(module.os.environ, {"SUDO_UID": "1000"}, clear=False), \
             mock.patch.object(module, "_drop_to_user", return_value=True) as drop_user:
            self.assertTrue(module._drop_privileges_if_possible())

        drop_user.assert_called_once_with("workspace-user", preserve_caps=None)

    def test_compact_log_filter_hides_routine_warnings_and_keeps_high_scores(self):
        compact_filter = module.CompactLogFilter()
        routine = logging.LogRecord("test", logging.WARNING, "test.py", 1, "routine warning", (), None)
        high_score = logging.LogRecord("test", logging.WARNING, "test.py", 1, "anomaly score=0.91", (), None)
        error = logging.LogRecord("test", logging.ERROR, "test.py", 1, "request failed", (), None)
        self.assertFalse(compact_filter.filter(routine))
        self.assertTrue(compact_filter.filter(high_score))
        self.assertTrue(compact_filter.filter(error))

    def test_compact_logging_is_enabled_by_default_for_imported_module(self):
        root_logger = logging.getLogger()
        filter_found = any(isinstance(item, module.CompactLogFilter) for handler in root_logger.handlers for item in handler.filters)
        self.assertTrue(filter_found)

    def test_compact_status_contains_resource_risk_and_connection_state(self):
        status = module._format_compact_status(252, 1500, 4.5, 0.05, "Connected", "RSI", True)
        self.assertEqual(
            status,
            "[STATUS] RAM: 252MB/1500MB | Swap: 4.5MB | Score: 0.05 | Colab: Connected | Model: Disabled | Mode: RSI (Dry-Run)",
        )

    def test_derive_cloud_model_urls_from_rsi_endpoint(self):
        self.assertEqual(
            module._derive_cloud_model_urls("https://colab.example.test/api/rsi"),
            (
                "https://colab.example.test/api/model",
                "https://colab.example.test/api/model.sha256",
            ),
        )
        self.assertIsNone(module._derive_cloud_model_urls("http://colab.example.test/rsi"))

    def test_sync_cloud_model_verifies_hash_replaces_atomically_and_queues_state(self):
        model = module.LightweightMultiTaskAI(input_dim=10)
        artifact = io.BytesIO()
        module.torch.save(model.state_dict(), artifact)
        model_bytes = artifact.getvalue()
        expected_hash = hashlib.sha256(model_bytes).hexdigest()
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = pathlib.Path(temp_dir) / "cloud_base_model.pth"
            with mock.patch.dict(
                module.os.environ, {"COLAB_RSI_PQ_PUBLIC_KEY_SHA256": "a" * 64},
            ), mock.patch.object(
                module.mk1_secure_transport, "encrypted_request",
                side_effect=[f"{expected_hash} cloud_base_model.pth".encode("ascii"), model_bytes],
            ) as secure_request:
                result = module.sync_cloud_model(
                    "https://colab.example.test/model",
                    "https://colab.example.test/model.sha256",
                    str(model_path),
                    token="test-token",
                )

            self.assertTrue(result["updated"])
            self.assertEqual(hashlib.sha256(model_path.read_bytes()).hexdigest(), expected_hash)
            sidecar_path = pathlib.Path(str(model_path) + ".sha256")
            self.assertEqual(sidecar_path.read_text(encoding="utf-8").split()[0], expected_hash)
            self.assertEqual(secure_request.call_count, 2)
            self.assertEqual(secure_request.call_args_list[0].args[2], {"action": "model_hash"})
            self.assertEqual(secure_request.call_args_list[1].args[2], {"action": "model"})
            self.assertEqual(secure_request.call_args_list[0].args[4], "a" * 64)
            self.assertEqual(secure_request.call_args_list[0].args[3], "test-token")
            self.assertEqual(module._MODEL_SYNC_STATUS, "Updated")
            with module._MODEL_RELOAD_LOCK:
                self.assertIsNotNone(module._PENDING_CLOUD_STATE)
            applied_model = module.LightweightMultiTaskAI(input_dim=10)
            self.assertTrue(module._apply_pending_cloud_model(applied_model))
            self.assertEqual(module._MODEL_SYNC_STATUS, "Loaded")
            self.assertEqual(list(pathlib.Path(temp_dir).glob("*.tmp")), [])
            self.assertEqual(list(pathlib.Path(temp_dir).glob(".model-hash-*.tmp")), [])

    def test_sync_cloud_model_rejects_hash_mismatch_without_replacing_existing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = pathlib.Path(temp_dir) / "cloud_base_model.pth"
            model_path.write_bytes(b"existing-model")
            with mock.patch.dict(
                module.os.environ, {"COLAB_RSI_PQ_PUBLIC_KEY_SHA256": "a" * 64},
            ), mock.patch.object(
                module.mk1_secure_transport, "encrypted_request",
                side_effect=[f"{'0' * 64} cloud_base_model.pth".encode("ascii"), b"not-a-model"],
            ):
                result = module.sync_cloud_model(
                    "https://colab.example.test/model",
                    "https://colab.example.test/model.sha256",
                    str(model_path),
                )

            self.assertFalse(result["updated"])
            self.assertEqual(model_path.read_bytes(), b"existing-model")
            self.assertEqual(module._MODEL_SYNC_STATUS, "Failed")
            self.assertEqual(list(pathlib.Path(temp_dir).glob(".cloud-model-*.tmp")), [])

    def test_sync_cloud_model_queues_matching_local_model_for_application(self):
        model = module.LightweightMultiTaskAI(input_dim=10)
        artifact = io.BytesIO()
        module.torch.save(model.state_dict(), artifact)
        model_bytes = artifact.getvalue()
        expected_hash = hashlib.sha256(model_bytes).hexdigest()
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = pathlib.Path(temp_dir) / "cloud_base_model.pth"
            model_path.write_bytes(model_bytes)
            with mock.patch.dict(
                module.os.environ, {"COLAB_RSI_PQ_PUBLIC_KEY_SHA256": "a" * 64},
            ), mock.patch.object(
                module.mk1_secure_transport, "encrypted_request",
                return_value=f"{expected_hash} cloud_base_model.pth".encode("ascii"),
            ) as secure_request:
                result = module.sync_cloud_model(
                    "https://colab.example.test/model",
                    "https://colab.example.test/model.sha256",
                    str(model_path),
                )

            self.assertFalse(result["updated"])
            self.assertEqual(result["reason"], "already current")
            self.assertEqual(secure_request.call_count, 1)
            with module._MODEL_RELOAD_LOCK:
                self.assertIsNone(module._PENDING_CLOUD_STATE)

    def test_sync_cloud_model_fails_closed_without_pqc_key_pin(self):
        with mock.patch.dict(module.os.environ, {}, clear=True), mock.patch.object(
            module.mk1_secure_transport, "encrypted_request",
        ) as secure_request:
            result = module.sync_cloud_model(
                "https://colab.example.test/model",
                "https://colab.example.test/model.sha256",
                "unused-model.pth",
            )

        self.assertFalse(result["updated"])
        self.assertEqual(result["reason"], "PQC public-key pin required")
        secure_request.assert_not_called()

    def test_head_b_maps_benign_and_threat_labels_with_balanced_weights(self):
        targets, weights = module._head_b_targets([0, 0, 0, 1])

        torch = module.torch
        torch.testing.assert_close(
            targets.reshape(-1), torch.tensor([1.0, 1.0, 1.0, 0.0]),
        )
        torch.testing.assert_close(
            weights.reshape(-1), torch.tensor([2.0 / 3.0, 2.0 / 3.0, 2.0 / 3.0, 2.0]),
        )

    def test_reviewed_benign_feedback_only_softens_soft_ai_score(self):
        self.assertEqual(module._adjust_soft_ai_score(0.90, 1.0, reviewed=False), 0.90)
        self.assertAlmostEqual(module._adjust_soft_ai_score(0.90, 1.0, reviewed=True), 0.675)
        self.assertEqual(module._adjust_soft_ai_score(0.96, 1.0, reviewed=True), 0.96)

    def test_reviewed_head_b_can_clear_borderline_ai_only_detection(self):
        class Model:
            def __call__(self, _inputs):
                torch = module.torch
                return torch.zeros((1, 2)), torch.tensor([[0.99]]), torch.zeros((1, 1))

        features = [1.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0, 0.0, 0.5]
        with mock.patch.object(module, "_HEAD_B_REVIEWED", True), \
             mock.patch.object(module, "parse_packet_transport", return_value=None), \
             mock.patch.object(module, "analyze_packet_security_markers", return_value=[]), \
             mock.patch.object(module, "_compute_behavioral_signature_score", return_value=0.0), \
             mock.patch.object(module, "_compute_unknown_behavior_score", return_value=0.0):
            result = module.inspect_packet_pipeline(
                b"x" * 64, "lo", model=Model(), feature_vector=features,
                dpi_result={"suspicious": False, "findings": []},
            )

        self.assertFalse(result["block"])
        self.assertNotEqual(result["stage"], "ai")

    def test_selected_feature_capture_is_bounded_atomic_and_feature_only(self):
        record = {"features": [0.25] * 10, "label": 0}
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(module, "_MAX_LOCAL_CAPTURE_BYTES", 180):
            written = module._append_selected_feature_records(
                temp_dir,
                [record, {"features": [2.0] * 10}, {"packet_bytes": b"must-not-save"}],
            )
            written_again = module._append_selected_feature_records(temp_dir, [record] * 8)
            capture_path = pathlib.Path(temp_dir) / "curated" / "selected_features.jsonl"
            content = capture_path.read_bytes()
            lines = content.decode("utf-8").splitlines()
            loaded = [json.loads(line) for line in lines]

        self.assertEqual(written, 1)
        self.assertEqual(written_again, 8)
        self.assertLessEqual(len(content), 180)
        self.assertTrue(loaded)
        self.assertTrue(all(set(item) == {"features", "label"} for item in loaded))
        self.assertNotIn(b"must-not-save", content)
        self.assertEqual(list(capture_path.parent.glob("*.tmp")), [])

    def test_rsi_payload_includes_selected_feature_capture_but_not_raw_packet_data(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            curated_dir = pathlib.Path(temp_dir) / "curated"
            curated_dir.mkdir()
            (curated_dir / "selected_features.jsonl").write_text(
                json.dumps({"features": [0.1] * 10, "label": 0}) + "\n",
                encoding="utf-8",
            )
            payload = module._build_rsi_payload(module.LightweightMultiTaskAI(input_dim=10), temp_dir)

        self.assertEqual(payload["curated_data"]["records"], [{"features": [0.1] * 10, "label": 0}])
        self.assertTrue(payload["curated_data"]["contents_uploaded"])
        self.assertNotIn("packet_bytes", json.dumps(payload))
        self.assertEqual(set(payload), {"task", "curated_data", "training", "submitted_at"})
        self.assertEqual(set(payload["curated_data"]), {"records", "contents_uploaded"})

    def test_rsi_payload_includes_only_explicit_reviewed_labels_from_feedback_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            curated_dir = pathlib.Path(temp_dir) / "curated"
            curated_dir.mkdir()
            feedback_path = curated_dir / "reviewed_feedback.jsonl"
            feedback_path.write_text("\n".join([
                json.dumps({"features": [0.1] * 10, "label": 0}),
                json.dumps({"features": [0.9] * 10, "label": 1}),
            ]) + "\n", encoding="utf-8")
            payload = module._build_rsi_payload(module.LightweightMultiTaskAI(input_dim=10), temp_dir)

        self.assertEqual(
            [record["label"] for record in payload["curated_data"]["records"]],
            [0, 1],
        )

    def test_module_import_does_not_autoinstall_dependencies(self):
        with mock.patch.object(module.importlib.util, "find_spec", return_value=None), \
             mock.patch.object(module.subprocess, "run", return_value=mock.Mock(returncode=1)) as run:
            runpy.run_path(str(MODULE_PATH), run_name="airgap_ai_defender_autoinstall_regression")

        self.assertEqual(run.call_count, 0)

    def test_ensure_dependencies_uses_cpu_torch_and_continues_when_install_fails(self):
        with mock.patch.object(module.importlib.util, "find_spec", return_value=None), \
             mock.patch.object(module.subprocess, "run", return_value=mock.Mock(returncode=1)) as run:
            available = module.ensure_dependencies()

        self.assertEqual(available, {"torch": False, "psutil": False, "cryptography": False})
        torch_command = run.call_args_list[0].args[0]
        self.assertIn("--extra-index-url", torch_command)
        self.assertIn("https://download.pytorch.org/whl/cpu", torch_command)
        self.assertIn("300", torch_command)
        self.assertEqual(run.call_args.kwargs["timeout"], 1800)

    def test_load_raw_data_from_files_yields_bounded_json_and_jsonl_batches(self):
        records = [
            {"features": [str(value) for value in range(10)] + [99]}
            for _ in range(5)
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = pathlib.Path(temp_dir) / "records.json"
            jsonl_path = pathlib.Path(temp_dir) / "records.jsonl"
            json_path.write_text(json.dumps(records[:3]), encoding="utf-8")
            jsonl_path.write_text("".join(json.dumps(item) + "\n" for item in records[3:]), encoding="utf-8")

            batches = list(module.load_raw_data_from_files([json_path, jsonl_path], batch_size=2))

        self.assertEqual([len(batch) for batch in batches], [2, 2, 1])
        self.assertEqual(batches[0][0]["features"], [float(value) for value in range(10)])

    def test_load_raw_data_from_files_stops_at_sample_limit(self):
        records = [{"features": [float(value)] * 10} for value in range(6)]
        with tempfile.TemporaryDirectory() as temp_dir:
            jsonl_path = pathlib.Path(temp_dir) / "records.jsonl"
            jsonl_path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
            batches = list(module.load_raw_data_from_files([jsonl_path], batch_size=2, max_samples=3))

        self.assertEqual([len(batch) for batch in batches], [2, 1])

    def test_load_raw_data_preserves_labels_only_for_reviewed_sources(self):
        record = {"features": [0.2] * 10, "label": 1}
        with tempfile.TemporaryDirectory() as temp_dir:
            jsonl_path = pathlib.Path(temp_dir) / "reviewed.jsonl"
            jsonl_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            untrusted = list(module.load_raw_data_from_files([jsonl_path], batch_size=1))
            reviewed = list(module.load_raw_data_from_files(
                [jsonl_path], batch_size=1, preserve_labels=True,
            ))

        self.assertEqual(untrusted, [[{"features": [0.2] * 10}]])
        self.assertEqual(reviewed, [[{"features": [0.2] * 10, "label": 1}]])

    def test_download_from_gdrive_folder_downloads_only_size_verified_data(self):
        payload = json.dumps({"features": [0.0] * 10}) + "\n"
        candidate = mock.Mock(id="file-id", path="dataset/sample.jsonl")
        response = mock.Mock(status_code=200, headers={
            "Content-Length": str(len(payload.encode("utf-8"))),
            "Content-Type": "application/json",
        })
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(module.mk1_secure_transport, "require_wireguard_full_tunnel", return_value="wg0"), \
             mock.patch.object(module, "GDOWN_AVAILABLE", True), \
             mock.patch.object(module.gdown, "download_folder", return_value=[candidate]) as list_folder, \
             mock.patch.object(module.requests, "head", return_value=response) as head_request, \
             mock.patch.object(
                 module.gdown,
                 "download",
                 side_effect=lambda id, output, **kwargs: pathlib.Path(output).write_text(payload, encoding="utf-8"),
             ) as download_file:
            downloaded = module.download_from_gdrive_folder("folder-id", temp_dir)
            list_folder.assert_called_once()
            self.assertTrue(list_folder.call_args.kwargs["skip_download"])
            self.assertEqual(list_folder.call_args.kwargs["timeout"], (30, 120))
            self.assertEqual(list_folder.call_args.kwargs["retries"], 4)
            self.assertEqual(head_request.call_args.kwargs["timeout"], (30, 120))
            download_file.assert_called_once()
            self.assertEqual(download_file.call_args.kwargs["timeout"], (30, 300))
            self.assertEqual(download_file.call_args.kwargs["retries"], 4)
            self.assertEqual(len(downloaded), 1)
            self.assertEqual(pathlib.Path(downloaded[0]).read_text(encoding="utf-8"), payload)

    def test_drive_size_check_timeout_is_skipped_safely(self):
        candidate = mock.Mock(id="slow-file", path="dataset/slow.jsonl")
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(module.mk1_secure_transport, "require_wireguard_full_tunnel", return_value="wg0"), \
             mock.patch.object(module, "GDOWN_AVAILABLE", True), \
             mock.patch.object(module.gdown, "download_folder", return_value=[candidate]), \
             mock.patch.object(module.requests, "head", side_effect=module.requests.ReadTimeout("slow response")) as head_request, \
             mock.patch.object(module.gdown, "download") as download:
            result = module.download_from_gdrive_folder("folder-id", temp_dir)

        self.assertEqual(result, [])
        self.assertEqual(head_request.call_count, 3)
        download.assert_not_called()

    def test_gdrive_retries_temporary_head_timeout(self):
        payload = json.dumps({"features": [0.0] * 10}) + "\n"
        candidate = mock.Mock(id="retry-file", path="dataset/retry.jsonl")
        response = mock.Mock(status_code=200, headers={
            "Content-Length": str(len(payload.encode("utf-8"))),
            "Content-Type": "application/json",
        })
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(module.mk1_secure_transport, "require_wireguard_full_tunnel", return_value="wg0"), \
             mock.patch.object(module, "GDOWN_AVAILABLE", True), \
             mock.patch.object(module.gdown, "download_folder", return_value=[candidate]), \
             mock.patch.object(
                 module.requests,
                 "head",
                 side_effect=[module.requests.ReadTimeout("temporary delay"), response],
             ) as head_request, \
             mock.patch.object(
                 module.gdown,
                 "download",
                 side_effect=lambda id, output, **kwargs: pathlib.Path(output).write_text(payload, encoding="utf-8"),
             ):
            downloaded = module.download_from_gdrive_folder("folder-id", temp_dir)

        self.assertEqual(head_request.call_count, 2)
        self.assertEqual(len(downloaded), 1)

    def test_gdrive_worker_uses_curated_data_when_drive_and_raw_data_are_unavailable(self):
        record = {"features": [0.0] * 10, "label": 0}
        with tempfile.TemporaryDirectory() as temp_dir:
            raw_dir = pathlib.Path(temp_dir) / "gdrive_raw"
            curated_dir = pathlib.Path(temp_dir) / "curated"
            raw_dir.mkdir()
            curated_dir.mkdir()
            curated_path = curated_dir / "curated_data.jsonl"
            curated_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with mock.patch.object(module, "ONI_MODE", False), \
                 mock.patch.object(module, "download_from_gdrive_folder", return_value=[]), \
                 mock.patch.object(module, "enter_maintenance_mode"), \
                 mock.patch.object(module, "exit_maintenance_mode"), \
                 mock.patch.object(module, "load_raw_data_from_files", return_value=iter([[record]])) as load_data, \
                 mock.patch.object(module, "_enqueue_training_batch") as enqueue, \
                 mock.patch.object(module.time, "sleep", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    module._gdrive_update_worker(None, None, "folder-id", temp_dir, 300)

        load_data.assert_called_once_with([str(curated_path)], batch_size=module._DATA_BATCH_SIZE)
        enqueue.assert_called_once_with([record])

    def test_process_names_do_not_change_behavior_score(self):
        info = {
            "name": "code",
            "exe": "/usr/share/code/code",
            "cmdline": ["code", "--type=renderer"],
            "cpu_percent": 30.0,
            "memory_percent": 10.0,
            "num_threads": 8,
        }
        features, score = module._vectorize_process_behavior(info)
        other_features, other_score = module._vectorize_process_behavior(dict(info, name="codecave"))
        self.assertEqual(features, other_features)
        self.assertEqual(score, other_score)

    def test_backdoor_scan_exempts_only_benign_development_connections(self):
        connections = [
            mock.Mock(status=module.psutil.CONN_ESTABLISHED, raddr=("127.0.0.1", 9222), laddr=("127.0.0.1", 50000)),
            mock.Mock(status=module.psutil.CONN_ESTABLISHED, raddr=("203.0.113.10", 443), laddr=("192.0.2.2", 50001)),
            mock.Mock(status=module.psutil.CONN_ESTABLISHED, raddr=("203.0.113.20", 4444), laddr=("192.0.2.2", 50002)),
        ]
        proc = mock.Mock()
        proc.info = {
            "pid": 42,
            "name": "code",
            "exe": "/usr/share/code/code",
            "cmdline": ["code", "curl | sh"],
            "cpu_percent": 30.0,
            "memory_percent": 10.0,
            "num_threads": 8,
        }
        proc.parent.return_value = None
        proc.net_connections.return_value = connections
        proc.connections = mock.Mock(side_effect=AssertionError("deprecated API must not be used"))
        with mock.patch.object(module.psutil, "process_iter", return_value=[proc]):
            findings = module.scan_for_backdoors()

        proc.net_connections.assert_called_once_with(kind="inet")
        proc.connections.assert_not_called()
        self.assertEqual(
            [finding["remote"] for finding in findings],
            ["203.0.113.20:4444"],
        )

    def test_vectorizer_reduces_score_for_development_process_with_only_benign_connections(self):
        info = {
            "name": "code",
            "cmdline": ["code", "curl | sh"],
            "cpu_percent": 30.0,
            "memory_percent": 10.0,
            "num_threads": 8,
        }
        _, baseline_score = module._vectorize_process_behavior(info)
        _, development_score = module._vectorize_process_behavior(dict(
            info,
            _connections=[
                mock.Mock(raddr=("127.0.0.1", 9222)),
                mock.Mock(raddr=("203.0.113.10", 443)),
            ],
        ))
        self.assertGreater(baseline_score, development_score)
        self.assertLess(development_score, 0.35)

    def test_process_connections_falls_back_without_deprecation_warning(self):
        proc = mock.Mock()
        proc.net_connections = None
        proc.connections.return_value = []
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = module._process_connections(proc)

        self.assertEqual(result, [])
        self.assertFalse(any(issubclass(item.category, DeprecationWarning) for item in caught))

    def test_parent_command_detection_uses_token_boundaries(self):
        self.assertFalse(module._is_suspicious_parent_command(
            "code --utility-sub-type=node.mojom.NodeService shellIntegration-bash.sh"
        ))
        self.assertFalse(module._is_suspicious_parent_command("bash --init-file /tmp/bashrc"))
        self.assertTrue(module._is_suspicious_parent_command("bash -c 'nc -l 9000'"))
        self.assertTrue(module._is_suspicious_parent_command("powershell.exe -EncodedCommand abc"))

    def test_process_event_monitor_does_not_whitelist_python_inline_code(self):
        with mock.patch.object(module, "_resolve_proc_executable", return_value="/usr/bin/python3"), \
             mock.patch.object(module, "_is_suspicious_executable_path", return_value=False):
            self.assertTrue(module._is_suspicious_process_command(1234, "python3 -c print('ready')"))

    def test_rsi_without_endpoint_completes_as_simulation(self):
        model = module.LightweightMultiTaskAI(input_dim=10)
        with mock.patch.dict(module.os.environ, {"COLAB_RSI_ENDPOINT": ""}), \
             mock.patch.object(module, "log") as log_mock:
            worker, completion, result = module._start_colab_rsi_request(model, ".", wait_for_result=True)

        self.assertIsNone(worker)
        self.assertTrue(completion.is_set())
        self.assertTrue(result["simulated"])
        self.assertTrue(any(
            call.args and "送信を完了しました" in call.args[0]
            for call in log_mock.info.call_args_list
        ))

    def test_rsi_refuses_remote_request_without_pqc_pin(self):
        model = module.LightweightMultiTaskAI(input_dim=10)
        records = [
            {"features": [0.1] * 10, "label": 0},
            {"features": [0.9] * 10, "label": 1},
        ]
        with mock.patch.dict(module.os.environ, {
            "COLAB_RSI_ENDPOINT": "https://colab.example.test/rsi",
            "COLAB_RSI_PQ_PUBLIC_KEY_SHA256": "",
            "COLAB_RSI_TOKEN": "test-token",
        }), mock.patch.object(module.mk1_secure_transport, "encrypted_request") as request:
            worker, completion, result = module._start_colab_rsi_request(
                model, ".", wait_for_result=True, records=records,
            )

        self.assertIsNone(worker)
        self.assertTrue(completion.is_set())
        self.assertTrue(result["rejected"])
        request.assert_not_called()

    def test_rsi_posts_only_selected_features_in_colab_api_schema(self):
        model = module.LightweightMultiTaskAI(input_dim=10)
        sent_payload = {}
        records = [
            {"features": [0.1] * 10, "label": 0, "packet_bytes": b"never-send"},
            {"features": [0.9] * 10, "label": 1},
        ]
        with mock.patch.dict(module.os.environ, {
            "COLAB_RSI_ENDPOINT": "https://colab.example.test/rsi",
            "COLAB_RSI_PQ_PUBLIC_KEY_SHA256": "a" * 64,
        }), mock.patch.object(
            module.mk1_secure_transport, "encrypted_request",
            side_effect=lambda _requests, _url, payload, _token, _pin:
                (sent_payload.update(payload) or b'{"accepted":true}'),
        ) as secure_request:
            worker, completion, result = module._start_colab_rsi_request(
                model, ".", wait_for_result=True, records=records, token="config-token",
            )

        self.assertTrue(completion.is_set())
        self.assertTrue(result["sent"])
        self.assertEqual(module._RSI_CONNECTION_STATUS, "Connected")
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        secure_request.assert_called_once()
        self.assertEqual(sent_payload["task"], "recursive_self_improvement")
        self.assertEqual(set(sent_payload), {"task", "curated_data", "training", "submitted_at"})
        self.assertEqual(set(sent_payload["curated_data"]), {"records", "contents_uploaded"})
        self.assertEqual(sent_payload["curated_data"]["records"], [
            {"features": [0.1] * 10, "label": 0},
            {"features": [0.9] * 10, "label": 1},
        ])
        self.assertEqual(sent_payload["training"]["epochs"], 1)
        self.assertTrue(sent_payload["curated_data"]["contents_uploaded"])
        self.assertEqual(secure_request.call_args.args[3], "config-token")
        self.assertEqual(secure_request.call_args.args[4], "a" * 64)
        self.assertNotIn("never-send", str(sent_payload))

    def test_rsi_refuses_to_send_single_class_feedback(self):
        model = module.LightweightMultiTaskAI(input_dim=10)
        records = [{"features": [0.1] * 10, "label": 0}]
        with mock.patch.dict(module.os.environ, {
            "COLAB_RSI_ENDPOINT": "https://colab.example.test/rsi",
            "COLAB_RSI_PQ_PUBLIC_KEY_SHA256": "a" * 64,
            "COLAB_RSI_TOKEN": "test-token",
        }), \
             mock.patch.object(module.mk1_secure_transport, "encrypted_request") as secure_request, \
             mock.patch.object(module, "log") as log_mock:
            worker, completion, result = module._start_colab_rsi_request(
                model, ".", wait_for_result=True, records=records,
            )

        self.assertIsNone(worker)
        self.assertTrue(completion.is_set())
        self.assertTrue(result["rejected"])
        secure_request.assert_not_called()
        log_mock.warning.assert_called_once()

    def test_rsi_connection_failure_returns_local_fallback(self):
        model = module.LightweightMultiTaskAI(input_dim=10)
        records = [
            {"features": [0.1] * 10, "label": 0},
            {"features": [0.9] * 10, "label": 1},
        ]
        with mock.patch.dict(module.os.environ, {
            "COLAB_RSI_ENDPOINT": "https://colab.example.test/rsi",
            "COLAB_RSI_PQ_PUBLIC_KEY_SHA256": "a" * 64,
            "COLAB_RSI_TOKEN": "test-token",
        }), \
             mock.patch.object(
                 module.mk1_secure_transport, "encrypted_request",
                 side_effect=module.requests.ConnectionError("offline"),
             ), \
             mock.patch.object(module, "log") as log_mock:
            worker, completion, result = module._start_colab_rsi_request(
                model, ".", wait_for_result=True, records=records,
            )
            worker.join(timeout=1)

        self.assertTrue(completion.is_set())
        self.assertFalse(result["sent"])
        self.assertEqual(module._RSI_CONNECTION_STATUS, "Failed")
        self.assertTrue(any("ローカル軽量処理を継続します" in call.args[0] for call in log_mock.error.call_args_list))

    def test_rsi_validation_uses_local_data_without_drive_fetch(self):
        record = {"features": [0.1] * 10}
        with tempfile.TemporaryDirectory() as temp_dir:
            curated_dir = pathlib.Path(temp_dir) / "curated"
            curated_dir.mkdir()
            (curated_dir / "curated_data.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
            feedback_path = curated_dir / "reviewed_feedback.jsonl"
            feedback_path.write_text("\n".join([
                json.dumps({"features": [0.2] * 10, "label": 0}),
                json.dumps({"features": [0.8] * 10, "label": 1}),
            ]) + "\n", encoding="utf-8")
            with mock.patch.object(module, "download_from_gdrive_folder") as download, \
                 mock.patch.object(module, "train_local_whitelist") as train:
                result = module._run_lightweight_training_validation(
                    temp_dir,
                    "folder-id",
                    max_samples=3,
                    model=module.LightweightMultiTaskAI(input_dim=10),
                    fetch_drive=False,
                )

        self.assertEqual(result, 0)
        download.assert_not_called()
        self.assertEqual(train.call_count, 2)
        self.assertEqual(train.call_args_list[1].args[2][0]["label"], 0)
        self.assertEqual(train.call_args_list[1].args[2][1]["label"], 1)

    def test_validation_prefers_local_data_before_drive_fetch(self):
        record = {"features": [0.1] * 10}
        with tempfile.TemporaryDirectory() as temp_dir:
            curated_dir = pathlib.Path(temp_dir) / "curated"
            curated_dir.mkdir()
            (curated_dir / "curated_data.jsonl").write_text(
                json.dumps(record) + "\n", encoding="utf-8",
            )
            with mock.patch.object(module, "download_from_gdrive_folder") as download, \
                 mock.patch.object(module, "train_local_whitelist") as train:
                result = module._run_lightweight_training_validation(
                    temp_dir,
                    "folder-id",
                    max_samples=1,
                    model=module.LightweightMultiTaskAI(input_dim=10),
                )

        self.assertEqual(result, 0)
        download.assert_not_called()
        train.assert_called_once()

    def test_validation_fetches_drive_data_when_no_local_data_exists(self):
        record = {"features": [0.1] * 10}
        with tempfile.TemporaryDirectory() as temp_dir:
            def download_to_local(_drive_id, dest_dir):
                raw_dir = pathlib.Path(dest_dir)
                raw_dir.mkdir(parents=True, exist_ok=True)
                (raw_dir / "sample.jsonl").write_text(
                    json.dumps(record) + "\n", encoding="utf-8",
                )

            with mock.patch.object(
                module, "download_from_gdrive_folder", side_effect=download_to_local,
            ) as download, mock.patch.object(module, "train_local_whitelist") as train:
                result = module._run_lightweight_training_validation(
                    temp_dir,
                    "folder-id",
                    max_samples=1,
                    model=module.LightweightMultiTaskAI(input_dim=10),
                )

        self.assertEqual(result, 0)
        download.assert_called_once_with("folder-id", os.path.join(temp_dir, "gdrive_raw"))
        train.assert_called_once()

    def test_training_queue_is_bounded(self):
        self.assertEqual(module._train_queue.maxsize, module._TRAIN_QUEUE_MAX_BATCHES)
        self.assertGreater(module._train_queue.maxsize, 0)

    def test_local_training_persists_and_restores_only_head_b(self):
        torch = module.torch
        with mock.patch.object(module, "_HEAD_B_REVIEWED_LABELS", set()), \
             mock.patch.object(module, "_HEAD_B_REVIEWED", False), \
             tempfile.TemporaryDirectory() as temp_dir:
            checkpoint_path = str(pathlib.Path(temp_dir) / "local_adaptation.pth")
            model = module.LightweightMultiTaskAI(input_dim=10)
            original_shared = model.shared_layer[0].weight.detach().clone()
            original_head_b = model.head_b[0].weight.detach().clone()
            optimizer = torch.optim.SGD(model.parameters(), lr=0.01)
            module.train_local_whitelist(
                model,
                optimizer,
                [{"features": [0.2] * 10}, {"features": [0.8] * 10}],
                checkpoint_path=checkpoint_path,
            )

            self.assertTrue(pathlib.Path(checkpoint_path).is_file())
            self.assertTrue(pathlib.Path(checkpoint_path + ".sha256").is_file())
            self.assertFalse(torch.equal(model.head_b[0].weight, original_head_b))

            restored_model = module.LightweightMultiTaskAI(input_dim=10)
            baseline_shared = restored_model.shared_layer[0].weight.detach().clone()
            self.assertTrue(module._load_local_adaptation(restored_model, checkpoint_path))
            torch.testing.assert_close(restored_model.head_b[0].weight, model.head_b[0].weight)
            torch.testing.assert_close(restored_model.head_b[0].bias, model.head_b[0].bias)
            torch.testing.assert_close(restored_model.shared_layer[0].weight, baseline_shared)
            torch.testing.assert_close(model.shared_layer[0].weight, original_shared)

    def test_local_feedback_checkpoint_marks_both_reviewed_classes(self):
        with mock.patch.object(module, "_HEAD_B_REVIEWED_LABELS", set()), \
             mock.patch.object(module, "_HEAD_B_REVIEWED", False), \
             tempfile.TemporaryDirectory() as temp_dir:
            checkpoint_path = str(pathlib.Path(temp_dir) / "local_adaptation.pth")
            model = module.LightweightMultiTaskAI(input_dim=10)
            optimizer = module.torch.optim.SGD(model.parameters(), lr=0.01)
            module.train_local_whitelist(model, optimizer, [
                {"features": [0.2] * 10, "label": 0},
                {"features": [0.8] * 10, "label": 1},
            ], checkpoint_path=checkpoint_path)

            restored_model = module.LightweightMultiTaskAI(input_dim=10)
            self.assertTrue(module._load_local_adaptation(restored_model, checkpoint_path))
            self.assertTrue(module._HEAD_B_REVIEWED)
            self.assertEqual(module._HEAD_B_REVIEWED_LABELS, {0, 1})

    def test_training_enqueue_retries_when_queue_is_full(self):
        original_queue = module._train_queue
        full_queue = mock.Mock()
        full_queue.put.side_effect = [queue.Full, None]
        try:
            module._train_queue = full_queue
            self.assertTrue(module._enqueue_training_batch([{"features": [0.0] * 10}], wait_timeout=0))
            self.assertEqual(full_queue.put.call_count, 2)
        finally:
            module._train_queue = original_queue

    def test_monitor_candidates_never_enqueue_training_batches(self):
        candidates = []
        duplicate_features = [0.5] * 10
        with mock.patch.object(module, "_enqueue_training_batch") as enqueue, \
             mock.patch.object(module, "_append_selected_feature_records") as persist:
            for _ in range(100):
                module._buffer_monitor_candidate(candidates, duplicate_features, 0.8)

        self.assertEqual(len(candidates), 100)
        self.assertTrue(all(item["features"] == duplicate_features for item in candidates))
        enqueue.assert_not_called()
        persist.assert_not_called()

    def test_curate_and_save_streams_training_batches(self):
        class Score:
            def __init__(self, value):
                self.value = value
            def item(self):
                return self.value

        class DummyModel:
            def eval(self):
                pass
            def __call__(self, features):
                return Score(0.5), Score(0.7), Score(0.1)

        raw_records = [{"features": [float(index)] * 10} for index in range(205)]
        received_batches = []
        with tempfile.TemporaryDirectory() as temp_dir:
            curated_path = module.curate_and_save(
                DummyModel(),
                (raw_records[index:index + 37] for index in range(0, len(raw_records), 37)),
                temp_dir,
                batch_callback=lambda batch: received_batches.append(list(batch)),
                batch_size=100,
            )
            with open(curated_path, encoding="utf-8") as handle:
                saved_count = sum(1 for _ in handle)

        self.assertEqual([len(batch) for batch in received_batches], [100, 100, 5])
        self.assertEqual(saved_count, 205)

    def test_memory_manager_skips_disk_eviction_without_aesgcm(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(module, "AESGCM", None):
            manager = module.MemoryManager(max_memory_mb=1, swap_dir=temp_dir)
            try:
                self.assertEqual(manager.evict_buffer([{"secret": "value"}]), 0)
                self.assertEqual(manager._offset, 0)
            finally:
                manager.cleanup()

    def test_memory_manager_falls_back_when_swap_dir_is_not_writable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            real_mkstemp = tempfile.mkstemp

            def mkstemp_with_permission_error(*args, **kwargs):
                if kwargs.get("dir") == temp_dir:
                    raise PermissionError("swap directory is not writable")
                return real_mkstemp(*args, **kwargs)

            with mock.patch.object(module.tempfile, "mkstemp", side_effect=mkstemp_with_permission_error):
                manager = module.MemoryManager(max_memory_mb=1, swap_dir=temp_dir)
            try:
                self.assertNotEqual(os.path.dirname(manager._swap_path), temp_dir)
                self.assertTrue(os.path.exists(manager._swap_path))
            finally:
                manager.cleanup()

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
                self.closed = False
            def settimeout(self, timeout):
                pass
            def bind(self, *args, **kwargs):
                return None
            def close(self):
                self.closed = True
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
        dummy_socket = DummySocket()
        original_queue = module._packet_queue
        original_last_pkt_time = module._last_pkt_time
        original_ema_delta = module._ema_delta
        with module._FLOW_CACHE_LOCK:
            original_flow_cache = module._FLOW_STATE_CACHE.copy()
            module._FLOW_STATE_CACHE.clear()
        try:
            module._packet_queue = q
            module._last_pkt_time = 100.0
            module._ema_delta = 0.1
            with mock.patch.object(module.socket, "socket", return_value=dummy_socket), \
                 mock.patch.object(module, "handle_packet_event"), \
                 mock.patch.object(module.time, "time", side_effect=[100.2, 100.2]):
                module._packet_capture_worker("eth0", DummyMemMgr(), True)
            feat, _ = q.get_nowait()
            self.assertAlmostEqual(feat[1], 0.11, places=5)
            self.assertTrue(dummy_socket.closed)
        finally:
            module._packet_queue = original_queue
            module._last_pkt_time = original_last_pkt_time
            module._ema_delta = original_ema_delta
            with module._FLOW_CACHE_LOCK:
                module._FLOW_STATE_CACHE.clear()
                module._FLOW_STATE_CACHE.update(original_flow_cache)

    def test_non_linux_capture_uses_simulation_without_opening_raw_socket(self):
        class StopAfterOnePacket:
            def __init__(self):
                self.waits = 0

            def is_set(self):
                return self.waits > 0

            def wait(self, timeout):
                self.waits += 1
                return False

        class DummyMemMgr:
            @staticmethod
            def get_usage_ratio():
                return 0.25

        capture_queue = queue.Queue(maxsize=4)
        original_queue = module._packet_queue
        try:
            module._packet_queue = capture_queue
            with mock.patch.object(module.platform, "system", return_value="Darwin"), \
                 mock.patch.object(module.socket, "socket", side_effect=AssertionError("raw socket must not be opened")), \
                 mock.patch.object(module, "analyze_dpi_payload", return_value={"suspicious": False}) as analyze, \
                 mock.patch.object(module, "handle_packet_event") as handle_event:
                module._packet_capture_worker("en0", DummyMemMgr(), False, StopAfterOnePacket())

            item = capture_queue.get_nowait()
            self.assertEqual(item.packet_bytes[12:14], struct.pack("!H", 0x0806))
            self.assertEqual(len(item.feature_vector), 10)
            self.assertEqual(item.feature_vector[9], 0.25)
            self.assertEqual(analyze.call_count, 1)
            self.assertTrue(handle_event.call_args.args[2])
        finally:
            module._packet_queue = original_queue

    def test_behavioral_score_uses_encrypted_traffic_histories_without_zero_division(self):
        originals = (
            list(module._TRAFFIC_ACTIVITY_HISTORY),
            list(module._PACKET_LENGTH_HISTORY),
            list(module._PACKET_INTERARRIVAL_HISTORY),
        )
        try:
            module._TRAFFIC_ACTIVITY_HISTORY.clear()
            module._TRAFFIC_ACTIVITY_HISTORY.extend([128] * 16)
            module._PACKET_LENGTH_HISTORY.clear()
            module._PACKET_LENGTH_HISTORY.extend([128] * 16)
            module._PACKET_INTERARRIVAL_HISTORY.clear()
            module._PACKET_INTERARRIVAL_HISTORY.extend([0.5] * 8)

            score = module._compute_behavioral_signature_score(
                b"\x00" * 128,
                {"dst_port": 443},
                {"protocols": ["TLS/SSL"]},
            )

            self.assertGreaterEqual(score, 0.35)
        finally:
            for history, values in zip(
                (module._TRAFFIC_ACTIVITY_HISTORY, module._PACKET_LENGTH_HISTORY, module._PACKET_INTERARRIVAL_HISTORY),
                originals,
            ):
                history.clear()
                history.extend(values)

    def test_composite_anomaly_score_weights_behavioral_metadata_highest(self):
        score = module._compute_composite_anomaly_score(
            rule_score=0.4,
            ai_score=0.4,
            math_score=0.4,
            unknown_score=0.4,
            behavior_score=0.8,
        )

        self.assertAlmostEqual(score, 0.62)

    def test_maintenance_mode_skips_threat_trigger_and_kill_switch_log(self):
        original_maintenance = module._MAINTENANCE_ACTIVE
        original_triggered = module._KILL_SWITCH_TRIGGERED
        original_last_trigger = module._LAST_KILL_SWITCH_TRIGGER
        original_counter = module._anomaly_counter
        original_learning_alert_time = module._LAST_LEARNING_ALERT_TIME
        try:
            module._MAINTENANCE_ACTIVE = True
            module._KILL_SWITCH_TRIGGERED = False
            module._LAST_KILL_SWITCH_TRIGGER = 0.0
            module._anomaly_counter = 0
            module._LAST_LEARNING_ALERT_TIME = 0.0
            with mock.patch.object(module, "execute_kill_switch") as kill_switch, \
                 mock.patch.object(module, "log") as log_mock, \
                 mock.patch.object(module.time, "monotonic", return_value=100.0):
                self.assertFalse(module.evaluate_threat_state("eth0", dry_run=False, score_a=0.99, backdoor_detected=True))
                kill_switch.assert_not_called()
                log_mock.critical.assert_not_called()
                log_mock.warning.assert_called_once()
                self.assertEqual(module._anomaly_counter, 0)
        finally:
            module._MAINTENANCE_ACTIVE = original_maintenance
            module._KILL_SWITCH_TRIGGERED = original_triggered
            module._LAST_KILL_SWITCH_TRIGGER = original_last_trigger
            module._anomaly_counter = original_counter
            module._LAST_LEARNING_ALERT_TIME = original_learning_alert_time

    def test_rsi_learning_mode_does_not_promote_backdoor_findings(self):
        original_rsi = module._RSI_MODE_ACTIVE
        original_risk = module._BACKDOOR_RISK_SCORE
        original_learning_alert_time = module._LAST_LEARNING_ALERT_TIME
        try:
            module._RSI_MODE_ACTIVE = True
            module._BACKDOOR_RISK_SCORE = 0.0
            module._LAST_LEARNING_ALERT_TIME = 0.0
            finding = {
                    "type": "external_connection",
                    "pid": 1,
                    "name": "code",
                    "remote": "127.0.0.1:9222",
                }
            with mock.patch.object(module, "evaluate_threat_state") as evaluate, \
                 mock.patch.object(module, "log") as log_mock, \
                 mock.patch.object(module.time, "monotonic", return_value=100.0):
                boost = module.apply_backdoor_findings([finding])
                module.apply_backdoor_findings([finding])
            self.assertEqual(boost, 0.0)
            self.assertEqual(module._BACKDOOR_RISK_SCORE, 0.0)
            evaluate.assert_not_called()
            log_mock.warning.assert_called_once()
        finally:
            module._RSI_MODE_ACTIVE = original_rsi
            module._BACKDOOR_RISK_SCORE = original_risk
            module._LAST_LEARNING_ALERT_TIME = original_learning_alert_time

    def test_self_protection_signal_requests_graceful_shutdown(self):
        handlers = {}
        with mock.patch.object(
            module._signal_module,
            "signal",
            side_effect=lambda signum, handler: handlers.setdefault(signum, handler),
        ):
            module._install_self_protection_handlers()

        with mock.patch.object(module, "evaluate_threat_state") as evaluate:
            with self.assertRaises(KeyboardInterrupt):
                handlers[module._signal_module.SIGINT](module._signal_module.SIGINT, None)

        evaluate.assert_not_called()

    def test_privileged_agent_survives_monitor_thread_start_failure(self):
        packet_thread = mock.Mock()
        monitor_thread = mock.Mock()
        monitor_thread.start.side_effect = RuntimeError("can't start new thread")
        manager = mock.Mock()
        stop_event = mock.Mock()
        stop_event.wait.side_effect = KeyboardInterrupt
        with (
            mock.patch.object(module._signal_module, "signal"),
            mock.patch.object(module.platform, "system", return_value="Linux"),
            mock.patch.object(module, "_drop_to_user"),
            mock.patch.object(module, "_PRIVILEGED_STOP_EVENT", stop_event),
            mock.patch.object(module, "MemoryManager", return_value=manager) as memory_manager_class,
            mock.patch.object(module.threading, "Thread", side_effect=[packet_thread, monitor_thread]),
            mock.patch.object(module, "log") as log_mock,
        ):
            module._privileged_agent_main("eth0", 128, "/tmp", True)

        packet_thread.start.assert_called_once()
        monitor_thread.start.assert_called_once()
        manager.cleanup.assert_called_once()
        swap_dir = memory_manager_class.call_args.kwargs["swap_dir"]
        self.assertTrue(swap_dir.startswith(tempfile.gettempdir()))
        self.assertFalse(os.path.exists(swap_dir))
        self.assertTrue(any("監視スレッドを開始できません" in str(call) for call in log_mock.warning.call_args_list))

    def test_privileged_agent_shutdown_is_cooperative(self):
        stop_event = mock.Mock()
        command_queue = mock.Mock()
        command_process = mock.Mock()
        capture_process = mock.Mock()
        command_process.is_alive.return_value = False
        capture_process.is_alive.return_value = False
        with mock.patch.object(module, "_PRIVILEGED_STOP_EVENT", stop_event, create=True), \
             mock.patch.object(module, "_command_queue", command_queue), \
             mock.patch.object(module, "_PRIVILEGED_COMMAND_PROCESS", command_process), \
             mock.patch.object(module, "_PRIVILEGED_CAPTURE_PROCESS", capture_process), \
             mock.patch.object(module, "_PRIVILEGED_AGENT_ACTIVE", True):
            module._shutdown_privileged_agent()

        stop_event.set.assert_called_once_with()
        command_queue.put.assert_called_once_with(None)
        command_process.join.assert_called_once()
        capture_process.join.assert_called_once()
        command_process.terminate.assert_not_called()
        capture_process.terminate.assert_not_called()

    def test_privileged_shutdown_swallows_permission_errors(self):
        stop_event = mock.Mock()
        command_queue = mock.Mock()
        command_process = mock.Mock()
        capture_process = mock.Mock()
        command_process.join.side_effect = PermissionError("operation not permitted")
        capture_process.join.side_effect = PermissionError("operation not permitted")
        command_process.is_alive.return_value = False
        capture_process.is_alive.return_value = False
        with mock.patch.object(module, "_PRIVILEGED_STOP_EVENT", stop_event), \
             mock.patch.object(module, "_command_queue", command_queue), \
             mock.patch.object(module, "_PRIVILEGED_COMMAND_PROCESS", command_process), \
             mock.patch.object(module, "_PRIVILEGED_CAPTURE_PROCESS", capture_process), \
             mock.patch.object(module, "_PRIVILEGED_AGENT_ACTIVE", True):
            module._shutdown_privileged_agent()

        stop_event.set.assert_called_once_with()
        command_process.join.assert_called_once_with(timeout=15.0)
        capture_process.join.assert_called_once_with(timeout=15.0)
        command_process.terminate.assert_not_called()
        capture_process.terminate.assert_not_called()

    def test_privileged_process_terminate_guard_swallows_permission_error(self):
        process = mock.Mock()
        original_terminate = process._popen.terminate
        original_terminate.side_effect = PermissionError("operation not permitted")

        module._guard_process_terminate_permission(process)

        process._popen.terminate()
        original_terminate.assert_called_once_with()

    def test_privileged_command_worker_exits_when_stop_event_is_set(self):
        stop_event = mock.Mock()
        stop_event.is_set.side_effect = [False, True]
        command_queue = mock.Mock()
        command_queue.get.side_effect = module.queue.Empty
        with mock.patch.object(module, "_PRIVILEGED_STOP_EVENT", stop_event), \
             mock.patch.object(module, "_command_queue", command_queue), \
             mock.patch.object(module._signal_module, "signal"), \
             mock.patch.object(module, "log"):
            module._privileged_command_process_main(stop_event)

        command_queue.get.assert_called_once_with(timeout=0.25)

    def test_packet_inspection_log_uses_private_appendable_permissions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = os.path.join(temp_dir, "packet_logs", "inspection.log")
            result = {
                "suspicious": True,
                "findings": [],
                "attack_signatures": [],
                "protocols": [],
                "entropy": 0.0,
            }
            module.log_full_packet_inspection(b"first", "lo", result, "test", "one", log_path)
            module.log_full_packet_inspection(b"second", "lo", result, "test", "two", log_path)

            self.assertEqual(os.stat(log_path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(os.path.dirname(log_path)).st_mode & 0o777, 0o700)
            with open(log_path, encoding="utf-8") as handle:
                records = [json.loads(line) for line in handle]
            self.assertEqual([record["reason"] for record in records], ["one", "two"])

    def test_packet_inspection_log_preparation_assigns_drop_target(self):
        target = mock.Mock(pw_uid=1234, pw_gid=2345, pw_name="workspace-user")
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = os.path.join(temp_dir, "ai_data", "packet_logs", "inspection.log")
            with mock.patch.object(module, "_FULL_PACKET_INSPECTION_LOG_PATH", log_path), \
                 mock.patch.object(module.os, "geteuid", return_value=0), \
                  mock.patch.dict(module.os.environ, {"SUDO_UID": "1234"}, clear=False), \
                 mock.patch.object(module.pwd, "getpwuid", return_value=target), \
                 mock.patch.object(module.os, "chown") as chown, \
                 mock.patch.object(module.os, "fchown") as fchown, \
                 mock.patch.object(module.os, "chmod") as chmod:
                module._prepare_packet_inspection_log()

            chown.assert_called_once_with(
                os.path.join(temp_dir, "ai_data", "packet_logs"),
                1234,
                2345,
                follow_symlinks=False,
            )
            fchown.assert_called_once_with(mock.ANY, 1234, 2345)
            chmod.assert_called_once_with(os.path.join(temp_dir, "ai_data", "packet_logs"), 0o700)
            module._close_packet_inspection_log()

    def test_prepared_packet_log_fd_survives_directory_permission_drop(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = os.path.join(temp_dir, "packet_logs", "inspection.log")
            directory = os.path.dirname(log_path)
            result = {
                "suspicious": True,
                "findings": [],
                "attack_signatures": [],
                "protocols": [],
                "entropy": 0.0,
            }
            with mock.patch.object(module, "_FULL_PACKET_INSPECTION_LOG_PATH", log_path):
                module._prepare_packet_inspection_log()
                try:
                    os.chmod(directory, 0)
                    module.log_full_packet_inspection(b"packet", "lo", result, "test", "fd-write")
                finally:
                    os.chmod(directory, 0o700)
                    module._close_packet_inspection_log()

            with open(log_path, encoding="utf-8") as handle:
                record = json.loads(handle.readline())
            self.assertEqual(record["reason"], "fd-write")

    def test_privileged_command_worker_resets_inherited_signal_handlers(self):
        with mock.patch.object(module, "_command_queue") as command_queue, \
             mock.patch.object(module._signal_module, "signal") as signal_mock, \
             mock.patch.object(module, "log"):
            command_queue.get.return_value = None
            module._privileged_command_process_main()

        signal_mock.assert_has_calls([
            mock.call(module._signal_module.SIGINT, module._signal_module.SIG_IGN),
            mock.call(module._signal_module.SIGTERM, module._signal_module.SIG_DFL),
        ])

    def test_load_cloud_model_uses_cpu_map_location(self):
        model = module.LightweightMultiTaskAI(input_dim=10)
        valid_state_dict = {key: value.detach().clone() for key, value in model.state_dict().items()}
        with mock.patch.object(module.os.path, "exists", return_value=True), \
             mock.patch.object(module.torch, "load", return_value=valid_state_dict) as load_mock, \
             mock.patch.object(module, "log") as log_mock, \
             mock.patch.dict(module.os.environ, {"AIRGAP_MODEL_HASH": "deadbeef"}, clear=False), \
             mock.patch.object(module, "_verify_model_hash", return_value=True):
            self.assertTrue(module.load_cloud_model(model, "/tmp/cloud_base_model.pth"))
            self.assertEqual(load_mock.call_args.kwargs["map_location"], module.torch.device("cpu"))
            self.assertTrue(load_mock.call_args.kwargs.get("weights_only", False))
            self.assertTrue(log_mock.info.called or log_mock.warning.called)

    def test_load_cloud_model_migrates_legacy_checkpoint_without_changing_outputs(self):
        if module.torch is None:
            self.skipTest("PyTorch is not installed")

        torch = module.torch
        legacy_state = {
            "shared_layer.0.weight": torch.randn(32, 10),
            "shared_layer.0.bias": torch.randn(32),
            "shared_layer.2.weight": torch.randn(16, 32),
            "shared_layer.2.bias": torch.randn(16),
            "head_a.0.weight": torch.randn(1, 16),
            "head_a.0.bias": torch.randn(1),
            "head_b.0.weight": torch.randn(1, 16),
            "head_b.0.bias": torch.randn(1),
            "head_c.0.weight": torch.randn(1, 16),
            "head_c.0.bias": torch.randn(1),
        }
        model = module.LightweightMultiTaskAI(input_dim=10)
        with mock.patch.object(module.os.path, "exists", return_value=True), \
             mock.patch.object(module.torch, "load", return_value=legacy_state), \
             mock.patch.object(module, "_verify_model_hash", return_value=True), \
             mock.patch.dict(module.os.environ, {"AIRGAP_MODEL_HASH": "legacy-checkpoint"}, clear=False):
            self.assertTrue(module.load_cloud_model(model, "/tmp/legacy_model.pth"))

        inputs = torch.rand(8, 10)
        functional = torch.nn.functional
        with torch.no_grad():
            legacy_shared = functional.relu(functional.linear(
                inputs, legacy_state["shared_layer.0.weight"], legacy_state["shared_layer.0.bias"],
            ))
            legacy_shared = functional.relu(functional.linear(
                legacy_shared, legacy_state["shared_layer.2.weight"], legacy_state["shared_layer.2.bias"],
            ))
            expected_outputs = (
                torch.sigmoid(functional.linear(legacy_shared, legacy_state["head_a.0.weight"], legacy_state["head_a.0.bias"])),
                torch.sigmoid(functional.linear(legacy_shared, legacy_state["head_b.0.weight"], legacy_state["head_b.0.bias"])),
                torch.sigmoid(functional.linear(legacy_shared, legacy_state["head_c.0.weight"], legacy_state["head_c.0.bias"])),
            )
            actual_outputs = model(inputs)

        for expected_output, actual_output in zip(expected_outputs, actual_outputs):
            torch.testing.assert_close(actual_output, expected_output)

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

    def test_load_cloud_model_can_skip_hash_check_for_development(self):
        model = module.LightweightMultiTaskAI(input_dim=10)
        valid_state_dict = {key: value.detach().clone() for key, value in model.state_dict().items()}
        with mock.patch.object(module.os.path, "exists", return_value=True), \
             mock.patch.object(module.torch, "load", return_value=valid_state_dict), \
             mock.patch.object(module, "_verify_model_hash") as verify_hash, \
             mock.patch.dict(module.os.environ, {}, clear=True):
            self.assertTrue(module.load_cloud_model(
                model, "/tmp/cloud_base_model.pth", ignore_model_hash=True,
            ))
        verify_hash.assert_not_called()

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
            self.assertEqual(run_cmd.call_count, 3)

            executed_commands = [call.args[0] for call in run_cmd.call_args_list]
            self.assertEqual(executed_commands, [
                ["iptables", "-I", "INPUT", "-j", "DROP"],
                ["iptables", "-I", "OUTPUT", "-j", "DROP"],
                ["iptables", "-I", "FORWARD", "-j", "DROP"],
            ])

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

    def test_kernel_hardening_keeps_linux_overcommit_heuristic_for_fork(self):
        report = {"applied": [], "failures": []}
        with mock.patch.object(module.os.path, "exists", return_value=True), \
             mock.patch.object(module, "_write_sysctl_value", return_value=True) as write_value:
            module._apply_kernel_hardening({}, report)

        write_value.assert_any_call("/proc/sys/vm/overcommit_memory", "0")

    def test_privileged_agent_start_failure_cleans_up_command_worker(self):
        command_process = mock.Mock(pid=123)
        capture_process = mock.Mock(pid=None)
        capture_process.start.side_effect = OSError(12, "Cannot allocate memory")
        with mock.patch.object(module.platform, "system", return_value="Linux"), \
             mock.patch.object(module.os, "geteuid", return_value=0), \
               mock.patch.object(module.multiprocessing, "Process", side_effect=[command_process, capture_process]) as process_factory:
            module._PRIVILEGED_AGENT_ACTIVE = False
            result = module._ensure_privileged_agent("eth0", 512, "/tmp", True)

        self.assertIsNone(result)
        self.assertTrue(all(not call.kwargs.get("daemon", False) for call in process_factory.call_args_list))
        command_process.terminate.assert_called_once()
        command_process.join.assert_called_once_with(timeout=1)
        self.assertIsNone(module._PRIVILEGED_COMMAND_PROCESS)
        self.assertIsNone(module._PRIVILEGED_CAPTURE_PROCESS)
        self.assertFalse(module._PRIVILEGED_AGENT_ACTIVE)

    def test_generate_optimal_kill_payload_includes_nft_flush_when_available(self):
        profile = {
            "os": {"system": "Linux"},
            "available_interfaces": ["eth0"],
            "tools": {"ip": True, "iptables": True, "nft": True},
            "permissions": {"root": True},
            "network_layers": ["physical"],
        }
        payload = module.generate_optimal_kill_payload(profile, learning_data=["vpn"])
        self.assertFalse(any(cmd[:2] == ["nft", "flush"] for cmd in payload["commands"]))
        self.assertTrue(any(
            cmd[:2] == ["nft", "flush"]
            for fallback in payload["fallback_payloads"]
            for cmd in fallback["commands"]
        ))

    def test_memory_manager_check_considers_head_c_score(self):
        temp_swap_dir = "./test_swap"
        mgr = module.MemoryManager(max_memory_mb=1, swap_dir=temp_swap_dir)
        try:
            mock_rss = mock.Mock(rss=2 * 1024 * 1024)
            with mock.patch.object(mgr.process, "memory_info", return_value=mock_rss):
                ratio = mgr.check(head_c_score=0.9)
                self.assertTrue(mgr.is_critical)
                self.assertGreater(ratio, 1.0)
                mgr.check(head_c_score=[0.1, 0.9])
                self.assertTrue(mgr.is_critical)
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

    def test_untrained_model_keeps_independent_packet_risk_score(self):
        packet = self._build_ipv4_tcp_packet("1.1.1.1", "2.2.2.2", 443)
        dpi_result = {"suspicious": False, "score": 0.0, "findings": [], "protocols": []}

        pipeline = module.inspect_packet_pipeline(
            packet, "eth0", model=None, feature_vector=None, dpi_result=dpi_result,
        )
        effective_score = module._combine_threat_scores(0.0, pipeline["score"])

        self.assertFalse(pipeline["block"])
        self.assertGreater(pipeline["score"], 0.0)
        self.assertEqual(effective_score, pipeline["score"])
        self.assertEqual(module._combine_threat_scores(float("nan"), float("inf")), 0.0)

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
            plaintext_size = len((json.dumps(data) + "\n").encode())
            encrypted_record_overhead = 4 + mgr._nonce_size + 16
            self.assertEqual(mgr._offset, plaintext_size + encrypted_record_overhead)
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
