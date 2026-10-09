import hashlib
import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest
from typing import Any
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "airgap_ai_defender_6.py"
spec = importlib.util.spec_from_file_location("airgap_ai_defender_6", MODULE_PATH)
assert spec is not None and spec.loader is not None, "Failed to load spec or loader"
module: Any = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AirgapAI6Test(unittest.TestCase):
    @staticmethod
    def _fake_torch(load):
        # PyTorch 未導入環境では module.torch が None になるため、モジュール参照ごと差し替える
        return mock.Mock(
            load=load,
            device=mock.Mock(return_value="cpu"),
            cuda=mock.Mock(is_available=mock.Mock(return_value=False)),
        )

    def test_calculate_entropy_returns_shannon_entropy(self):
        self.assertEqual(module.calculate_entropy(b""), 0.0)
        self.assertEqual(module.calculate_entropy(b"aaaa"), 0.0)
        self.assertEqual(module.calculate_entropy(b"abab"), 1.0)

    def test_analyze_packet_security_classifies_high_entropy_payload(self):
        byte_values = list(range(32)) + list(range(128, 256))
        symbol_indexes = (
            [0, 0, 1, 1, *range(2, 14)]
            + list(range(2, 14))
            + [index for index in range(14, 96) for _ in range(2)]
            + list(range(96, 160))
        )
        payload = bytes(byte_values[index] for index in symbol_indexes)

        result = module.analyze_packet_security(payload)

        self.assertGreater(result["aes"]["entropy"], 7.2)
        self.assertFalse(result["aes"]["aes_candidate"])
        self.assertEqual(result["behavior"], "high_entropy_payload")

    def test_load_local_model_uses_cpu_map_location(self):
        class DummyModel:
            def __init__(self):
                self.loaded = None
            def load_state_dict(self, state_dict):
                self.loaded = state_dict

        fake_state = {
            "shared_layer.0.weight": None,
            "shared_layer.0.bias": None,
            "shared_layer.2.weight": None,
            "shared_layer.2.bias": None,
            "head_a.weight": None,
            "head_a.bias": None,
            "head_b.weight": None,
            "head_b.bias": None,
            "head_c.weight": None,
            "head_c.bias": None,
        }

        fake_torch = self._fake_torch(load=mock.Mock(return_value=fake_state))
        with mock.patch.object(module.os.path, "exists", return_value=True), \
             mock.patch.object(module, "_get_expected_model_hash", return_value="deadbeef"), \
             mock.patch.object(module, "_verify_model_hash", return_value=True), \
             mock.patch.object(module, "torch", fake_torch):
            model = DummyModel()
            self.assertTrue(module.load_local_model(model, "/tmp/local.pth"))
            fake_torch.load.assert_called_once_with("/tmp/local.pth", map_location="cpu", weights_only=True)
            self.assertEqual(model.loaded, fake_state)

    def test_load_local_model_rejects_mismatched_hash(self):
        class DummyModel:
            def load_state_dict(self, state_dict):
                raise AssertionError("should not load")

        fake_torch = self._fake_torch(load=mock.Mock(side_effect=AssertionError("torch.load should not run")))
        with mock.patch.object(module.os.path, "exists", return_value=True), \
             mock.patch.object(module, "_get_expected_model_hash", return_value="expected"), \
             mock.patch.object(module, "_verify_model_hash", return_value=False), \
             mock.patch.object(module, "torch", fake_torch):
            model = DummyModel()
            self.assertFalse(module.load_local_model(model, "/tmp/local.pth"))
            fake_torch.load.assert_not_called()

    def test_load_local_model_rejects_missing_expected_hash(self):
        class DummyModel:
            def load_state_dict(self, state_dict):
                raise AssertionError("should not load")

        fake_torch = self._fake_torch(load=mock.Mock(side_effect=AssertionError("torch.load should not run")))
        with mock.patch.object(module.os.path, "exists", return_value=True), \
             mock.patch.object(module, "_get_expected_model_hash", return_value=None), \
             mock.patch.object(module, "torch", fake_torch):
            self.assertFalse(module.load_local_model(DummyModel(), "/tmp/local.pth"))
            fake_torch.load.assert_not_called()

    def test_get_expected_model_hash_accepts_sha256sum_sidecar_format(self):
        expected_hash = hashlib.sha256(b"model-bytes").hexdigest()
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = pathlib.Path(temp_dir) / "local.pth"
            model_path.write_bytes(b"model-bytes")
            sidecar_path = pathlib.Path(str(model_path) + ".sha256")
            sidecar_path.write_text(f"{expected_hash}  local.pth\n", encoding="utf-8")
            self.assertEqual(module._get_expected_model_hash(str(model_path)), expected_hash)

    def test_boot_time_auto_hardening_reports_missing_root(self):
        profile = {"permissions": {"root": False}}
        result = module.boot_time_auto_hardening(profile)
        self.assertIn("missing_root", result["failures"])

    def test_memory_manager_check_considers_head_c_score(self):
        temp_dir = tempfile.mkdtemp()
        manager = module.MemoryManager(max_memory_mb=1, swap_dir=temp_dir)
        try:
            if module.psutil:
                with mock.patch.object(manager, "process") as proc:
                    proc.memory_info.return_value = mock.Mock(rss=2 * 1024 * 1024)
                    ratio = manager.check(head_c_score=0.9)
            else:
                ratio = manager.check(head_c_score=0.9)
            self.assertTrue(manager.is_critical)
            self.assertGreaterEqual(ratio, 0.0)
        finally:
            manager.cleanup()
            shutil = __import__("shutil")
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_generate_absolute_defense_payload_includes_drop_and_down(self):
        profile = {
            "available_interfaces": ["eth0", "wg0"],
            "tools": {"ip": True, "iptables": True, "nft": True},
        }
        payload = module.generate_absolute_defense_payload(profile)
        self.assertTrue(any(cmd[:4] == ["ip", "link", "set", "eth0"] for cmd in payload["commands"]))
        self.assertTrue(any(cmd[:2] == ["iptables", "-F"] for cmd in payload["commands"]))
        self.assertTrue(any(cmd[:2] == ["nft", "flush"] for cmd in payload["commands"]))

    def test_self_protection_triggers_kill_switch_on_tamper(self):
        protection = module.SelfProtection("eth0", "eth0", dry_run=True)
        with mock.patch.object(protection, "_compute_self_hash", side_effect=["a", "b"]):
            with mock.patch.object(module, "execute_kill_switch") as kill_switch:
                protection._monitor_loop()
                kill_switch.assert_called_once_with("eth0", dry_run=True)

    def test_main_invokes_profile_and_hardening(self):
        with mock.patch.object(module, "profile_environment", return_value={"permissions": {"root": False}, "available_interfaces": [], "tools": {}}) as profile_mock, \
             mock.patch.object(module, "boot_time_auto_hardening", return_value={"applied": [], "failures": ["missing_root"]}) as hardening_mock, \
             mock.patch.object(module, "MemoryManager") as manager_cls, \
             mock.patch.object(module, "SelfProtection") as protection_cls, \
             mock.patch.object(module, "load_local_model", return_value=False):
            manager = mock.Mock()
            manager.check.return_value = 0.0
            manager.should_preemptive_evict = False
            manager.cleanup.return_value = None
            manager_cls.return_value = manager
            protection = mock.Mock()
            protection.start.return_value = None
            protection.stop.return_value = None
            protection_cls.return_value = protection
            old_argv = sys.argv
            sys.argv = ["airgap_ai_defender_6.py", "--dry-run"]
            try:
                module.main()
            finally:
                sys.argv = old_argv
            profile_mock.assert_called_once()
            hardening_mock.assert_called_once()
            manager_cls.assert_called_once()
            protection_cls.assert_called_once()


if __name__ == "__main__":
    unittest.main()
