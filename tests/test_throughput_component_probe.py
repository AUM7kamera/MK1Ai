from __future__ import annotations

import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scripts.throughput_component_probe import (
    build_tcp_frame,
    benchmark_inspection_logging,
    benchmark_loopback_transport,
    measure,
    percentiles,
)


class ThroughputComponentProbeTests(unittest.TestCase):
    def test_frame_builder_returns_requested_ethernet_frame_length(self):
        for size in (64, 128, 1500, 1518):
            with self.subTest(size=size):
                frame = build_tcp_frame(size)
                self.assertEqual(len(frame), size)
                self.assertEqual(frame[12:14], b"\x08\x00")

    def test_frame_builder_rejects_frames_too_small_for_headers(self):
        with self.assertRaises(ValueError):
            build_tcp_frame(53)

    def test_percentiles_and_measurement_shape(self):
        self.assertEqual(
            percentiles([1.0, 2.0, 3.0]),
            {"mean_us": 2.0, "p95_us": 2.9, "p99_us": 2.98, "samples": 3},
        )
        result = measure(lambda: None, 0.05, input_bytes_per_operation=64)
        self.assertGreater(result["operations"], 0)
        self.assertGreater(result["operations_per_second"], 0)
        self.assertEqual(result["latency"]["samples"], 250)
        self.assertTrue(result["latency_excluded_from_rate_measurement"])

    def test_aes_gcm_authentication_rejects_tampering(self):
        cipher = AESGCM.generate_key(bit_length=256)
        aead = AESGCM(cipher)
        nonce = b"\0" * 12
        ciphertext = bytearray(aead.encrypt(nonce, b"synthetic", b"aad"))
        ciphertext[-1] ^= 1
        with self.assertRaises(InvalidTag):
            aead.decrypt(nonce, bytes(ciphertext), b"aad")

    def test_full_inspection_logging_writes_and_cleans_synthetic_records(self):
        import airgap_ai_defender as defender

        original_flag = defender.FULL_PACKET_INSPECTION
        original_log_level = defender.log.level
        result = benchmark_inspection_logging(64, 0.05)
        self.assertGreater(result["log_file_bytes_including_latency_samples"], 0)
        self.assertGreater(result["timed_log_bytes_per_second"], 0)
        self.assertTrue(result["temporary_synthetic_log_removed"])
        self.assertFalse(result["file_flush_or_fsync"])
        self.assertEqual(defender.FULL_PACKET_INSPECTION, original_flag)
        self.assertEqual(defender.log.level, original_log_level)

    def test_localhost_transport_authenticates_concurrent_sessions(self):
        result = benchmark_loopback_transport(64, 2, 0.05)
        self.assertEqual(result["connection_count"], 2)
        self.assertEqual(result["payload_bytes_per_direction"], 64)
        self.assertGreater(result["authenticated_request_records"], 0)
        self.assertEqual(
            result["authenticated_request_records"],
            result["authenticated_response_records"],
        )
        self.assertEqual(result["failed_request_records"], 0)
        self.assertGreater(result["request_goodput_bps"], 0)
        self.assertEqual(result["request_response_rtt"]["samples"], sum(
            result["latency_samples_per_connection"],
        ))
        self.assertFalse(result["wireguard_or_tls_included"])
        self.assertFalse(result["remote_peer_authentication_included"])
        self.assertTrue(result["tcp_loopback_only"])
        self.assertEqual(result["server_bind_host"], "127.0.0.1")

    def test_secure_pipeline_loopback_combines_kem_aead_auth_dpi_and_logging(self):
        import airgap_ai_defender as defender

        original_flag = defender.FULL_PACKET_INSPECTION
        original_log_level = defender.log.level
        result = benchmark_loopback_transport(
            64, 2, 0.05, include_secure_pipeline=True,
        )
        self.assertEqual(result["connection_count"], 2)
        self.assertEqual(result["authenticated_request_records"], result["authenticated_response_records"])
        self.assertGreater(result["authenticated_request_records"], 0)
        self.assertEqual(result["failed_request_records"], 0)
        self.assertEqual(result["inspection_log_records"], result["authenticated_request_records"])
        self.assertGreater(result["inspection_log_file_bytes"], 0)
        self.assertEqual(result["ml_kem_768_handshake_count"], 2)
        self.assertTrue(result["ml_kem_public_key_pin_verified"])
        self.assertEqual(result["ml_kem_768_handshake_latency"]["samples"], 2)
        self.assertGreaterEqual(result["process_cpu_time_seconds"], 0)
        self.assertGreaterEqual(result["process_cpu_percent_of_one_core"], 0)
        self.assertGreater(result["process_rss_bytes"]["peak_sampled"], 0)
        self.assertGreater(result["process_rss_bytes"]["samples"], 0)
        self.assertEqual(
            result["process_rss_bytes"]["scope"],
            "whole probe process, including server, clients, model, and sampler",
        )
        self.assertTrue(result["synthetic_api_token_authentication_included"])
        self.assertTrue(result["dpi_pipeline_included"])
        self.assertTrue(result["forced_full_inspection_logging_included"])
        self.assertTrue(result["key_exchange_included"])
        self.assertFalse(result["inspection_log_fsync"])
        self.assertTrue(result["temporary_inspection_log_removed_after_measurement"])
        self.assertFalse(result["wireguard_or_tls_included"])
        self.assertEqual(defender.FULL_PACKET_INSPECTION, original_flag)
        self.assertEqual(defender.log.level, original_log_level)


if __name__ == "__main__":
    unittest.main()
