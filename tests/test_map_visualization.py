import base64
import json
import pathlib
import socket
import tempfile
import time
import unittest

from mk1_map import MapMode, MapVisualizationService, build_threat_map_event


class MapVisualizationTest(unittest.TestCase):
    def test_event_schema_keeps_unavailable_geo_and_fingerprint_data_unknown(self):
        event = build_threat_map_event(
            "8.8.8.8",
            reason="dpi",
            threat_score=0.91,
            timestamp_us=123456,
        )

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["ip_address"], "8.8.8.8")
        self.assertEqual(event["location"]["latitude"], None)
        self.assertIsNone(event["location"]["longitude"])
        self.assertIsNone(event["estimated_dist"])
        self.assertEqual(event["os_type"], "unknown")
        self.assertEqual(event["timestamp_us"], 123456)
        self.assertIsNone(build_threat_map_event("192.168.1.1", reason="dpi", threat_score=0.9))
        self.assertIsNone(build_threat_map_event("not-an-ip", reason="dpi", threat_score=0.9))

    def test_off_mode_has_no_worker_and_publish_is_a_noop(self):
        with tempfile.TemporaryDirectory() as directory:
            service = MapVisualizationService(directory)

            self.assertEqual(service.mode, MapMode.OFF)
            self.assertFalse(service.publish({"ip_address": "8.8.8.8"}))
            self.assertIsNone(service._worker)
            self.assertIsNone(service.address)
            service.close()

    def test_local_mode_writes_events_to_offline_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            service = MapVisualizationService(directory)
            service.set_mode(MapMode.LOCAL)
            event = build_threat_map_event("8.8.8.8", reason="dpi", threat_score=0.9)
            assert event is not None

            self.assertTrue(service.publish(event))
            events_path = pathlib.Path(directory) / "map-events.jsonl"
            deadline = time.monotonic() + 2
            while not events_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            while events_path.exists() and events_path.stat().st_size == 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            service.close()

            rows = events_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(rows), 1)
            self.assertEqual(json.loads(rows[0])["ip_address"], "8.8.8.8")
            self.assertEqual(events_path.stat().st_mode & 0o777, 0o600)

    def test_chrome_mode_serves_websocket_only_on_loopback(self):
        with tempfile.TemporaryDirectory() as directory:
            service = MapVisualizationService(directory, port=0)
            service.set_mode(MapMode.CHROME)
            assert service.address is not None
            host, port = service.address
            self.assertEqual(host, "127.0.0.1")

            with socket.create_connection((host, port), timeout=2) as client:
                client.settimeout(2)
                key = base64.b64encode(b"0123456789abcdef").decode("ascii")
                request = (
                    "GET /map HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{port}\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: keep-alive, Upgrade\r\n"
                    f"Sec-WebSocket-Key: {key}\r\n"
                    "Sec-WebSocket-Version: 13\r\n"
                    "Origin: chrome-extension://abcdefghijklmnop\r\n\r\n"
                )
                client.sendall(request.encode("ascii"))
                response = bytearray()
                while b"\r\n\r\n" not in response:
                    response.extend(client.recv(1024))
                self.assertIn(b"101 Switching Protocols", response)

                event = build_threat_map_event("8.8.8.8", reason="dpi", threat_score=0.9)
                assert event is not None
                self.assertTrue(service.publish(event))
                header = client.recv(2)
                self.assertEqual(header[0], 0x81)
                payload_length = header[1] & 0x7F
                if payload_length == 126:
                    payload_length = int.from_bytes(client.recv(2), "big")
                payload = bytearray()
                while len(payload) < payload_length:
                    payload.extend(client.recv(payload_length - len(payload)))
                self.assertEqual(json.loads(payload)["ip_address"], "8.8.8.8")

            service.close()

    def test_non_loopback_bind_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "127.0.0.1"):
                MapVisualizationService(directory, host="0.0.0.0")


if __name__ == "__main__":
    unittest.main()
