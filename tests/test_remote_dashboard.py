import http.client
import json
import pathlib
import tempfile
import threading
import unittest
from dataclasses import replace
from http.server import ThreadingHTTPServer
from typing import Any, cast
from unittest import mock

from mk1_remote_dashboard import (
    DashboardConfig,
    DashboardHandler,
    DashboardState,
    RATE_LIMIT_REQUESTS,
    RemoteDashboardServer,
)
from mk1_secure_transport import SecureTransportError


class RemoteDashboardTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = pathlib.Path(self.temp_dir.name)
        self.config = DashboardConfig(
            host="127.0.0.1",
            port=8080,
            origin="https://localhost:8443",
            rp_id="localhost",
            rp_name="MK1Ai test",
            wireguard_interface="wg0",
            wireguard_bind_address="10.77.0.1",
            status_path=root / "panel-status.txt",
            database_path=root / "remote-dashboard.sqlite3",
            bootstrap_path=root / "remote-bootstrap.token",
            signing_key_path=root / "remote-session.key",
            admin_email="admin@example.test",
            email_from="security@example.test",
            smtp_host="smtp.gmail.com",
            smtp_port=587,
            smtp_username="admin@example.test",
            smtp_app_password="not-a-real-password",
            admin_phone="+15555550123",
            twilio_account_sid="AC" + "0" * 32,
            twilio_auth_token="not-a-real-token",
            twilio_from_number="+15555550124",
            role="enrollment",
            owner_profile_path=root / "owner_profile.dat",
        )

    def test_dashboard_refuses_non_https_or_cross_domain_origin(self):
        with self.assertRaisesRegex(ValueError, "https://"):
            replace(self.config, origin="http://localhost:8443").validate()
        with self.assertRaisesRegex(ValueError, "一致"):
            replace(self.config, origin="https://dashboard.example.test").validate()
        with self.assertRaisesRegex(ValueError, "loopback"):
            replace(self.config, host="0.0.0.0").validate()

    def test_remote_server_refuses_to_start_without_verified_wireguard(self):
        with mock.patch(
            "mk1_remote_dashboard.require_wireguard_full_tunnel",
            side_effect=SecureTransportError("test: WireGuard is down"),
        ):
            with self.assertRaisesRegex(ValueError, "WireGuard"):
                RemoteDashboardServer(self.config)

    def test_status_exposes_only_allowlisted_fields_and_rejects_out_of_range_values(self):
        self.config.status_path.write_text(
            "state=RUNNING\n"
            "packets_per_second=25.50\n"
            "packets_total=42\n"
            "threat_score=0.450\n"
            "backdoor_score=0.200\n"
            "alert=THREAT\n"
            "interface=eth0\n"
            "model_sync_status=Loaded\n"
            "training_queue_batches=3\n"
            "secret_token=do-not-expose\n"
            "threat_score=9000000001\n",
            encoding="ascii",
        )
        state = DashboardState(self.config)

        result = state.status()

        self.assertEqual(result["state"], "RUNNING")
        self.assertEqual(result["packets_per_second"], 25.5)
        self.assertEqual(result["packets_total"], 42)
        self.assertEqual(result["alert"], "THREAT")
        self.assertNotIn("secret_token", result)
        self.assertNotIn("do-not-expose", repr(result))
        self.assertLessEqual(result["threat_score"], 1)

    def test_session_signing_key_and_bootstrap_token_are_private_and_one_time(self):
        state = DashboardState(self.config)
        self.assertEqual(self.config.signing_key_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.config.bootstrap_path.stat().st_mode & 0o777, 0o600)
        self.assertIsNotNone(state.bootstrap_token)
        self.assertTrue(state.validate_bootstrap_token(state.bootstrap_token or ""))
        self.assertFalse(state.validate_bootstrap_token("wrong-token"))

        state.store_credential(b"credential-id", b"public-key", 0)

        self.assertTrue(state.has_credentials())
        self.assertIsNone(state.bootstrap_token)
        self.assertFalse(self.config.bootstrap_path.exists())
        self.assertEqual(self.config.owner_profile_path.stat().st_mode & 0o777, 0o400)

    def test_login_role_imports_read_only_owner_profile_and_refuses_writable_profile(self):
        enrollment = DashboardState(self.config)
        enrollment.store_credential(b"credential-id", b"public-key", 7)
        login_config = replace(
            self.config,
            role="login",
            database_path=pathlib.Path(self.temp_dir.name) / "production.sqlite3",
            bootstrap_path=pathlib.Path(self.temp_dir.name) / "production-bootstrap.token",
            signing_key_path=pathlib.Path(self.temp_dir.name) / "production-session.key",
        )

        state = DashboardState(login_config)

        rows = state.credential_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(bytes(rows[0]["credential_id"]), b"credential-id")
        self.assertEqual(rows[0]["sign_count"], 7)
        self.assertIsNone(state.bootstrap_token)

        self.config.owner_profile_path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "mode 0400"):
            DashboardState(replace(login_config, database_path=pathlib.Path(self.temp_dir.name) / "other.sqlite3"))

    def test_rate_limit_is_enforced_per_client_and_route(self):
        state = DashboardState(self.config)

        for _ in range(RATE_LIMIT_REQUESTS):
            self.assertTrue(state.allow_request("192.0.2.1", "/api/auth/options"))

        self.assertFalse(state.allow_request("192.0.2.1", "/api/auth/options"))
        self.assertTrue(state.allow_request("192.0.2.1", "/api/session"))

    def test_enrollment_role_has_registration_ui_only(self):
        state = DashboardState(self.config)
        server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
        port = server.server_address[1]
        state.config = replace(
            self.config,
            port=port,
            origin=f"https://127.0.0.1:{port}",
            rp_id="127.0.0.1",
        )
        cast(Any, server).dashboard_state = state
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(worker.join, 2)
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        self.addCleanup(connection.close)

        connection.request("GET", "/")
        response = connection.getresponse()
        page = response.read()
        self.assertEqual(response.status, 200)
        self.assertIn(b"ONE-TIME ENROLLMENT", page)

        connection.request("GET", "/register.js")
        response = connection.getresponse()
        script = response.read()
        self.assertEqual(response.status, 200)
        self.assertIn(b"navigator.credentials.create", script)

        body = json.dumps({"bootstrap_token": state.bootstrap_token}).encode("ascii")
        with mock.patch("mk1_remote_dashboard.generate_registration_options") as options, \
             mock.patch("mk1_remote_dashboard.options_to_json", return_value='{"challenge":"YQ"}'):
            options.return_value.challenge = b"challenge"
            connection.request(
                "POST",
                "/api/register/options",
                body=body,
                headers={
                    "Host": f"127.0.0.1:{port}",
                    "Origin": f"https://127.0.0.1:{port}",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                },
            )
            response = connection.getresponse()
            registration_options = response.read()
        self.assertEqual(response.status, 200)
        self.assertIn(b'"options"', registration_options)

        connection.request("GET", "/api/status")
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 404)

        connection.request(
            "POST",
            "/api/auth/options",
            body=b"{}",
            headers={
                "Host": f"127.0.0.1:{port}",
                "Origin": f"https://127.0.0.1:{port}",
                "Content-Type": "application/json",
                "Content-Length": "2",
            },
        )
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 404)

    def test_enrollment_configuration_does_not_need_email_or_sms_secrets(self):
        enrollment_config = replace(
            self.config,
            email_from="",
            smtp_username="",
            smtp_app_password="",
            admin_phone="",
            twilio_account_sid="",
            twilio_auth_token="",
            twilio_from_number="",
        )
        enrollment_config.validate()

    def test_dual_otp_delivery_is_required_and_codes_are_not_stored_plaintext(self):
        state = DashboardState(self.config)
        session = {}
        email_codes = []
        sms_codes = []
        with mock.patch.object(state, "send_email_code", side_effect=email_codes.append), \
             mock.patch.object(state, "send_sms_code", side_effect=sms_codes.append):
            state.issue_otp(session)

        self.assertEqual(session["stage"], "otp")
        self.assertEqual(len(email_codes), 1)
        self.assertEqual(len(sms_codes), 1)
        self.assertTrue(state.code_digest(email_codes[0], "email"))
        self.assertNotIn(email_codes[0], session["email_code_digest"])
        self.assertNotEqual(email_codes[0], sms_codes[0])

        failed_session = {}
        with mock.patch.object(state, "send_email_code"), \
             mock.patch.object(state, "send_sms_code", side_effect=RuntimeError("provider failed")):
            with self.assertRaisesRegex(RuntimeError, "両方"):
                state.issue_otp(failed_session)
        self.assertEqual(failed_session["stage"], "failed")
        self.assertNotIn("email_code_digest", failed_session)
        self.assertNotIn("sms_code_digest", failed_session)

    def test_provider_notifications_require_wireguard_and_tls13(self):
        state = DashboardState(self.config)
        smtp = mock.MagicMock()
        with mock.patch(
            "mk1_remote_dashboard.require_wireguard_full_tunnel",
            return_value="wg0",
        ) as wireguard, mock.patch(
            "mk1_remote_dashboard.smtplib.SMTP", return_value=smtp,
        ):
            state.send_email_code("123456")
        wireguard.assert_called_once_with("wg0")
        smtp_client = smtp.__enter__.return_value
        smtp_client.starttls.assert_called_once()
        email_context = smtp_client.starttls.call_args.kwargs["context"]
        self.assertEqual(email_context.minimum_version.name, "TLSv1_3")

        response = mock.MagicMock()
        response.status = 201
        response.__enter__.return_value = response
        with mock.patch(
            "mk1_remote_dashboard.require_wireguard_full_tunnel",
            return_value="wg0",
        ) as wireguard, mock.patch(
            "mk1_remote_dashboard.urllib.request.urlopen", return_value=response,
        ) as urlopen:
            state.send_sms_code("654321")
        wireguard.assert_called_once_with("wg0")
        sms_context = urlopen.call_args.kwargs["context"]
        self.assertEqual(sms_context.minimum_version.name, "TLSv1_3")

    def test_remote_http_api_is_read_only_and_requires_authentication(self):
        enrollment = DashboardState(self.config)
        enrollment.store_credential(b"credential-id", b"public-key", 0)
        login_config = replace(
            self.config,
            role="login",
            database_path=pathlib.Path(self.temp_dir.name) / "production.sqlite3",
            bootstrap_path=pathlib.Path(self.temp_dir.name) / "production-bootstrap.token",
            signing_key_path=pathlib.Path(self.temp_dir.name) / "production-session.key",
        )
        state = DashboardState(login_config)
        server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
        port = server.server_address[1]
        state.config = replace(
            login_config,
            port=port,
            origin=f"https://127.0.0.1:{port}",
            rp_id="127.0.0.1",
        )
        cast(Any, server).dashboard_state = state
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(worker.join, 2)

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        self.addCleanup(connection.close)
        connection.request("GET", "/api/status")
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 401)
        self.assertEqual(response.getheader("X-Frame-Options"), "DENY")
        self.assertIn("no-store", response.getheader("Cache-Control") or "")

        connection.request("GET", "/register")
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 404)

        connection.request(
            "POST",
            "/api/start-monitor",
            body=b"{}",
            headers={
                "Host": f"127.0.0.1:{port}",
                "Origin": f"https://127.0.0.1:{port}",
                "Content-Type": "application/json",
                "Content-Length": "2",
            },
        )
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 404)


if __name__ == "__main__":
    unittest.main()
