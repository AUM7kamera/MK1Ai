from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import time
import unittest
import uuid


ROOT = pathlib.Path(__file__).resolve().parents[2]
ENABLED = os.environ.get("MK1_RUN_NETNS_TESTS") == "1"
HAS_TOOLS = all(subprocess.run(
    ["which", name], check=False, capture_output=True, timeout=5,
).returncode == 0 for name in ("ip", "nft"))


@unittest.skipUnless(
    ENABLED and HAS_TOOLS and os.geteuid() == 0,
    "Requires root/CAP_NET_ADMIN, iproute2, nftables, and MK1_RUN_NETNS_TESTS=1",
)
class FirewallNamespaceIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        suffix = uuid.uuid4().hex[:8]
        cls.quarantine_ns = f"mk1q{suffix}"
        cls.peer_ns = f"mk1p{suffix}"
        cls.namespaces = [cls.quarantine_ns, cls.peer_ns]
        cls.server = None
        cls._run(["ip", "netns", "add", cls.quarantine_ns])
        cls._run(["ip", "netns", "add", cls.peer_ns])
        cls._run(["ip", "link", "add", "qv0", "type", "veth", "peer", "name", "pv0"])
        cls._run(["ip", "link", "set", "qv0", "netns", cls.quarantine_ns])
        cls._run(["ip", "link", "set", "pv0", "netns", cls.peer_ns])
        cls._run(["ip", "-n", cls.quarantine_ns, "address", "add", "198.18.0.1/24", "dev", "qv0"])
        cls._run(["ip", "-n", cls.peer_ns, "address", "add", "198.18.0.2/24", "dev", "pv0"])
        cls._run(["ip", "-n", cls.peer_ns, "address", "add", "198.18.0.3/24", "dev", "pv0"])
        for namespace, device in ((cls.quarantine_ns, "qv0"), (cls.peer_ns, "pv0")):
            cls._run(["ip", "-n", namespace, "link", "set", "lo", "up"])
            cls._run(["ip", "-n", namespace, "link", "set", device, "up"])
        cls._run(
            [
                "ip", "netns", "exec", cls.quarantine_ns,
                "nft", "-f", "-",
            ],
            input_text=(
                "add table inet mk1ai_egress\n"
                "add chain inet mk1ai_egress marker\n"
            ),
        )

        server_code = """
import socket
import threading

def tcp_server(port):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen()
    while True:
        connection, _ = server.accept()
        connection.sendall(b"ok")
        connection.close()

def udp_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("0.0.0.0", port))
    while True:
        payload, address = server.recvfrom(64)
        server.sendto(payload, address)

threading.Thread(target=tcp_server, args=(18080,), daemon=True).start()
threading.Thread(target=tcp_server, args=(18081,), daemon=True).start()
threading.Thread(target=udp_server, args=(18080,), daemon=True).start()
print("READY", flush=True)
threading.Event().wait()
"""
        cls.server = subprocess.Popen(
            [
                "ip", "netns", "exec", cls.peer_ns, sys.executable, "-u", "-c",
                server_code,
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        ready = cls.server.stdout.readline() if cls.server.stdout else ""
        if ready.strip() != "READY":
            raise RuntimeError("Namespace test server failed to start")

    @classmethod
    def tearDownClass(cls):
        if cls.server is not None:
            cls.server.terminate()
            try:
                cls.server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cls.server.kill()
                cls.server.wait(timeout=3)
        for namespace in cls.namespaces:
            subprocess.run(
                ["ip", "netns", "del", namespace],
                check=False,
                capture_output=True,
                timeout=5,
            )

    @staticmethod
    def _run(command, *, input_text=None, check=True):
        return subprocess.run(
            command,
            input=input_text,
            text=True,
            check=check,
            capture_output=True,
            timeout=15,
        )

    def _in_namespace(self, namespace, *command):
        return self._run(["ip", "netns", "exec", namespace, *command])

    def _apply_policy(self):
        code = """
from mk1_firewall import apply_nft_policy
raise SystemExit(0 if apply_nft_policy(
    mode="management_safe_harbor",
    management_ips=["198.18.0.2"],
    management_ports=[18080],
) else 1)
"""
        self._in_namespace(self.quarantine_ns, sys.executable, "-c", code)

    def _can_connect(self, address: str, port: int, *, protocol="tcp") -> bool:
        code = """
import socket, sys
kind = socket.SOCK_DGRAM if sys.argv[3] == "udp" else socket.SOCK_STREAM
sock = socket.socket(socket.AF_INET, kind)
sock.settimeout(0.5)
try:
    if kind == socket.SOCK_DGRAM:
        sock.sendto(b"probe", (sys.argv[1], int(sys.argv[2])))
        sock.recvfrom(64)
    else:
        sock.connect((sys.argv[1], int(sys.argv[2])))
        sock.recv(16)
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
"""
        result = subprocess.run(
            [
                "ip", "netns", "exec", self.quarantine_ns, sys.executable,
                "-c", code, address, str(port), protocol,
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            timeout=3,
        )
        return result.returncode == 0

    def test_policy_preserves_egress_table_blocks_other_paths_and_is_idempotent(self):
        self._apply_policy()
        egress = self._in_namespace(
            self.quarantine_ns, "nft", "list", "table", "inet", "mk1ai_egress",
        ).stdout
        self.assertIn("table inet mk1ai_egress", egress)
        self._assert_traffic_policy()

        first_application = self._in_namespace(
            self.quarantine_ns,
            "nft",
            "list",
            "table",
            "inet",
            "mk1ai_quarantine",
        ).stdout
        self._apply_policy()
        second_application = self._in_namespace(
            self.quarantine_ns,
            "nft",
            "list",
            "table",
            "inet",
            "mk1ai_quarantine",
        ).stdout
        self.assertEqual(first_application, second_application)

    def test_failed_batch_leaves_existing_quarantine_and_egress_unchanged(self):
        self._apply_policy()
        before_policy = self._in_namespace(
            self.quarantine_ns,
            "nft",
            "list",
            "table",
            "inet",
            "mk1ai_quarantine",
        ).stdout
        before_egress = self._in_namespace(
            self.quarantine_ns,
            "nft",
            "list",
            "table",
            "inet",
            "mk1ai_egress",
        ).stdout

        failed = self._run(
            ["ip", "netns", "exec", self.quarantine_ns, "nft", "-f", "-"],
            check=False,
            input_text=(
 codespace-probable-dollop-pj64p66j94jv29wg6
                "destroy table inet mk1ai_quarantine\n"

                "add table inet mk1ai_quarantine\n"
                "delete table inet mk1ai_quarantine\n"
 main
                "add table inet mk1ai_quarantine\n"
                "add chain inet mk1ai_quarantine duplicate\n"
                "add rule inet mk1ai_missing input drop\n"
            ),
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(
            before_policy,
            self._in_namespace(
                self.quarantine_ns,
                "nft",
                "list",
                "table",
                "inet",
                "mk1ai_quarantine",
            ).stdout,
        )
        self.assertEqual(
            before_egress,
            self._in_namespace(
                self.quarantine_ns,
                "nft",
                "list",
                "table",
                "inet",
                "mk1ai_egress",
            ).stdout,
        )

 codespace-probable-dollop-pj64p66j94jv29wg6

    def test_removal_deletes_only_quarantine_table(self):
        self._apply_policy()
        code = """
from mk1_firewall import remove_nft_policy
raise SystemExit(0 if remove_nft_policy() else 1)
"""
        self._in_namespace(self.quarantine_ns, sys.executable, "-c", code)
        gone = self._run(
            ["ip", "netns", "exec", self.quarantine_ns, "nft", "list", "table",
             "inet", "mk1ai_quarantine"], check=False)
        self.assertNotEqual(gone.returncode, 0)
        self.assertIn("mk1ai_egress", self._in_namespace(
            self.quarantine_ns, "nft", "list", "table", "inet", "mk1ai_egress",
        ).stdout)
        # removal is idempotent when the table is already absent
        self._in_namespace(self.quarantine_ns, sys.executable, "-c", code)

 main
    def _assert_traffic_policy(self):
        time.sleep(0.1)
        self.assertTrue(self._can_connect("198.18.0.2", 18080))
        self.assertFalse(self._can_connect("198.18.0.2", 18081))
        self.assertFalse(self._can_connect("198.18.0.3", 18080))
        self.assertFalse(self._can_connect("198.18.0.2", 18080, protocol="udp"))


if __name__ == "__main__":
    unittest.main()
