import base64
import hashlib
import json
import re
import socket
import struct
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import migrate_shelly_wifi as m  # noqa: E402


class PureHelperTests(unittest.TestCase):
    def test_requires_home_assistant_url(self):
        with self.assertRaisesRegex(m.MigrationError, "HOME_ASSISTANT_URL"):
            m.invoke_shelly_migration(m.Options(home_assistant_url=""))

    def test_retry_returns_eventual_result(self):
        calls = []

        def operation():
            calls.append(1)
            if len(calls) < 3:
                raise RuntimeError("transient failure")
            return "success"

        self.assertEqual(m.invoke_with_retry(operation, "test", attempts=3, delay_seconds=0), "success")
        self.assertEqual(len(calls), 3)

    def test_join_api_uri(self):
        self.assertEqual(m.join_api_uri("https://ha.example/", "/api/test"), "https://ha.example/api/test")

    def test_normalize_mac(self):
        self.assertEqual(m.normalize_mac_address("aa:bb:cc:11:22:33"), "AABBCC112233")
        self.assertEqual(m.normalize_mac_address("AA-BB-CC-11-22-33"), "AABBCC112233")
        with self.assertRaises(m.MigrationError):
            m.normalize_mac_address("not-a-mac")

    def test_sha256_ha1(self):
        self.assertEqual(
            m.sha256_hex("admin:shellyplus1pm-ABCDEF123456:correct horse battery staple"),
            "0113d2cd6a5c4aecd44f1c3c2601516a2262241d81520800ff83083e4c382ee4",
        )

    def test_cidr_hosts(self):
        self.assertEqual(m.get_cidr_hosts("192.168.20.0/30"), ["192.168.20.1", "192.168.20.2"])
        self.assertEqual(len(m.get_cidr_hosts("192.168.20.0/24")), 254)
        with self.assertRaises(m.MigrationError):
            m.get_cidr_hosts("192.168.16.0/21")

    def test_target_placement_needs_ssid_and_subnet(self):
        target = m.Device("192.168.20.38", 80, "AABBCCDDEEFF", 2)
        old = m.Device("192.168.178.64", 80, "AABBCCDDEEFF", 2)
        args = ("CloudDenied", "192.168.20.0/24")
        self.assertTrue(m.is_shelly_target_placement(target, "CloudDenied", *args))
        self.assertFalse(m.is_shelly_target_placement(old, "CloudDenied", *args))
        self.assertFalse(m.is_shelly_target_placement(target, "skynet", *args))


class TlsVerificationTests(unittest.TestCase):
    def test_home_assistant_requests_verify_tls(self):
        response = m.HttpResponse(200, {}, b"{}", "https://ha.example.invalid/api/")
        with mock.patch.object(m, "http_request", return_value=response) as request:
            m.ha_request("https://ha.example.invalid", "token", "GET", "/api/")
        self.assertIs(True, request.call_args.kwargs["verify_tls"])

    def test_verified_context_checks_certificates(self):
        self.assertEqual(m.ssl.CERT_REQUIRED, m._VERIFIED_TLS.verify_mode)
        self.assertTrue(m._VERIFIED_TLS.check_hostname)

    def test_device_requests_tolerate_self_signed_certificates(self):
        self.assertEqual(m.ssl.CERT_NONE, m._INSECURE_TLS.verify_mode)


class InventoryAndStateTests(unittest.TestCase):
    def test_entries_unwrap_and_validate(self):
        with mock.patch.object(m, "ha_request", return_value=[{"entry_id": "e1", "title": "A"}, {"entry_id": "e2", "title": "B"}]):
            self.assertEqual([e["entry_id"] for e in m.get_ha_entries("https://ha", "t")], ["e1", "e2"])
        with mock.patch.object(m, "ha_request", return_value={"entries": [{"title": "no id"}]}):
            with self.assertRaises(m.MigrationError):
                m.get_ha_entries("https://ha", "t")

    def test_inventory_reads_host_from_reconfigure_flow(self):
        flow = {
            "type": "form", "step_id": "reconfigure", "flow_id": "flow-1",
            "data_schema": [
                {"name": "host", "default": "192.168.178.20"},
                {"name": "port", "default": 80},
                {"name": "verify_ssl", "default": False},
            ],
        }
        with mock.patch.object(m, "get_ha_entries", return_value=[{"entry_id": "e1", "title": "Kitchen", "state": "loaded"}]), \
             mock.patch.object(m, "start_ha_entry_flow", return_value=flow), \
             mock.patch.object(m, "stop_ha_entry_flow") as stop:
            result = m.get_ha_shelly_inventory("https://ha", "t")
        self.assertEqual((result[0].host, result[0].state, result[0].port), ("192.168.178.20", "loaded", 80))
        stop.assert_called_once()

    def test_title_wildcards_apply_before_limit(self):
        inventory = [m.Entry("1", "Kitchen Plug", "", "h"), m.Entry("2", "Office Light", "", "h"), m.Entry("3", "Office Plug", "", "h")]
        result = m.select_inventory_entries(inventory, ["Office*"], limit=1)
        self.assertEqual([e.title for e in result], ["Office Light"])

    def test_checkpoint_is_resumable_and_secret_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = m.read_migration_state(Path(tmp) / "missing.json")
        entry = m.Entry("entry-1", "Kitchen", "", "192.168.178.20")
        device = m.Device("h", 80, "AABBCCDDEEFF", 2)
        m.set_migration_checkpoint(state, entry, device, "transitioning", old_ssid="OldWlan")
        entry.host = "192.168.20.42"
        m.set_migration_checkpoint(state, entry, device, "discovered", "192.168.20.42", 80)
        record = state["devices"][0]
        self.assertEqual((record["newIp"], record["newPort"], record["oldIp"], record["oldSsid"]),
                         ("192.168.20.42", 80, "192.168.178.20", "OldWlan"))
        self.assertIsNone(re.search(r"password|token|secret", json.dumps(state), re.I))

    def test_state_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "state.json"
            state = m.read_migration_state(path)
            m.write_migration_state(state, path)
            self.assertEqual(m.read_migration_state(path)["version"], 1)

    def test_resume_uses_discovered_vlan_address(self):
        inventory = [m.Entry("entry-1", "x", "", "192.168.178.20")]
        state = {"devices": [{"entryId": "entry-1", "newIp": "192.168.20.42", "newPort": 443, "phase": "finalize_failed"}]}
        result = m.resolve_inventory_from_state(inventory, state)
        self.assertEqual((result[0].host, result[0].port), ("192.168.20.42", 443))


class ShellyRoutingTests(unittest.TestCase):
    def test_primary_ssid_gen1_and_gen2(self):
        with mock.patch.object(m, "get_shelly_settings", return_value={"wifi_sta": {"ssid": "OldWlan"}}):
            self.assertEqual(m.get_shelly_primary_ssid(m.Device("h", 80, "M", 1)), "OldWlan")
        with mock.patch.object(m, "get_shelly_settings", return_value={"Wifi": {"sta": {"ssid": "OldWlan"}}}):
            self.assertEqual(m.get_shelly_primary_ssid(m.Device("h", 80, "M", 3)), "OldWlan")

    def test_protected_gen2_rpc_uses_digest(self):
        device = m.Device("192.0.2.10", 80, "M", 2, protected=True)
        with mock.patch.object(m, "shelly_digest_json_request", return_value={"result": {"ok": True}}) as digest:
            self.assertEqual(m.shelly_rpc(device, "Sys.GetConfig", password="pw"), {"ok": True})
        digest.assert_called_once()

    def test_rpc_errors_surface(self):
        device = m.Device("192.0.2.10", 80, "M", 2)
        with mock.patch.object(m, "shelly_request", return_value={"error": {"code": -103, "message": "Bad arguments"}}):
            with self.assertRaisesRegex(m.MigrationError, "code=-103.*Bad arguments"):
                m.shelly_rpc(device, "Wifi.SetConfig")

    def test_protected_gen1_coiot_uses_basic(self):
        device = m.Device("192.0.2.11", 80, "M", 1, protected=True)
        with mock.patch.object(m, "shelly_request", return_value={}) as request:
            m.set_shelly_coiot(device, "192.168.178.10:5683", "pw")
        self.assertEqual(request.call_args.kwargs["authentication"], "basic")
        self.assertEqual(request.call_args.kwargs["password"], "pw")

    def test_gen2_fallback_passes_admin_password(self):
        device = m.Device("192.0.2.12", 80, "M", 3, protected=True)
        calls = []

        def rpc(dev, method, params=None, password=None):
            calls.append((method, password))
            return {"sta1": {"enable": True, "ssid": "OldWlan"}} if method == "Wifi.GetConfig" else {}

        with mock.patch.object(m, "shelly_rpc", side_effect=rpc):
            m.set_shelly_fallback_wifi(device, "OldWlan", "wifi", "admin pw")
        self.assertEqual(calls, [("Wifi.SetConfig", "admin pw"), ("Wifi.GetConfig", "admin pw")])

    def test_gen2_primary_wifi_rpc(self):
        device = m.Device("192.0.2.12", 80, "M", 3, protected=True)
        with mock.patch.object(m, "shelly_rpc", return_value={}) as rpc:
            m.set_shelly_primary_wifi(device, "NewWlan", "wifi", "admin pw")
        method, params, password = rpc.call_args.args[1:]
        self.assertEqual(method, "Wifi.SetConfig")
        self.assertIn("sta", params["config"])
        self.assertEqual(password, "admin pw")

    def test_ha_address_update_submits_once(self):
        with mock.patch.object(m, "start_ha_entry_flow", return_value={"flow_id": "f1"}), \
             mock.patch.object(m, "ha_request", return_value={"type": "abort", "reason": "reconfigure_successful"}) as request, \
             mock.patch.object(m, "stop_ha_entry_flow"):
            m.set_ha_shelly_address("https://ha", "t", "e1", "192.168.20.42", 80)
        request.assert_called_once()


class _DigestHandler(BaseHTTPRequestHandler):
    realm, nonce, password = "shellyplus1pm-ABC", "abc123nonce", "s3cret"

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        header = self.headers.get("Authorization", "")
        if self._valid(header):
            payload = json.dumps({"id": 1, "result": {"echo": json.loads(body)["method"]}}).encode()
            self.send_response(200)
        else:
            payload = b""
            self.send_response(401)
            self.send_header("WWW-Authenticate", f'Digest qop="auth", realm="{self.realm}", nonce="{self.nonce}", algorithm=SHA-256')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _valid(self, header):
        if not header.startswith("Digest "):
            return False
        f = dict(re.findall(r'(\w+)="?([^",]+)"?', header))
        sha = lambda s: hashlib.sha256(s.encode()).hexdigest()  # noqa: E731
        ha1 = sha(f"admin:{self.realm}:{self.password}")
        ha2 = sha(f"POST:{f['uri']}")
        expected = sha(f"{ha1}:{self.nonce}:{f['nc']}:{f['cnonce']}:auth:{ha2}")
        return f["response"] == expected and f["algorithm"] == "SHA-256"


class DigestAuthTests(unittest.TestCase):
    def test_digest_round_trip_against_local_server(self):
        server = HTTPServer(("127.0.0.1", 0), _DigestHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f"http://127.0.0.1:{server.server_port}/rpc"
        result = m.shelly_digest_json_request(url, "POST", {"id": 1, "method": "Sys.GetConfig"}, "s3cret")
        self.assertEqual(result["result"]["echo"], "Sys.GetConfig")
        with self.assertRaisesRegex(m.MigrationError, "HTTP 401"):
            m.shelly_digest_json_request(url, "POST", {"id": 1, "method": "x"}, "wrong")


class WebSocketTests(unittest.TestCase):
    def test_command_round_trip_with_fragmentation_and_ping(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)

        def frame(opcode, payload, fin=True):
            return bytes([(0x80 if fin else 0) | opcode, len(payload)]) + payload

        def read_frame(conn):
            first, second = conn.recv(2)
            length = second & 0x7F
            mask = conn.recv(4)
            data = b""
            while len(data) < length:
                data += conn.recv(length - len(data))
            return first & 0x0F, bytes(b ^ mask[i % 4] for i, b in enumerate(data))

        def serve():
            conn, _ = listener.accept()
            request = b""
            while b"\r\n\r\n" not in request:
                request += conn.recv(1024)
            key = re.search(rb"Sec-WebSocket-Key: (\S+)", request).group(1)
            accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                         b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
            conn.sendall(frame(1, b'{"type": "auth_required"}'))
            _, auth = read_frame(conn)
            assert json.loads(auth)["access_token"] == "tok"
            conn.sendall(frame(1, b'{"type": "auth_ok"}'))
            _, command = read_frame(conn)
            assert json.loads(command)["id"] == 1
            conn.sendall(frame(9, b"hi"))  # ping must be answered and skipped
            reply = json.dumps({"id": 1, "success": True, "result": ["ok"]}).encode()
            conn.sendall(frame(1, reply[:10], fin=False) + frame(0, reply[10:]))
            conn.close()

        threading.Thread(target=serve, daemon=True).start()
        url = f"ws://127.0.0.1:{listener.getsockname()[1]}/api/websocket"
        self.assertEqual(m.ha_websocket_command(url, "tok", {"type": "config_entries/flow/progress"}), ["ok"])


if __name__ == "__main__":
    unittest.main()
