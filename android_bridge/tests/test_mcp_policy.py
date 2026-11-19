"""MCP discovery gate and server-side tool allowlist.

The fake adb binary records every invocation, so a denied call can be shown to
have executed nothing at all.
"""

import json
import os
import struct
import sys
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(os.path.dirname(HERE), "app")
sys.path.insert(0, APP_DIR)

import server as bridge  # noqa: E402
import adbctl  # noqa: E402

FAKE_ADB = r'''#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
log = os.environ.get("FAKE_ADB_LOG")
if log:
    with open(log, "a") as fh:
        fh.write(repr(args) + "\n")
if args and args[0] == "devices":
    print("List of devices attached")
    print(os.environ.get("FAKE_ADB_SERIAL", "192.168.1.50:41234")
          + "\tdevice product:x model:SM_X210 device:y")
    sys.exit(0)
if args and args[0] == "connect":
    print("connected to " + args[1])
    sys.exit(0)
if "-s" in args and "exec-out" in args:
    with open(os.environ["FAKE_ADB_PNG"], "rb") as fh:
        sys.stdout.buffer.write(fh.read())
    sys.exit(0)
if len(args) > 4 and args[2:4] == ["shell", "input"]:
    sys.exit(0)
sys.exit(2)
'''

UNSET = object()
PNG = (
    b"\x89PNG\r\n\x1a\n"
    + struct.pack(">I", 13)
    + b"IHDR"
    + struct.pack(">II", 1080, 2400)
    + b"\x00" * 9
)


class McpPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bridge-mcp-")
        self.png_path = os.path.join(self.tmp, "frame.png")
        with open(self.png_path, "wb") as handle:
            handle.write(PNG)
        self.adb = os.path.join(self.tmp, "adb")
        with open(self.adb, "w", encoding="utf-8") as handle:
            handle.write(FAKE_ADB)
        os.chmod(self.adb, 0o755)
        self.log_path = os.path.join(self.tmp, "adb.log")
        open(self.log_path, "w").close()

        self._orig_binary = adbctl.ADB_BINARY
        adbctl.ADB_BINARY = self.adb
        self._orig_source = bridge.mcp_source_allowed
        bridge.mcp_source_allowed = lambda address: address == "127.0.0.1"
        self._saved_env = {
            key: os.environ.get(key)
            for key in ("FAKE_ADB_LOG", "FAKE_ADB_SERIAL", "FAKE_ADB_PNG")
        }
        os.environ.update({
            "FAKE_ADB_LOG": self.log_path,
            "FAKE_ADB_SERIAL": "192.168.1.50:41234",
            "FAKE_ADB_PNG": self.png_path,
        })
        self.servers = []

    def tearDown(self):
        bridge.mcp_source_allowed = self._orig_source
        for server in self.servers:
            server.shutdown()
            server.server_close()
        adbctl.ADB_BINARY = self._orig_binary
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    # ---------- helpers ----------

    def start(self, expose=UNSET, raw=None):
        data_dir = tempfile.mkdtemp(prefix="data-", dir=self.tmp)
        if expose is not UNSET or raw is not None:
            private = bridge.private_dir(data_dir)
            os.makedirs(private, mode=0o700, exist_ok=True)
            target = bridge.tools_path(data_dir)
            payload = raw if raw is not None else {"expose_tools": expose}
            with open(target, "w", encoding="utf-8") as handle:
                if isinstance(payload, str):
                    handle.write(payload)
                else:
                    json.dump(payload, handle)
            os.chmod(target, 0o600)
        bridge.save_device(data_dir, "192.168.1.50", "41234")
        server = bridge.create_server("127.0.0.1", 0, data_dir=data_dir)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.servers.append(server)
        return server

    def mcp(self, server, payload, headers=None):
        body = json.dumps(payload).encode("utf-8")
        merged = {"Content-Type": "application/json"}
        merged.update(headers or {})
        connection = HTTPConnection(
            "127.0.0.1", server.server_address[1], timeout=20
        )
        try:
            connection.request("POST", "/mcp", body=body, headers=merged)
            response = connection.getresponse()
            data = response.read()
            return response.status, (json.loads(data) if data else None)
        finally:
            connection.close()

    def call(self, server, name, arguments=None):
        return self.mcp(server, {
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        })

    def list_tools(self, server):
        return self.mcp(server, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})

    def viewing_on(self, server):
        server.viewing_active = True
        server.viewing_expires = time.monotonic() + 3600

    def adb_calls(self):
        with open(self.log_path, encoding="utf-8") as handle:
            return [line.rstrip("\n") for line in handle if line.strip()]

    def clear_adb(self):
        open(self.log_path, "w").close()

    # ---------- 11-18: discovery gate ----------

    def test_11_allowlisted_initialize_with_viewing_off(self):
        server = self.start()
        status, payload = self.mcp(
            server, {"jsonrpc": "2.0", "id": 1, "method": "initialize"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["result"]["serverInfo"]["name"], "android-bridge")
        self.assertEqual(payload["result"]["serverInfo"]["version"], "0.3.14")

    def test_12_allowlisted_tools_list_with_viewing_off(self):
        server = self.start()
        status, payload = self.list_tools(server)
        self.assertEqual(status, 200)
        names = sorted(tool["name"] for tool in payload["result"]["tools"])
        self.assertEqual(names, ["android_screenshot", "android_status"])

    def test_13_tools_call_denied_with_viewing_off(self):
        server = self.start()
        status, payload = self.call(server, "android_status")
        self.assertEqual(status, 403)
        self.assertEqual(payload, {"error": "viewing_session_closed"})

    def test_14_unknown_source_initialize_is_401(self):
        server = self.start()
        bridge.mcp_source_allowed = lambda address: False
        self.viewing_on(server)
        status, _ = self.mcp(
            server, {"jsonrpc": "2.0", "id": 1, "method": "initialize"}
        )
        self.assertEqual(status, 401)

    def test_15_unknown_source_tools_list_is_401(self):
        server = self.start()
        bridge.mcp_source_allowed = lambda address: False
        self.viewing_on(server)
        status, _ = self.list_tools(server)
        self.assertEqual(status, 401)

    def test_16_unknown_source_tools_call_is_401(self):
        server = self.start()
        bridge.mcp_source_allowed = lambda address: False
        self.viewing_on(server)
        status, payload = self.call(server, "android_screenshot")
        self.assertEqual(status, 401)
        self.assertNotIn("result", payload or {})

    def test_17_discovery_never_invokes_adb(self):
        server = self.start()
        self.clear_adb()
        for method in ("initialize", "tools/list", "ping"):
            status, _ = self.mcp(
                server, {"jsonrpc": "2.0", "id": 1, "method": method}
            )
            self.assertEqual(status, 200)
        self.assertEqual(self.adb_calls(), [])

    def test_18_spoofed_forwarding_headers_cannot_bypass_source_allowlist(self):
        server = self.start()
        bridge.mcp_source_allowed = lambda address: address == "10.9.9.9"
        self.viewing_on(server)
        headers = {
            "X-Forwarded-For": "10.9.9.9",
            "X-Real-IP": "10.9.9.9",
            "Forwarded": "for=10.9.9.9",
            "X-Forwarded-Host": "10.9.9.9",
        }
        status, _ = self.mcp(
            server, {"jsonrpc": "2.0", "id": 1, "method": "initialize"}, headers
        )
        self.assertEqual(status, 401)

    # ---------- 19-30: server-side tool allowlist ----------

    def test_19_default_exposes_only_screenshot_and_status(self):
        server = self.start()
        self.assertEqual(
            tuple(server.exposed_tools), ("android_screenshot", "android_status")
        )
        _, payload = self.list_tools(server)
        names = sorted(tool["name"] for tool in payload["result"]["tools"])
        self.assertEqual(names, ["android_screenshot", "android_status"])

    def test_20_authorised_screenshot_still_works(self):
        server = self.start()
        self.viewing_on(server)
        status, payload = self.call(server, "android_screenshot")
        self.assertEqual(status, 200)
        content = payload["result"]["content"][0]
        self.assertEqual(content["type"], "image")
        self.assertEqual(content["mimeType"], "image/png")
        import base64
        self.assertEqual(base64.b64decode(content["data"]), PNG)
        self.assertFalse(payload["result"]["isError"])

    def test_21_authorised_status_still_works(self):
        server = self.start()
        self.viewing_on(server)
        status, payload = self.call(server, "android_status")
        self.assertEqual(status, 200)
        self.assertIn('"connected": true', payload["result"]["content"][0]["text"])

    def test_22_direct_tap_is_rejected_when_not_exposed(self):
        server = self.start()
        self.viewing_on(server)
        server.control_active = True
        status, payload = self.call(server, "android_tap", {"x": 10, "y": 20})
        self.assertEqual(status, 200)
        self.assertEqual(payload["error"]["code"], -32602)
        self.assertNotIn("result", payload)
        self.assertEqual(self.adb_calls(), [])

    def test_23_swipe_text_and_action_result_are_rejected(self):
        server = self.start()
        self.viewing_on(server)
        server.control_active = True
        cases = [
            ("android_swipe", {"x1": 1, "y1": 2, "x2": 3, "y2": 4}),
            ("android_text", {"text": "hello"}),
            ("android_action_result", {"id": "abc"}),
        ]
        for name, arguments in cases:
            with self.subTest(name=name):
                self.clear_adb()
                status, payload = self.call(server, name, arguments)
                self.assertEqual(status, 200)
                self.assertEqual(payload["error"]["code"], -32602)
                self.assertEqual(self.adb_calls(), [])

    def test_24_unknown_future_tool_names_are_rejected(self):
        server = self.start()
        self.viewing_on(server)
        status, payload = self.call(server, "android_reboot")
        self.assertEqual(status, 200)
        self.assertEqual(payload["error"]["code"], -32602)

    def test_25_denied_calls_never_reach_adb_input(self):
        server = self.start()
        self.viewing_on(server)
        server.control_active = True
        self.clear_adb()
        self.call(server, "android_tap", {"x": 10, "y": 20})
        self.assertEqual(self.adb_calls(), [])

    def test_26_empty_expose_tools_lists_nothing(self):
        server = self.start(expose=[])
        self.assertEqual(tuple(server.exposed_tools), ())
        _, payload = self.list_tools(server)
        self.assertEqual(payload["result"]["tools"], [])
        self.viewing_on(server)
        _, payload = self.call(server, "android_screenshot")
        self.assertEqual(payload["error"]["code"], -32602)

    def test_27_missing_setting_falls_back_to_read_only_default(self):
        server = self.start()
        self.assertEqual(
            tuple(server.exposed_tools), ("android_screenshot", "android_status")
        )
        self.viewing_on(server)
        _, payload = self.call(server, "android_tap", {"x": 1, "y": 2})
        self.assertEqual(payload["error"]["code"], -32602)

    def test_28_unknown_configured_names_cannot_enable_control_tools(self):
        server = self.start(expose=["*", "android_*", "all"])
        self.assertEqual(tuple(server.exposed_tools), ())
        _, payload = self.list_tools(server)
        self.assertEqual(payload["result"]["tools"], [])
        self.viewing_on(server)
        _, payload = self.call(server, "android_tap", {"x": 1, "y": 2})
        self.assertEqual(payload["error"]["code"], -32602)

    def test_29_invalid_configuration_fails_safe(self):
        cases = (
            {"expose_tools": "android_tap"},
            {"expose_tools": {"android_tap": True}},
            "{not json",
            ["android_tap"],
        )
        for raw in cases:
            with self.subTest(raw=raw):
                server = self.start(raw=raw)
                self.assertEqual(
                    tuple(server.exposed_tools),
                    ("android_screenshot", "android_status"),
                )
                self.viewing_on(server)
                _, payload = self.call(server, "android_tap", {"x": 1, "y": 2})
                self.assertEqual(payload["error"]["code"], -32602)

    def test_30_duplicate_configured_names_are_handled_safely(self):
        server = self.start(
            expose=["android_status", "android_status", "android_screenshot", "android_status"]
        )
        self.assertEqual(
            tuple(server.exposed_tools), ("android_status", "android_screenshot")
        )
        _, payload = self.list_tools(server)
        names = [tool["name"] for tool in payload["result"]["tools"]]
        self.assertEqual(names, ["android_screenshot", "android_status"])
        self.viewing_on(server)
        status, payload = self.call(server, "android_status")
        self.assertEqual(status, 200)
        self.assertFalse(payload["result"]["isError"])

    def test_unknown_names_are_logged_by_name_without_control_tools(self):
        import contextlib
        import io
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            server = self.start(expose=["android_status", "bogus", 42])
        output = capture.getvalue()
        self.assertIn("mcp_tool_ignored name=bogus", output)
        self.assertIn("mcp_tool_ignored name=non_string", output)
        self.assertEqual(tuple(server.exposed_tools), ("android_status",))

    def test_startup_log_describes_the_real_gate(self):
        with open(bridge.__file__, encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("(HA-user panel, MCP source+viewing gate)", source)
        self.assertNotIn("(bearer auth enabled)", source)


if __name__ == "__main__":
    unittest.main()
