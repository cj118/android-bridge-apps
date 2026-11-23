"""Screenshot, pairing and ADB-surface tests using a fake adb binary."""

import base64
import contextlib
import io
import json
import os
import stat
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.client import HTTPConnection

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(os.path.dirname(HERE), "app")
sys.path.insert(0, APP_DIR)

import server as bridge  # noqa: E402
import adbctl  # noqa: E402

FAKE_ADB = r'''#!/usr/bin/env python3
import os, sys, time
args = sys.argv[1:]
log = os.environ.get("FAKE_ADB_LOG")
if log:
    with open(log, "a") as fh:
        fh.write(repr(args) + "\n")
mode = os.environ.get("FAKE_ADB_MODE", "ok")
if args and args[0] == "start-server":
    print("* daemon started successfully")
    sys.exit(0)
if "-s" in args and "shell" in args:
    if args[-1] == "ro.serialno":
        print("R5CT12345678")
        sys.exit(0)
    if args[-1] == "ro.product.model":
        print("SM_X210")
        sys.exit(0)
    sys.exit(9)
if args and args[0] == "version":
    print("Android Debug Bridge version 1.0.41")
    sys.exit(0)
if args and args[0] == "devices":
    print("List of devices attached")
    if mode != "no_device":
        print("192.168.1.50:41234\tdevice product:gta9pwifi model:SM_X210 device:gta9pwifi")
    sys.exit(0)
if args and args[0] == "pair":
    code = sys.stdin.readline().strip()
    target = os.environ.get("FAKE_ADB_STDIN")
    if target:
        with open(target, "a") as fh:
            fh.write(code + "\n")
    if code != os.environ.get("FAKE_ADB_CODE", "123456"):
        sys.exit(1)
    print("Successfully paired")
    sys.exit(0)
if args and args[0] == "connect":
    print("connected to 192.168.1.50:41234")
    sys.exit(0)
if args and args[0] == "disconnect":
    sys.exit(0)
if "-s" in args and "exec-out" in args:
    if mode == "fail":
        sys.exit(1)
    if mode == "garbage":
        sys.stdout.buffer.write(b"not-a-png")
        sys.exit(0)
    if mode == "huge":
        sys.stdout.buffer.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * (13 * 1024 * 1024))
        sys.exit(0)
    with open(os.environ["FAKE_ADB_PNG"], "rb") as fh:
        sys.stdout.buffer.write(fh.read())
    sys.exit(0)
sys.exit(2)
'''


def make_png(width=1080, height=2400):
    return (
        b"\x89PNG\r\n\x1a\n"
        + struct.pack(">I", 13)
        + b"IHDR"
        + struct.pack(">II", width, height)
        + b"\x00" * 9
    )


class ScreenshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="bridge-adb-")
        cls.png_path = os.path.join(cls.tmp, "frame.png")
        cls.png = make_png()
        with open(cls.png_path, "wb") as handle:
            handle.write(cls.png)

        cls.adb_path = os.path.join(cls.tmp, "adb")
        with open(cls.adb_path, "w", encoding="utf-8") as handle:
            handle.write(FAKE_ADB)
        os.chmod(cls.adb_path, 0o755)
        adbctl.ADB_BINARY = cls.adb_path

        cls.log_path = os.path.join(cls.tmp, "adb.log")
        os.environ["FAKE_ADB_LOG"] = cls.log_path
        os.environ["FAKE_ADB_PNG"] = cls.png_path
        os.environ["FAKE_ADB_CODE"] = "123456"

        cls.data_dir = os.path.join(cls.tmp, "data")
        os.makedirs(cls.data_dir, mode=0o700)
        cls.server = bridge.create_server("127.0.0.1", 0, data_dir=cls.data_dir)
        cls.port = cls.server.server_address[1]
        bridge.save_device(cls.data_dir, "192.168.1.50", "41234")
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        with open(bridge.token_path(cls.data_dir), "rb") as handle:
            cls.token = handle.read().strip().decode("ascii")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self._orig_source = bridge.mcp_source_allowed
        bridge.mcp_source_allowed = lambda address: True
        adbctl.reset_server_state()
        self.server.capture_times.clear()
        self.server.viewing_active = True
        self.server.viewing_expires = time.monotonic() + 3600
        os.environ["FAKE_ADB_MODE"] = "ok"

    def tearDown(self):
        bridge.mcp_source_allowed = self._orig_source

    def auth(self):
        return {"Authorization": "Bearer " + self.token}

    def request(self, method="GET", path="/", headers=None, body=None):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    # ---------- capture ----------

    def test_screenshot_returns_png(self):
        status, body, headers = self.request("GET", "/screenshot", self.auth())
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "image/png")
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(body, self.png)

    def test_screenshot_requires_auth(self):
        status, _, _ = self.request("GET", "/screenshot")
        self.assertEqual(status, 401)

    def test_screenshot_requires_a_viewing_session(self):
        self.server.viewing_active = False
        status, body, _ = self.request("GET", "/screenshot", self.auth())
        self.assertEqual(status, 403)
        self.assertIn(b"viewing_session_closed", body)

    def test_disconnected_device_is_409(self):
        os.environ["FAKE_ADB_MODE"] = "no_device"
        status, body, _ = self.request("GET", "/screenshot", self.auth())
        self.assertEqual(status, 409)
        self.assertIn(b"device_not_connected", body)

    def test_capture_failure_is_502(self):
        os.environ["FAKE_ADB_MODE"] = "fail"
        status, body, _ = self.request("GET", "/screenshot", self.auth())
        self.assertEqual(status, 502)
        self.assertIn(b"capture_failed", body)

    def test_invalid_image_is_502(self):
        os.environ["FAKE_ADB_MODE"] = "garbage"
        status, body, _ = self.request("GET", "/screenshot", self.auth())
        self.assertEqual(status, 502)
        self.assertIn(b"invalid_image", body)

    def test_oversize_image_is_502(self):
        os.environ["FAKE_ADB_MODE"] = "huge"
        status, body, _ = self.request("GET", "/screenshot", self.auth())
        self.assertEqual(status, 502)
        self.assertIn(b"image_too_large", body)

    def test_capture_timeout_is_504(self):
        original = adbctl.screencap
        adbctl.screencap = lambda *a, **k: (_ for _ in ()).throw(adbctl.AdbError("timeout"))
        try:
            status, body, _ = self.request("GET", "/screenshot", self.auth())
        finally:
            adbctl.screencap = original
        self.assertEqual(status, 504)
        self.assertIn(b"capture_timeout", body)

    def test_capture_is_rate_limited(self):
        first, _, _ = self.request("GET", "/screenshot", self.auth())
        second, body, _ = self.request("GET", "/screenshot", self.auth())
        self.assertEqual(first, 200)
        self.assertEqual(second, 429)
        self.assertIn(b"rate_limited", body)

    def test_concurrent_capture_is_rejected(self):
        self.server.capture_lock.acquire()
        try:
            status, body, _ = self.request("GET", "/screenshot", self.auth())
        finally:
            self.server.capture_lock.release()
        self.assertEqual(status, 429)
        self.assertIn(b"capture_busy", body)

    def test_only_fixed_identity_shell_reads_are_invoked(self):
        self.request("GET", "/screenshot", self.auth())
        with open(self.log_path, "r", encoding="utf-8") as handle:
            invocations = handle.read()
        self.assertNotIn("'input'", invocations)
        self.assertNotIn("'exec'", invocations)
        for line in invocations.splitlines():
            if "'shell'" in line:
                self.assertIn("'getprop', 'ro.serialno'", line)

    def test_status_reports_connection(self):
        status, body, _ = self.request("GET", "/status", self.auth())
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["paired"])
        self.assertTrue(payload["connected"])
        self.assertEqual(payload["device_model"], "SM_X210")
        self.assertNotIn(self.token, body.decode())


    # ---------- MCP ----------

    def mcp(self, payload):
        body = json.dumps(payload).encode("utf-8")
        headers = dict(self.auth())
        headers["Content-Type"] = "application/json"
        status, data, _ = self.request("POST", "/mcp", headers, body)
        return status, (json.loads(data) if data else None)

    def test_mcp_rejects_an_unknown_source(self):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
        original = self._with_allowlist(False)
        try:
            status, _, _ = self.request(
                "POST", "/mcp", {"Content-Type": "application/json"}, body
            )
        finally:
            self._restore_allowlist(original)
        self.assertEqual(status, 401)

    def test_mcp_initialize_and_tools_list(self):
        status, payload = self.mcp({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["result"]["serverInfo"]["name"], "android-bridge")

        status, payload = self.mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual(status, 200)
        names = sorted(tool["name"] for tool in payload["result"]["tools"])
        self.assertEqual(
            names, ["android_screenshot", "android_status", "android_ui_elements"]
        )

    def test_mcp_screenshot_returns_image_content(self):
        status, payload = self.mcp(
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "android_screenshot", "arguments": {}}}
        )
        self.assertEqual(status, 200)
        content = payload["result"]["content"][0]
        self.assertEqual(content["type"], "image")
        self.assertEqual(content["mimeType"], "image/png")
        self.assertEqual(base64.b64decode(content["data"]), self.png)
        self.assertFalse(payload["result"]["isError"])

    def test_mcp_status_tool(self):
        status, payload = self.mcp(
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "android_status", "arguments": {}}}
        )
        self.assertEqual(status, 200)
        text = payload["result"]["content"][0]["text"]
        self.assertIn('"paired": true', text)


    # ---------- MCP credential isolation ----------

    def mcp_anonymous(self, payload):
        body = json.dumps(payload).encode("utf-8")
        status, data, _ = self.request(
            "POST", "/mcp", {"Content-Type": "application/json"}, body
        )
        return status, (json.loads(data) if data else None)

    def _with_allowlist(self, allowed):
        original = bridge.mcp_source_allowed
        bridge.mcp_source_allowed = lambda address: bool(allowed)
        return original

    def _restore_allowlist(self, original):
        bridge.mcp_source_allowed = original

    def _open_window(self):
        self.server.viewing_active = True
        self.server.viewing_expires = time.monotonic() + 3600
        return 200, b"", {}

    def _close_window(self):
        self.server.viewing_active = False
        return 200, b"", {}



    def test_mcp_allows_allowlisted_source_without_token(self):
        original = self._with_allowlist({"127.0.0.1"})
        try:
            self._open_window()
            status, payload = self.mcp_anonymous(
                {"jsonrpc": "2.0", "id": 9, "method": "tools/list"}
            )
        finally:
            self._restore_allowlist(original)
        self.assertEqual(status, 200)
        names = sorted(t["name"] for t in payload["result"]["tools"])
        self.assertEqual(
            names, ["android_screenshot", "android_status", "android_ui_elements"]
        )

    def test_mcp_rejects_unknown_source_without_token(self):
        original = self._with_allowlist(set())
        try:
            status, _, _ = self.request(
                "POST", "/mcp",
                {"Content-Type": "application/json"},
                json.dumps({"jsonrpc": "2.0", "id": 10, "method": "tools/list"}).encode(),
            )
        finally:
            self._restore_allowlist(original)
        self.assertEqual(status, 401)

    def test_mcp_ignores_an_invalid_bearer_for_allowlisted_peer(self):
        original = self._with_allowlist(True)
        try:
            status, _, _ = self.request(
                "POST", "/mcp",
                {"Content-Type": "application/json",
                 "Authorization": "Bearer " + "A" * 43},
                json.dumps({"jsonrpc": "2.0", "id": 11, "method": "tools/list"}).encode(),
            )
        finally:
            self._restore_allowlist(original)
        self.assertEqual(status, 200)


    def test_mcp_without_window_denies_tools_call(self):
        self.server.viewing_active = False
        original = self._with_allowlist({"127.0.0.1"})
        try:
            status, body, _ = self.request(
                "POST", "/mcp",
                {"Content-Type": "application/json"},
                json.dumps({"jsonrpc": "2.0", "id": 20, "method": "tools/call",
                            "params": {"name": "android_status",
                                       "arguments": {}}}).encode(),
            )
        finally:
            self._restore_allowlist(original)
        self.assertEqual(status, 403)
        self.assertIn(b"viewing_session_closed", body)

    def test_mcp_stopped_session_denies_tools_call(self):
        original = self._with_allowlist({"127.0.0.1"})
        try:
            self._open_window()
            self._close_window()
            status, _, _ = self.request(
                "POST", "/mcp",
                {"Content-Type": "application/json"},
                json.dumps({"jsonrpc": "2.0", "id": 21, "method": "tools/call",
                            "params": {"name": "android_status",
                                       "arguments": {}}}).encode(),
            )
        finally:
            self._restore_allowlist(original)
        self.assertEqual(status, 403)

    def test_window_route_rejects_bearer_only(self):
        self.server.viewing_active = False
        status, _, _ = self.request(
            "POST", "/window",
            {"Content-Type": "application/x-www-form-urlencoded",
             "Authorization": "Bearer " + self.token},
            b"action=on",
        )
        self.assertEqual(status, 403)
        self.assertFalse(self.server.viewing_active)

    def test_window_opens_and_closes(self):
        status, _, _ = self._open_window()
        self.assertEqual(status, 200)
        self.assertTrue(self.server.viewing_active)
        status, _, _ = self._close_window()
        self.assertEqual(status, 200)
        self.assertFalse(self.server.viewing_active)


    def test_adb_version_is_reported_at_startup(self):
        self.assertEqual(adbctl.version(), "1.0.41")
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            bridge._log_adb_version()
        self.assertIn("adb available version=1.0.41", capture.getvalue())


    # ---------- gate: source AND viewing, never a bearer ----------

    def screenshot_call(self, headers=None):
        return self.request(
            "POST", "/mcp",
            {"Content-Type": "application/json", **(headers or {})},
            json.dumps({"jsonrpc": "2.0", "id": 30, "method": "tools/call",
                        "params": {"name": "android_screenshot",
                                   "arguments": {}}}).encode(),
        )

    def test_allowed_peer_viewing_on_can_screenshot_without_token(self):
        original = self._with_allowlist(True)
        try:
            self.server.viewing_active = True
            self.server.viewing_expires = time.monotonic() + 3600
            status, data, _ = self.screenshot_call()
        finally:
            self._restore_allowlist(original)
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(payload["result"]["content"][0]["type"], "image")

    def test_viewing_off_denies_even_with_a_valid_bearer(self):
        original = self._with_allowlist(True)
        try:
            self.server.viewing_active = False
            status, data, _ = self.screenshot_call(self.auth())
        finally:
            self._restore_allowlist(original)
        self.assertEqual(status, 403)
        self.assertNotIn(b'"result"', data)
        self.assertNotIn(b'"data"', data)

    def test_unknown_peer_denied_even_with_a_valid_bearer(self):
        original = self._with_allowlist(False)
        try:
            self.server.viewing_active = True
            self.server.viewing_expires = time.monotonic() + 3600
            status, data, _ = self.screenshot_call(self.auth())
        finally:
            self._restore_allowlist(original)
        self.assertEqual(status, 401)
        self.assertNotIn(b'"result"', data)

    def test_expired_viewing_denies_even_with_a_valid_bearer(self):
        original = self._with_allowlist(True)
        try:
            self.server.viewing_active = True
            self.server.viewing_expires = time.monotonic() + 3600
            self.server.viewing_expires = time.monotonic() - 1.0
            status, data, _ = self.screenshot_call(self.auth())
        finally:
            self._restore_allowlist(original)
        self.assertEqual(status, 403)
        self.assertNotIn(b'"result"', data)


    def test_zero_expiry_is_closed(self):
        original = self._with_allowlist(True)
        try:
            self.server.viewing_active = True
            self.server.viewing_expires = 0.0
            status, data, _ = self.screenshot_call(self.auth())
        finally:
            self._restore_allowlist(original)
        self.assertEqual(status, 403)
        self.assertNotIn(b'"result"', data)

    def test_missing_expiry_is_closed(self):
        original = self._with_allowlist(True)
        try:
            self.server.viewing_active = True
            if hasattr(self.server, "viewing_expires"):
                del self.server.viewing_expires
            status, data, _ = self.screenshot_call()
        finally:
            self._restore_allowlist(original)
        self.assertEqual(status, 403)

    def test_invalid_expiry_is_closed(self):
        original = self._with_allowlist(True)
        try:
            self.server.viewing_active = True
            self.server.viewing_expires = "not-a-number"
            status, data, _ = self.screenshot_call(self.auth())
        finally:
            self._restore_allowlist(original)
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
