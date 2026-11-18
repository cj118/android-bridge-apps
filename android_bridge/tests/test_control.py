"""Approval security: UI session, CSRF, binding, replay, expiry, STOP."""

import base64
import json
import os
import re
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
import os, sys
args = sys.argv[1:]
log = os.environ.get("FAKE_ADB_LOG")
if log:
    with open(log, "a") as fh:
        fh.write(repr(args) + "\n")
if args and args[0] == "devices":
    print("List of devices attached")
    print(os.environ.get("FAKE_ADB_SERIAL", "192.168.1.50:41234") + "\tdevice product:x model:SM_X210 device:y")
    sys.exit(0)
if args and args[0] in ("connect", "disconnect"):
    sys.exit(0)
if "-s" in args and "exec-out" in args:
    with open(os.environ["FAKE_ADB_PNG"], "rb") as fh:
        sys.stdout.buffer.write(fh.read())
    sys.exit(0)
if len(args) > 4 and args[2:4] == ["shell", "input"] and args[4] in ("tap", "swipe", "text"):
    sys.exit(0)
sys.exit(7)
'''


def make_png(w=1920, h=1200):
    return (b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR"
            + struct.pack(">II", w, h) + b"\x00" * 9)


class ControlSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="bridge-ctl-")
        cls.png = make_png()
        cls.png_path = os.path.join(cls.tmp, "frame.png")
        with open(cls.png_path, "wb") as fh:
            fh.write(cls.png)
        adb = os.path.join(cls.tmp, "adb")
        with open(adb, "w") as fh:
            fh.write(FAKE_ADB)
        os.chmod(adb, 0o755)
        adbctl.ADB_BINARY = adb
        cls.log_path = os.path.join(cls.tmp, "adb.log")
        os.environ["FAKE_ADB_LOG"] = cls.log_path
        os.environ["FAKE_ADB_PNG"] = cls.png_path

        cls.data_dir = os.path.join(cls.tmp, "data")
        os.makedirs(cls.data_dir, 0o700)
        cls.server = bridge.create_server("127.0.0.1", 0, data_dir=cls.data_dir)
        cls.port = cls.server.server_address[1]
        bridge.save_device(cls.data_dir, "192.168.1.50", "41234")
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        with open(bridge.token_path(cls.data_dir), "rb") as fh:
            cls.token = fh.read().strip().decode()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.server.viewing_active = False
        self.server.control_active = False
        self.server.approvals.clear()
        self.server.capture_times.clear()
        os.environ["FAKE_ADB_SERIAL"] = "192.168.1.50:41234"
        bridge.save_device(self.data_dir, "192.168.1.50", "41234")
        open(self.log_path, "w").close()

    # ---------- helpers ----------

    def req(self, method, path, headers=None, body=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            r = conn.getresponse()
            return r.status, r.read(), dict(r.getheaders())
        finally:
            conn.close()

    def form(self, path, data, headers=None):
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        h.update(headers or {})
        return self.req("POST", path, h, urllib.parse.urlencode(data).encode())

    def origin(self):
        return "http://127.0.0.1:%d" % self.port

    def login(self):
        status, _, headers = self.form("/control", {"token": self.token})
        self.assertEqual(status, 200)
        cookie = {"Cookie": headers["Set-Cookie"].split(";", 1)[0]}
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        csrf = re.search(rb"name='csrf' value='([0-9a-f]+)'", page).group(1).decode()
        return cookie, csrf

    def ctl(self, path, data, cookie, csrf):
        payload = dict(data)
        payload["csrf"] = csrf
        return self.form(path, payload, {**cookie, "Origin": self.origin()})

    def start_control(self):
        cookie, csrf = self.login()
        status, _, _ = self.ctl("/control/session", {"view": "on", "control": "on"}, cookie, csrf)
        self.assertEqual(status, 200)
        return cookie, csrf

    def mcp(self, payload):
        body = json.dumps(payload).encode()
        status, data, _ = self.req(
            "POST", "/mcp",
            {"Content-Type": "application/json",
             "Authorization": "Bearer " + self.token},
            body,
        )
        return status, json.loads(data)

    def propose(self, tool, args):
        return self.mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": tool, "arguments": args}})

    def result(self, key):
        return self.mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "android_action_result",
                                    "arguments": {"id": key}}})

    def new_proposal(self):
        _, payload = self.propose("android_tap", {"x": 540, "y": 780})
        text = payload["result"]["content"][0]["text"]
        return json.loads(text)["approval_id"]

    def adb_log(self):
        with open(self.log_path) as fh:
            return fh.read()

    def bearer(self):
        return {"Authorization": "Bearer " + self.token}

    # ---------- proposal ----------

    def test_proposal_requires_control_session(self):
        _, payload = self.propose("android_tap", {"x": 10, "y": 20})
        self.assertTrue(payload["result"]["isError"])
        self.assertEqual(payload["result"]["content"][0]["text"], "control_session_inactive")

    def test_proposal_returns_pending_with_preshot(self):
        self.start_control()
        _, payload = self.propose("android_tap", {"x": 540, "y": 780})
        summary = json.loads(payload["result"]["content"][0]["text"])
        self.assertEqual(summary["state"], "pending")
        self.assertIn("Tap (540, 780)", summary["action"])
        self.assertEqual(payload["result"]["content"][1]["type"], "image")
        self.assertEqual(base64.b64decode(payload["result"]["content"][1]["data"]), self.png)
        self.assertNotIn("'input'", self.adb_log())

    # ---------- bearer must not authorise control ----------

    def test_bearer_cannot_approve(self):
        self.start_control()
        key = self.new_proposal()
        status, _, _ = self.form("/control/approve", {"id": key}, self.bearer())
        self.assertEqual(status, 403)
        self.assertEqual(self.server.approvals.get(key)["state"], "pending")
        self.assertNotIn("'input'", self.adb_log())

    def test_bearer_cannot_enable_control(self):
        status, _, _ = self.form(
            "/control/session", {"control": "on"}, self.bearer()
        )
        self.assertEqual(status, 403)
        self.assertFalse(self.server.control_active)

    def test_bearer_cannot_reject(self):
        self.start_control()
        key = self.new_proposal()
        status, _, _ = self.form("/control/reject", {"id": key}, self.bearer())
        self.assertEqual(status, 403)
        self.assertEqual(self.server.approvals.get(key)["state"], "pending")

    def test_bearer_can_emergency_stop(self):
        self.start_control()
        key = self.new_proposal()
        status, _, _ = self.form("/control/stop", {}, self.bearer())
        self.assertEqual(status, 200)
        self.assertFalse(self.server.control_active)
        self.assertIsNone(self.server.approvals.get(key))

    # ---------- CSRF ----------

    def test_missing_csrf_is_forbidden(self):
        cookie, _ = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key},
            {**cookie, "Origin": self.origin()},
        )
        self.assertEqual(status, 403)
        self.assertNotIn("'input'", self.adb_log())

    def test_wrong_csrf_is_forbidden(self):
        cookie, _ = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": "0" * 32},
            {**cookie, "Origin": self.origin()},
        )
        self.assertEqual(status, 403)

    def test_cross_site_request_is_forbidden(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf},
            {**cookie, "Origin": "http://evil.example",
             "Sec-Fetch-Site": "cross-site"},
        )
        self.assertEqual(status, 403)
        self.assertNotIn("'input'", self.adb_log())

    def test_foreign_origin_without_fetch_metadata_is_forbidden(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf},
            {**cookie, "Origin": "http://evil.example"},
        )
        self.assertEqual(status, 403)

    def test_ingress_request_without_origin_is_allowed(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf}, cookie
        )
        self.assertEqual(status, 200)
        self.assertIn("'input'", self.adb_log())

    def test_ingress_forwarded_host_is_accepted(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf},
            {**cookie, "Origin": "https://ha.example",
             "X-Forwarded-Host": "ha.example"},
        )
        self.assertEqual(status, 200)

    def test_ingress_same_origin_fetch_metadata_is_accepted(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf},
            {**cookie, "Origin": "https://ha.example",
             "Sec-Fetch-Site": "same-origin"},
        )
        self.assertEqual(status, 200)

    def test_csrf_is_bound_to_session(self):
        _, csrf_a = self.start_control()
        cookie_b, _ = self.login()
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf_a},
            {**cookie_b, "Origin": self.origin()},
        )
        self.assertEqual(status, 403)

    # ---------- execution ----------

    def test_approve_executes_and_returns_postshot(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 200)
        self.assertIn("'shell', 'input', 'tap', '540', '780'", self.adb_log())
        _, polled = self.result(key)
        state = json.loads(polled["result"]["content"][0]["text"])
        self.assertEqual(state["state"], "executed")
        self.assertEqual(polled["result"]["content"][1]["type"], "image")

    def test_replay_is_rejected(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        self.ctl("/control/approve", {"id": key}, cookie, csrf)
        status, body, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 409)
        self.assertIn(b"not pending", body)

    def test_reject_prevents_execution(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.ctl("/control/reject", {"id": key}, cookie, csrf)
        self.assertEqual(status, 200)
        _, polled = self.result(key)
        self.assertEqual(json.loads(polled["result"]["content"][0]["text"])["state"], "rejected")
        self.assertNotIn("'input'", self.adb_log())

    def test_expired_approval_is_rejected(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        self.server.approvals.get(key)["expires"] = time.monotonic() - 1
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 409)
        self.assertNotIn("'input'", self.adb_log())

    def test_device_mismatch_is_rejected(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        # Device changes between proposal and approval.
        bridge.save_device(self.data_dir, "192.168.1.60", "41234")
        os.environ["FAKE_ADB_SERIAL"] = "192.168.1.60:41234"
        status, body, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 409)
        self.assertIn(b"device mismatch", body)
        self.assertNotIn("'input'", self.adb_log())

    def test_stop_cancels_pending_and_blocks_new(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.ctl("/control/stop", {}, cookie, csrf)
        self.assertEqual(status, 200)
        self.assertIsNone(self.server.approvals.get(key))
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 409)
        _, payload = self.propose("android_tap", {"x": 13, "y": 14})
        self.assertEqual(payload["result"]["content"][0]["text"], "control_session_inactive")

    def test_text_metacharacters_rejected(self):
        self.start_control()
        _, payload = self.propose("android_text", {"text": "hello; rm -rf /"})
        self.assertTrue(payload["result"]["isError"])

    def test_viewing_and_control_are_independent(self):
        cookie, csrf = self.start_control()
        self.ctl("/control/session", {"view": "on", "control": "off"}, cookie, csrf)
        status, _, _ = self.req("GET", "/screenshot", self.bearer())
        self.assertEqual(status, 200)
        _, payload = self.propose("android_tap", {"x": 1, "y": 1})
        self.assertEqual(payload["result"]["content"][0]["text"], "control_session_inactive")

    def test_disconnect_ends_sessions(self):
        self.start_control()
        status, _, _ = self.form("/disconnect", {"token": self.token}, {})
        self.assertEqual(status, 200)
        self.assertFalse(self.server.control_active)
        self.assertFalse(self.server.viewing_active)


    def test_root_redirects_to_control(self):
        status, _, headers = self.req("GET", "/")
        self.assertEqual(status, 302)
        self.assertEqual(headers.get("Location"), "/control")

    def test_root_redirect_respects_ingress_prefix(self):
        status, _, headers = self.req(
            "GET", "/", {"X-Ingress-Path": "/api/hassio_ingress/abc123"}
        )
        self.assertEqual(status, 302)
        self.assertEqual(headers.get("Location"), "/api/hassio_ingress/abc123/control")

    def test_index_also_redirects(self):
        status, _, headers = self.req("GET", "/index.html")
        self.assertEqual(status, 302)
        self.assertEqual(headers.get("Location"), "/control")


if __name__ == "__main__":
    unittest.main()
