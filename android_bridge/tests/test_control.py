"""Approval security: UI session, CSRF, binding, replay, expiry, STOP."""

import base64
import contextlib
import io
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
    print("connected to " + (args[1] if len(args) > 1 else "device"))
    sys.exit(0)
if args and args[0] == "disconnect":
    sys.exit(0)
if "-s" in args and "get-serialno" in args:
    print(os.environ.get("FAKE_ADB_SERIAL", "192.168.1.50:41234"))
    sys.exit(0)
if "-s" in args and "getprop" in args:
    print(os.environ.get("FAKE_ADB_MODEL", "SM_X210"))
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
        # Phase-3 work still exercises the approval flow: this fixture opts in
        # to the full known tool set explicitly, as a future release would.
        os.makedirs(bridge.private_dir(cls.data_dir), mode=0o700, exist_ok=True)
        tools_target = bridge.tools_path(cls.data_dir)
        with open(tools_target, "w", encoding="utf-8") as fh:
            json.dump({"expose_tools": sorted(bridge.KNOWN_MCP_TOOLS)}, fh)
        os.chmod(tools_target, 0o600)
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

    def tearDown(self):
        bridge.Handler._peer = self._orig_peer
        bridge.mcp_source_allowed = self._orig_mcp_source

    def setUp(self):
        self._orig_peer = bridge.Handler._peer
        self._orig_mcp_source = bridge.mcp_source_allowed
        bridge.mcp_source_allowed = lambda address: True
        self.server.allowed_users = frozenset({"alice"})
        self.set_peer("172.30.32.2")
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
        if "X-Ingress-Path" not in h:
            h["X-Ingress-Path"] = self.UI_PREFIX
        return self.req("POST", path, h, urllib.parse.urlencode(data).encode())

    def origin(self):
        return "http://127.0.0.1:%d" % self.port

    ORIGIN = "https://ha.example"
    UI_PREFIX = "/api/hassio_ingress/TESTTOKEN"

    def login(self, user="alice", origin=None, sfs=None):
        nonce, login_cookie = self.login_page()
        headers = {"Cookie": login_cookie}
        if user is not None:
            headers["X-Remote-User-Name"] = user
        if origin is not None:
            headers["Origin"] = origin
        if sfs:
            headers["Sec-Fetch-Site"] = sfs
        status, _, response = self.form("/control", {"nonce": nonce}, headers)
        self.assertEqual(status, 200)
        cookie = {"Cookie": response["Set-Cookie"].split(";", 1)[0]}
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        csrf = re.search(rb"name='csrf' value='([0-9a-f]+)'", page).group(1).decode()
        return cookie, csrf

    def ctl(self, path, data, cookie, csrf, origin=False, sfs=None):
        payload = dict(data)
        payload["csrf"] = csrf
        headers = dict(cookie)
        if origin is not False:
            headers["Origin"] = self.ORIGIN if origin is None else origin
        if sfs:
            headers["Sec-Fetch-Site"] = sfs
        return self.form(path, payload, headers)

    def set_peer(self, address):
        bridge.Handler._peer = lambda handler: address

    def set_ingress(self, on=True):
        self.set_peer("172.30.32.2" if on else "172.30.33.4")

    def login_page(self):
        status, page, headers = self.req("GET", "/control")
        self.assertEqual(status, 200)
        nonce = re.search(rb"name='nonce' value='([0-9a-f]+)'", page).group(1).decode()
        return nonce, headers["Set-Cookie"].split(";", 1)[0]

    def login_null(self):
        """Session created through ingress with no origin headers at all."""
        return self.login()

    def start_control(self):
        cookie, csrf = self.login()
        status, _, _ = self.ctl("/control/session", {"view": "on", "control": "on"}, cookie, csrf)
        self.assertIn(status, (200, 303))
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
        self.server.viewing_active = True
        self.server.viewing_expires = time.monotonic() + 3600
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

    def test_ingress_host_mismatch_is_accepted(self):
        """Origin equal to the sign-in origin, Host rewritten by the proxy."""
        cookie, csrf = self.login(origin=self.ORIGIN, sfs="same-origin")
        self.ctl("/control/session", {"view": "on", "control": "on"},
                 cookie, csrf, origin=self.ORIGIN)
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf},
            {**cookie,
             "Origin": self.ORIGIN,
             "Host": "69e5db10-android-bridge:8791"},
        )
        self.assertEqual(status, 303)
        self.assertIn("'input'", self.adb_log())

    def test_foreign_https_origin_without_metadata_is_rejected(self):
        """A valid HTTPS Origin that did not create the session is refused."""
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf},
            {**cookie, "Origin": "https://evil.example"},
        )
        self.assertEqual(status, 403)
        self.assertNotIn("'input'", self.adb_log())

    def test_foreign_origin_same_scheme_and_port_is_rejected(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf},
            {**cookie, "Origin": "https://ha.example:8443"},
        )
        self.assertEqual(status, 403)

    def test_session_without_bound_origin_rejects_a_real_origin(self):
        cookie, csrf = self.login_null()
        self.ctl("/control/session", {"view": "on", "control": "on"}, cookie, csrf,
                 origin="null", sfs="same-origin")
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf},
            {**cookie, "Origin": "https://ha.example",
             "Sec-Fetch-Site": "same-origin"},
        )
        self.assertEqual(status, 403)

    # ---------- opaque origin (live ingress behaviour) ----------

    def test_null_origin_with_same_origin_is_accepted(self):
        cookie, csrf = self.login_null()
        status, _, _ = self.ctl(
            "/control/session", {"view": "on", "control": "on"},
            cookie, csrf, origin="null", sfs="same-origin",
        )
        self.assertEqual(status, 303)
        key = self.new_proposal()
        status, _, _ = self.ctl(
            "/control/approve", {"id": key}, cookie, csrf,
            origin="null", sfs="same-origin",
        )
        self.assertEqual(status, 303)
        self.assertIn("'input'", self.adb_log())

    def test_null_origin_with_cross_site_is_rejected(self):
        cookie, csrf = self.login_null()
        self.ctl("/control/session", {"view": "on", "control": "on"}, cookie, csrf,
                 origin="null", sfs="same-origin")
        key = self.new_proposal()
        status, _, _ = self.ctl(
            "/control/approve", {"id": key}, cookie, csrf,
            origin="null", sfs="cross-site",
        )
        self.assertEqual(status, 403)
        self.assertNotIn("'input'", self.adb_log())

    def test_null_origin_with_same_site_is_rejected(self):
        cookie, csrf = self.login_null()
        self.ctl("/control/session", {"view": "on", "control": "on"}, cookie, csrf,
                 origin="null", sfs="same-origin")
        key = self.new_proposal()
        status, _, _ = self.ctl(
            "/control/approve", {"id": key}, cookie, csrf,
            origin="null", sfs="same-site",
        )
        self.assertEqual(status, 403)

    def test_null_origin_without_csrf_is_rejected(self):
        cookie, csrf = self.login_null()
        self.ctl("/control/session", {"view": "on", "control": "on"}, cookie, csrf,
                 origin="null", sfs="same-origin")
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key},
            {**cookie, "Origin": "null", "Sec-Fetch-Site": "same-origin"},
        )
        self.assertEqual(status, 403)
        self.assertNotIn("'input'", self.adb_log())

    def test_null_origin_without_session_is_rejected(self):
        status, _, _ = self.form(
            "/control/approve", {"id": "deadbeef", "csrf": "0" * 32},
            {"Origin": "null", "Sec-Fetch-Site": "same-origin"},
        )
        self.assertEqual(status, 403)

    def test_signin_with_null_origin_requires_fetch_metadata(self):
        status, _, headers = self.form(
            "/control", {"token": self.token}, {"Origin": "null"}
        )
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", headers)

    def test_rejection_log_includes_fetch_site(self):
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.form(
                "/control/approve", {"id": "x"},
                {"Origin": "null", "Sec-Fetch-Site": "cross-site"},
            )
        output = capture.getvalue()
        self.assertIn("control_forbidden reason=", output)
        self.assertIn("sfs=cross-site", output)

    def test_ingress_forwarded_host_is_accepted(self):
        cookie, csrf = self.login(origin=self.ORIGIN, sfs="same-origin")
        self.ctl("/control/session", {"view": "on", "control": "on"},
                 cookie, csrf, origin=self.ORIGIN)
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf},
            {**cookie, "Origin": "https://ha.example",
             "X-Forwarded-Host": "ha.example"},
        )
        self.assertEqual(status, 303)

    def test_ingress_same_origin_fetch_metadata_is_accepted(self):
        cookie, csrf = self.login(origin=self.ORIGIN, sfs="same-origin")
        self.ctl("/control/session", {"view": "on", "control": "on"},
                 cookie, csrf, origin=self.ORIGIN)
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf},
            {**cookie, "Origin": self.ORIGIN,
             "Sec-Fetch-Site": "same-origin"},
        )
        self.assertEqual(status, 303)

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
        self.assertEqual(status, 303)
        self.assertIn("'shell', 'input', 'tap', '540', '780'", self.adb_log())
        _, polled = self.result(key)
        state = json.loads(polled["result"]["content"][0]["text"])
        self.assertEqual(state["state"], "executed")
        self.assertEqual(polled["result"]["content"][1]["type"], "image")

    def test_replay_is_rejected(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        self.ctl("/control/approve", {"id": key}, cookie, csrf)
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertEqual(self.adb_log().count("'input'"), 1)

    def test_reject_prevents_execution(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.ctl("/control/reject", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        _, polled = self.result(key)
        self.assertEqual(json.loads(polled["result"]["content"][0]["text"])["state"], "rejected")
        self.assertNotIn("'input'", self.adb_log())

    def test_expired_approval_is_rejected(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        self.server.approvals.get(key)["expires"] = time.monotonic() - 1
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertNotIn("'input'", self.adb_log())

    def test_device_mismatch_is_rejected(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        # Device changes between proposal and approval.
        bridge.save_device(self.data_dir, "192.168.1.60", "41234")
        os.environ["FAKE_ADB_SERIAL"] = "192.168.1.60:41234"
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertNotIn("'input'", self.adb_log())

    def test_stop_cancels_pending_and_blocks_new(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.ctl("/control/stop", {}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIsNone(self.server.approvals.get(key))
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        status, payload, _ = self.req(
            "POST", "/mcp",
            {"Content-Type": "application/json"},
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "android_tap",
                                   "arguments": {"x": 13, "y": 14}}}).encode(),
        )
        self.assertEqual(status, 403)
        self.assertNotIn(b"result", payload)

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
        cookie, csrf = self.start_control()
        status, _, _ = self.ctl("/disconnect", {}, cookie, csrf)
        self.assertEqual(status, 303)
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


    def test_stale_cookie_does_not_mask_valid_one(self):
        cookie, csrf = self.login(origin=self.ORIGIN, sfs="same-origin")
        self.ctl("/control/session", {"view": "on", "control": "on"},
                 cookie, csrf, origin=self.ORIGIN)
        key = self.new_proposal()
        combined = "ab_ui=%s.%s; %s" % ("a" * 32, "b" * 64, cookie["Cookie"])
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf},
            {"Cookie": combined, "Origin": "https://ha.example",
             "X-Forwarded-Host": "ha.example"},
        )
        self.assertEqual(status, 303)

    def test_missing_session_reason_is_logged(self):
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.form(
                "/control/approve", {"id": "deadbeef"},
                {"Origin": "https://ha.example", "X-Forwarded-Host": "ha.example"},
            )
        self.assertIn("control_forbidden reason=session", capture.getvalue())

    def test_csrf_reason_is_logged(self):
        cookie, _ = self.start_control()
        key = self.new_proposal()
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.form(
                "/control/approve", {"id": key},
                {**cookie, "Origin": "https://ha.example",
                 "X-Forwarded-Host": "ha.example"},
            )
        self.assertIn("control_forbidden reason=csrf", capture.getvalue())

    def test_cross_site_reason_is_logged(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.form(
                "/control/approve", {"id": key, "csrf": csrf},
                {**cookie, "Origin": "https://evil.example",
                 "Sec-Fetch-Site": "cross-site"},
            )
        self.assertIn("control_forbidden reason=cross_site", capture.getvalue())


    # ---------- ingress peer (opaque origin, no fetch metadata) ----------

    def _enter_control_without_headers(self):
        """Sign in as an allowed HA user and enable control, no origin headers."""
        cookie, csrf = self.login()
        status, _, _ = self.form(
            "/control/session", {"view": "on", "control": "on", "csrf": csrf},
            cookie,
        )
        self.assertEqual(status, 303)
        return cookie, csrf

    def test_ingress_peer_without_origin_or_sfs_is_accepted(self):
        cookie, csrf = self._enter_control_without_headers()
        key = self.new_proposal()
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            status, _, _ = self.form(
                "/control/approve", {"id": key, "csrf": csrf}, cookie
            )
        self.assertEqual(status, 303)
        self.assertIn("reason=origin_null_ingress_ok", capture.getvalue())
        self.assertIn("'input'", self.adb_log())

    def test_ingress_peer_without_csrf_is_rejected(self):
        cookie, _csrf = self._enter_control_without_headers()
        key = self.new_proposal()
        status, _, _ = self.form("/control/approve", {"id": key}, cookie)
        self.assertEqual(status, 403)
        self.assertNotIn("'input'", self.adb_log())

    def test_ingress_peer_without_session_is_rejected(self):
        self.set_ingress(True)
        status, _, _ = self.form(
            "/control/approve", {"id": "deadbeef", "csrf": "0" * 32}, {}
        )
        self.assertEqual(status, 403)

    def test_non_ingress_peer_without_origin_is_rejected(self):
        cookie, csrf = self._enter_control_without_headers()
        self.set_ingress(False)
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf}, cookie
        )
        self.assertEqual(status, 403)

    def test_ingress_peer_with_cross_site_metadata_is_rejected(self):
        cookie, csrf = self._enter_control_without_headers()
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf},
            {**cookie, "Origin": "null", "Sec-Fetch-Site": "cross-site"},
        )
        self.assertEqual(status, 403)
        self.assertNotIn("'input'", self.adb_log())

    def test_ingress_peer_with_mismatched_origin_is_rejected(self):
        cookie, csrf = self._enter_control_without_headers()
        key = self.new_proposal()
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf},
            {**cookie, "Origin": "https://evil.example"},
        )
        self.assertEqual(status, 403)

    # ---------- login nonce ----------

    def test_login_with_nonce_from_ingress_is_accepted(self):
        self.set_ingress(True)
        nonce, login_cookie = self.login_page()
        status, _, headers = self.form(
            "/control", {"nonce": nonce},
            {"Cookie": login_cookie, "X-Remote-User-Name": "alice"},
        )
        self.assertEqual(status, 200)
        self.assertIn("Set-Cookie", headers)

    def test_login_without_nonce_is_rejected(self):
        status, _, headers = self.form(
            "/control", {}, {"X-Remote-User-Name": "alice"}
        )
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", headers)

    def test_login_nonce_is_single_use(self):
        self.set_ingress(True)
        nonce, login_cookie = self.login_page()
        first, _, _ = self.form(
            "/control", {"nonce": nonce},
            {"Cookie": login_cookie, "X-Remote-User-Name": "alice"},
        )
        self.assertEqual(first, 200)
        second, _, _ = self.form(
            "/control", {"nonce": nonce},
            {"Cookie": login_cookie, "X-Remote-User-Name": "alice"},
        )
        self.assertEqual(second, 403)

    def test_login_nonce_expires(self):
        self.set_ingress(True)
        nonce, login_cookie = self.login_page()
        self.server.login_nonces[nonce] = time.monotonic() - 1
        status, _, _ = self.form(
            "/control", {"token": self.token, "nonce": nonce},
            {"Cookie": login_cookie},
        )
        self.assertEqual(status, 403)

    def test_rejection_log_lists_header_names_only(self):
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.form(
                "/control/approve", {"id": "x", "csrf": "0" * 32},
                {"Origin": "https://evil.example",
                 "Sec-Fetch-Site": "cross-site",
                 "Cookie": "ab_ui=totally-invalid"},
            )
        output = capture.getvalue()
        self.assertIn("hdrs=", output)
        self.assertIn("origin", output)
        self.assertIn("sec-fetch-site", output)
        self.assertNotIn("evil.example", output)
        self.assertNotIn("totally-invalid", output)
        self.assertNotIn(self.token, output)


    # ---------- ingress peer must be exactly 172.30.32.2 ----------

    def test_null_origin_rejected_from_core_peer(self):
        cookie, csrf = self._enter_control_without_headers()
        key = self.new_proposal()
        self.set_peer("172.30.32.1")           # Home Assistant Core, not Supervisor
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf}, cookie
        )
        self.assertEqual(status, 403)
        self.assertNotIn("'input'", self.adb_log())

    def test_null_origin_rejected_from_arbitrary_peer(self):
        cookie, csrf = self._enter_control_without_headers()
        key = self.new_proposal()
        self.set_peer("172.30.33.4")           # another add-on
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf}, cookie
        )
        self.assertEqual(status, 403)
        self.assertNotIn("'input'", self.adb_log())

    def test_forwarded_for_does_not_grant_ingress(self):
        cookie, csrf = self._enter_control_without_headers()
        key = self.new_proposal()
        self.set_peer("172.30.33.9")
        status, _, _ = self.form(
            "/control/approve", {"id": key, "csrf": csrf},
            {**cookie, "X-Forwarded-For": "172.30.32.2"},
        )
        self.assertEqual(status, 403)

    def test_login_null_origin_rejected_from_non_supervisor_peer(self):
        self.set_ingress(True)
        nonce, login_cookie = self.login_page()
        self.set_peer("172.30.32.1")
        status, _, _ = self.form(
            "/control", {"token": self.token, "nonce": nonce},
            {"Cookie": login_cookie},
        )
        self.assertEqual(status, 403)

    def test_login_cookie_is_scoped_to_ingress_root(self):
        status, _, headers = self.req(
            "GET", "/control", {"X-Ingress-Path": "/api/hassio_ingress/AAA111"}
        )
        self.assertEqual(status, 200)
        cookie = headers.get("Set-Cookie", "")
        self.assertIn("Path=/api/hassio_ingress/", cookie)
        self.assertNotIn("AAA111", cookie)

    def test_login_nonce_survives_a_changed_ingress_token(self):
        status, page, headers = self.req(
            "GET", "/control", {"X-Ingress-Path": "/api/hassio_ingress/AAA111"}
        )
        nonce = re.search(rb"name='nonce' value='([0-9a-f]+)'", page).group(1).decode()
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.set_ingress(True)
        status, _, _ = self.form(
            "/control", {"nonce": nonce},
            {"Cookie": cookie, "X-Remote-User-Name": "alice",
             "X-Ingress-Path": "/api/hassio_ingress/BBB222"},
        )
        self.assertEqual(status, 200)


    # ---------- Home Assistant identity sign-in ----------

    def login_attempt(self, user="alice", peer="172.30.32.2", with_nonce=True,
                      extra=None):
        self.set_peer(peer)
        page_nonce, cookie = self.login_page()
        headers = {"Cookie": cookie}
        if user is not None:
            headers["X-Remote-User-Name"] = user
        headers.update(extra or {})
        data = {"nonce": page_nonce} if with_nonce else {}
        return self.form("/control", data, headers)

    def test_allowed_ha_user_creates_session(self):
        status, _, headers = self.login_attempt("alice")
        self.assertEqual(status, 200)
        self.assertIn("Set-Cookie", headers)

    def test_unknown_ha_user_is_rejected(self):
        status, _, headers = self.login_attempt("bob")
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", headers)

    def test_missing_ha_user_is_rejected(self):
        status, _, headers = self.login_attempt(None)
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", headers)

    def test_ha_user_from_non_supervisor_peer_is_rejected(self):
        for peer in ("172.30.32.1", "172.30.33.7"):
            with self.subTest(peer=peer):
                status, _, headers = self.login_attempt("alice", peer=peer)
                self.assertEqual(status, 403)
                self.assertNotIn("Set-Cookie", headers)

    def test_bearer_token_cannot_sign_in(self):
        nonce, cookie = self.login_page()
        status, _, headers = self.form(
            "/control", {"nonce": nonce},
            {"Cookie": cookie, "Authorization": "Bearer " + self.token},
        )
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", headers)

    def test_empty_allowlist_blocks_everyone(self):
        self.server.allowed_users = frozenset()
        status, _, headers = self.login_attempt("alice")
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", headers)

    def test_browser_control_posts_redirect_api_posts_return_json(self):
        cookie, csrf = self.start_control()
        status, _, headers = self.ctl(
            "/control/session", {"view": "on", "control": "on"}, cookie, csrf
        )
        self.assertEqual(status, 303)
        self.assertEqual(
            headers.get("Location"), self.UI_PREFIX + "/control?flash=session"
        )

        api, body, _ = self.form(
            "/pair", {"host": "192.168.1.50"},
            {"Authorization": "Bearer " + self.token},
        )
        self.assertEqual(api, 403)
        self.assertIn(b"forbidden", body)

        stop, body, _ = self.form(
            "/control/stop", {}, {"Authorization": "Bearer " + self.token}
        )
        self.assertEqual(stop, 200)
        self.assertIn(b"control", body)


    # ---------- ingress prefix for redirects ----------

    def test_redirects_stay_inside_the_ingress_prefix(self):
        cookie, csrf = self.start_control()
        status, _, headers = self.ctl(
            "/control/session", {"view": "on", "control": "on"}, cookie, csrf
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], self.UI_PREFIX + "/control?flash=session")

        key = self.new_proposal()
        status, _, headers = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], self.UI_PREFIX + "/control?flash=executed")

        key = self.new_proposal()
        status, _, headers = self.ctl("/control/reject", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], self.UI_PREFIX + "/control?flash=rejected")

        status, _, headers = self.ctl("/control/stop", {}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], self.UI_PREFIX + "/control?flash=stopped")

    def test_malformed_ingress_prefix_is_rejected(self):
        cookie, csrf = self.start_control()
        for bad in (
            "/control",
            "https://evil.example/api/hassio_ingress/x",
            "/api/hassio_ingress/../control",
            "/api/hassio_ingress/a/b",
            "/api/hassio_ingress/",
        ):
            with self.subTest(bad=bad):
                status, _, headers = self.form(
                    "/control/session",
                    {"view": "on", "control": "on", "csrf": csrf},
                    {**cookie, "X-Ingress-Path": bad},
                )
                self.assertEqual(status, 400)
                self.assertNotIn("Location", headers)

    def test_missing_ingress_prefix_from_supervisor_peer_is_rejected(self):
        cookie, csrf = self.start_control()
        status, _, headers = self.req(
            "POST", "/control/session",
            {"Content-Type": "application/x-www-form-urlencoded", **cookie},
            urllib.parse.urlencode(
                {"view": "on", "control": "on", "csrf": csrf}
            ).encode(),
        )
        self.assertEqual(status, 400)
        self.assertNotIn("Location", headers)

    def test_login_without_ingress_prefix_is_rejected(self):
        nonce, cookie = self.login_page()
        status, _, headers = self.req(
            "POST", "/control",
            {"Content-Type": "application/x-www-form-urlencoded",
             "Cookie": cookie, "X-Remote-User-Name": "alice"},
            urllib.parse.urlencode({"nonce": nonce}).encode(),
        )
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", headers)

    def test_display_name_without_username_is_rejected(self):
        nonce, cookie = self.login_page()
        status, _, headers = self.form(
            "/control", {"nonce": nonce},
            {"Cookie": cookie, "X-Remote-User-Display-Name": "Alice Smith"},
        )
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", headers)

    def test_username_is_matched_not_display_name(self):
        nonce, cookie = self.login_page()
        status, _, headers = self.form(
            "/control", {"nonce": nonce},
            {"Cookie": cookie, "X-Remote-User-Name": "alice",
             "X-Remote-User-Display-Name": "Someone Else"},
        )
        self.assertEqual(status, 200)
        self.assertIn("Set-Cookie", headers)

    def test_github_style_name_is_not_a_ha_username(self):
        status, _, headers = self.login_attempt("cj118")
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", headers)


    # ---------- flash rendering after redirect ----------

    def follow(self, location, cookie):
        path = (
            location[len(self.UI_PREFIX):]
            if location.startswith(self.UI_PREFIX)
            else location
        )
        return self.req("GET", path, cookie)

    def test_following_redirects_renders_each_flash(self):
        cookie, csrf = self.start_control()

        status, _, headers = self.ctl(
            "/control/session", {"view": "on", "control": "on"}, cookie, csrf
        )
        self.assertEqual(status, 303)
        status, page, _ = self.follow(headers["Location"], cookie)
        self.assertEqual(status, 200)
        self.assertIn(b"Session updated", page)

        key = self.new_proposal()
        status, _, headers = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        status, page, _ = self.follow(headers["Location"], cookie)
        self.assertEqual(status, 200)
        self.assertIn(b"approved and executed", page)

        key = self.new_proposal()
        status, _, headers = self.ctl("/control/reject", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        status, page, _ = self.follow(headers["Location"], cookie)
        self.assertEqual(status, 200)
        self.assertIn(b"Action rejected", page)

        status, _, headers = self.ctl("/control/stop", {}, cookie, csrf)
        self.assertEqual(status, 303)
        status, page, _ = self.follow(headers["Location"], cookie)
        self.assertEqual(status, 200)
        self.assertIn(b"STOP: control disabled", page)

    def test_every_flash_value_renders(self):
        cookie, _csrf = self.login()
        for flash, expected in (
            ("session", b"Session updated"),
            ("executed", b"approved and executed"),
            ("rejected", b"Action rejected"),
            ("stopped", b"STOP: control disabled"),
            ("ok", b"Done"),
            ("error", b"not completed"),
        ):
            with self.subTest(flash=flash):
                status, page, _ = self.req(
                    "GET", "/control?flash=" + flash, cookie
                )
                self.assertEqual(status, 200)
                self.assertIn(expected, page)

    def test_unknown_flash_is_ignored_and_escaped(self):
        cookie, _csrf = self.login()
        status, page, _ = self.req(
            "GET", "/control?flash=%3Cscript%3Ealert(1)%3C%2Fscript%3E", cookie
        )
        self.assertEqual(status, 200)
        self.assertNotIn(b"<script>", page)
        self.assertNotIn(b"alert(1)", page)

        status, page, _ = self.req("GET", "/control?flash=zzz", cookie)
        self.assertEqual(status, 200)
        self.assertNotIn(b"zzz", page)


    # ---------- pairing requires the HA-user session ----------

    def test_bearer_cannot_pair_connect_or_disconnect(self):
        cases = (
            ("/pair", {"host": "192.168.1.50", "pairing_port": "37123",
                       "code": "123456", "connect_port": "41234"}),
            ("/connect", {"host": "192.168.1.50", "connect_port": "41234"}),
            ("/disconnect", {}),
        )
        for path, data in cases:
            with self.subTest(path=path):
                status, body, _ = self.req(
                    "POST", path,
                    {"Content-Type": "application/x-www-form-urlencoded",
                     "Authorization": "Bearer " + self.token},
                    urllib.parse.urlencode(data).encode(),
                )
                self.assertEqual(status, 403)

    def test_pair_from_the_control_page_redirects_and_uses_stdin(self):
        cookie, csrf = self.start_control()
        stdin_log = os.path.join(self.tmp, "adb-stdin.log")
        if os.path.exists(stdin_log):
            os.unlink(stdin_log)
        os.environ["FAKE_ADB_STDIN"] = stdin_log
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            status, _, headers = self.ctl(
                "/pair",
                {"host": "192.168.1.50", "pairing_port": "37123",
                 "code": "123456", "connect_port": "41234"},
                cookie, csrf,
            )
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], self.UI_PREFIX + "/control?flash=paired")
        with open(stdin_log, encoding="utf-8") as handle:
            self.assertIn("123456", handle.read())
        self.assertNotIn("123456", self.adb_log())
        self.assertNotIn("123456", capture.getvalue())

        status, page, _ = self.follow(headers["Location"], cookie)
        self.assertEqual(status, 200)
        self.assertIn(b"Tablet paired and connected", page)

    def test_pair_saves_the_device_identity(self):
        cookie, csrf = self.start_control()
        status, _, _ = self.ctl(
            "/pair",
            {"host": "192.168.1.50", "pairing_port": "37123",
             "code": "123456", "connect_port": "41234"},
            cookie, csrf,
        )
        self.assertEqual(status, 303)
        info = bridge.load_device(self.data_dir)
        self.assertEqual(info["serial"], "192.168.1.50:41234")
        self.assertEqual(info["model"], "SM_X210")

    def test_connect_saves_the_device_identity(self):
        cookie, csrf = self.start_control()
        status, _, _ = self.ctl(
            "/connect",
            {"host": "192.168.1.50", "connect_port": "41234"},
            cookie, csrf,
        )
        self.assertIn(status, (200, 303))
        info = bridge.load_device(self.data_dir)
        self.assertEqual(info["serial"], "192.168.1.50:41234")
        self.assertEqual(info["model"], "SM_X210")

    def test_pair_rejects_bad_host_port_and_code(self):
        cookie, csrf = self.start_control()
        base = {"host": "192.168.1.50", "pairing_port": "37123",
                "code": "123456", "connect_port": "41234"}
        cases = (
            dict(base, host="8.8.8.8"),
            dict(base, host="example.com"),
            dict(base, host="127.0.0.1"),
            dict(base, pairing_port="0"),
            dict(base, connect_port="70000"),
            dict(base, code="12345"),
            dict(base, code="1234567"),
        )
        for case in cases:
            with self.subTest(case=case):
                status, _, _ = self.ctl("/pair", case, cookie, csrf)
                self.assertEqual(status, 400)

    def test_stop_blocks_every_screenshot_path(self):
        cookie, csrf = self.start_control()
        self.assertTrue(self.server.viewing_active)
        status, _, _ = self.ctl("/control/stop", {}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertFalse(self.server.viewing_active)
        status, body, _ = self.req(
            "GET", "/screenshot", {"Authorization": "Bearer " + self.token}
        )
        self.assertEqual(status, 403)
        self.assertIn(b"viewing_session_closed", body)


    def test_pair_with_unreadable_key_logs_safe_reason(self):
        cookie, csrf = self.start_control()
        key_dir = os.path.join(self.server.data_dir, ".android")
        os.makedirs(key_dir, mode=0o700, exist_ok=True)
        key = os.path.join(key_dir, "adbkey")
        with open(key, "wb") as handle:
            handle.write(b"key")
        os.chmod(key, 0o644)
        os.chown(key, os.geteuid(), os.getegid())
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            status, _, headers = self.ctl(
                "/pair",
                {"host": "192.168.1.50", "pairing_port": "37123",
                 "code": "123456", "connect_port": "41234"},
                cookie, csrf,
            )
        self.assertEqual(status, 303)
        self.assertIn("flash=pair_failed", headers["Location"])
        self.assertIn("pairing_failed reason=key_unreadable", capture.getvalue())
        self.assertNotIn("123456", capture.getvalue())


    def test_stop_denies_mcp_even_with_a_valid_bearer(self):
        cookie, csrf = self.start_control()
        status, _, _ = self.ctl("/control/stop", {}, cookie, csrf)
        self.assertEqual(status, 303)
        status, body, _ = self.req(
            "POST", "/mcp",
            {"Content-Type": "application/json",
             "Authorization": "Bearer " + self.token},
            json.dumps({"jsonrpc": "2.0", "id": 40, "method": "tools/call",
                        "params": {"name": "android_screenshot",
                                   "arguments": {}}}).encode(),
        )
        self.assertEqual(status, 403)
        self.assertNotIn(b'"result"', body)


    def test_panel_shows_expired_viewing_as_off(self):
        cookie, _csrf = self.login()
        self.server.viewing_active = True
        self.server.viewing_expires = time.monotonic() - 1
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        self.assertIn(b"Viewing session: <b>off</b>", page)

    def test_panel_shows_active_viewing_as_on(self):
        cookie, _csrf = self.login()
        self.server.viewing_active = True
        self.server.viewing_expires = time.monotonic() + 60
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        self.assertIn(b"Viewing session: <b>ON</b>", page)


if __name__ == "__main__":
    unittest.main()
