"""Approval security: UI session, CSRF, binding, replay, expiry, STOP."""

import base64
import binascii
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
import zlib
from html.parser import HTMLParser
from http.client import HTTPConnection

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(os.path.dirname(HERE), "app")
sys.path.insert(0, APP_DIR)

import server as bridge  # noqa: E402
import adbctl  # noqa: E402
import control as control_actions  # noqa: E402

FAKE_ADB = r'''#!/usr/bin/env python3
import os, sys, time
args = sys.argv[1:]
log = os.environ.get("FAKE_ADB_LOG")
if log:
    with open(log, "a") as fh:
        fh.write(repr(args) + "\n")
server = os.environ.get("FAKE_ADB_SERVER", "ok")
if args and args[0] == "start-server":
    if server == "down":
        sys.stderr.write("error: cannot connect to daemon at tcp:localhost:5037: failed to start daemon\n")
        sys.exit(1)
    print("* daemon started successfully")
    sys.exit(0)
if server == "down":
    sys.stderr.write("error: cannot connect to daemon at tcp:localhost:5037\n")
    sys.exit(1)
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
    if args[-1] == "ro.serialno":
        print(os.environ.get("FAKE_ADB_HW_SERIAL", "R5CT12345678"))
    else:
        print(os.environ.get("FAKE_ADB_MODEL", "SM_X210"))
    sys.exit(0)
if len(args) > 4 and args[2:4] == ["shell", "dumpsys"]:
    print(os.environ.get(
        "FAKE_ADB_FOREGROUND",
        "  mCurrentFocus=Window{2f8e1 u0 "
        "com.android.settings/com.android.settings.Settings}",
    ))
    sys.exit(0)
if len(args) > 4 and args[2:4] == ["shell", "uiautomator"]:
    if not os.environ.get("FAKE_ADB_UI_DUMP"):
        sys.exit(7)
    print("UI hierchary dumped to: /sdcard/window_dump.xml")
    sys.exit(0)
if len(args) > 3 and args[2] == "exec-out" and args[3] == "cat":
    path = os.environ.get("FAKE_ADB_UI_DUMP")
    if not path:
        sys.exit(7)
    with open(path, "rb") as fh:
        sys.stdout.buffer.write(fh.read())
    sys.exit(0)
if "-s" in args and "exec-out" in args:
    sleep = float(os.environ.get("FAKE_ADB_SCREENCAP_SLEEP", "0") or "0")
    if sleep:
        time.sleep(sleep)
    mode = os.environ.get("FAKE_ADB_SCREENCAP_MODE", "ok")
    counter_path = os.environ.get("FAKE_ADB_SCREENCAP_COUNTER")
    count = 0
    if counter_path:
        try:
            with open(counter_path) as fh:
                count = int(fh.read().strip() or "0")
        except (OSError, ValueError):
            count = 0
        count += 1
        with open(counter_path, "w") as fh:
            fh.write(str(count))
    fail_after = int(os.environ.get("FAKE_ADB_SCREENCAP_FAIL_AFTER", "0") or "0")
    if mode == "fail" or (fail_after and count > fail_after):
        sys.exit(1)
    if mode == "garbage":
        sys.stdout.buffer.write(b"not-a-png")
        sys.exit(0)
    with open(os.environ["FAKE_ADB_PNG"], "rb") as fh:
        sys.stdout.buffer.write(fh.read())
    sys.exit(0)
if len(args) > 4 and args[2:4] == ["shell", "input"] and args[4] in ("tap", "swipe", "text"):
    if os.environ.get("FAKE_ADB_INPUT_FAIL"):
        sys.exit(1)
    sys.exit(0)
sys.exit(7)
'''


UI_DUMP_TAP_TARGET = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
        bounds="[0,0][1920,1200]" clickable="false" visible-to-user="true">
    <node index="0" text="Living Room TV" resource-id="com.x:id/tv"
          class="android.widget.Button" bounds="[400,700][700,860]"
          clickable="true" visible-to-user="true" />
  </node>
</hierarchy>
"""

UI_DUMP_TARGET_MOVED = UI_DUMP_TAP_TARGET.replace(
    "[400,700][700,860]", "[410,700][700,860]"
)
UI_DUMP_TARGET_RENAMED = UI_DUMP_TAP_TARGET.replace(
    "Living Room TV", "Kitchen Light"
)

UI_DUMP_SECRET = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
        bounds="[0,0][1920,1200]" clickable="false" visible-to-user="true">
    <node index="0" text="hunter2" resource-id="com.x:id/pass"
          class="android.widget.EditText" password="true"
          bounds="[400,700][700,860]" clickable="true"
          visible-to-user="true" />
  </node>
</hierarchy>
"""

UI_DUMP_TEXT_FIELD = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
        bounds="[0,0][1920,1200]" clickable="false" visible-to-user="true">
    <node index="0" text="Search settings"
          resource-id="com.android.settings:id/search_src_text"
          class="android.widget.EditText" bounds="[400,700][1500,860]"
          focused="true" clickable="true" visible-to-user="true" />
  </node>
</hierarchy>
"""

UI_DUMP_TEXT_FIELD_MOVED = UI_DUMP_TEXT_FIELD.replace(
    "[400,700][1500,860]", "[400,720][1500,880]"
)
UI_DUMP_TEXT_FIELD_BLURRED = UI_DUMP_TEXT_FIELD.replace(
    'focused="true"', 'focused="false"'
)
UI_DUMP_TEXT_FIELD_HIDDEN = UI_DUMP_TEXT_FIELD.replace(
    'visible-to-user="true"', 'visible-to-user="false"'
)

UI_DUMP_PASSWORD_FIELD = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
        bounds="[0,0][1920,1200]" clickable="false" visible-to-user="true">
    <node index="0" text="hunter2" resource-id="com.android.settings:id/password"
          class="android.widget.EditText" password="true"
          bounds="[400,700][1500,860]" focused="true" clickable="true"
          visible-to-user="true" />
  </node>
</hierarchy>
"""

UI_DUMP_PIN_FIELD = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
        bounds="[0,0][1920,1200]" clickable="false" visible-to-user="true">
    <node index="0" text="1234" resource-id="com.android.settings:id/pin_entry"
          class="android.widget.EditText" bounds="[400,700][1500,860]"
          focused="true" clickable="true" visible-to-user="true" />
  </node>
</hierarchy>
"""

UI_DUMP_CARD_FIELD = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
        bounds="[0,0][1920,1200]" clickable="false" visible-to-user="true">
    <node index="0" text="4111 1111 1111 1111"
          resource-id="com.android.settings:id/card_number"
          class="android.widget.EditText" bounds="[400,700][1500,860]"
          focused="true" clickable="true" visible-to-user="true" />
  </node>
</hierarchy>
"""

UI_DUMP_TWO_FIELDS = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
        bounds="[0,0][1920,1200]" clickable="false" visible-to-user="true">
    <node index="0" text="" resource-id="com.android.settings:id/first"
          class="android.widget.EditText" bounds="[400,700][900,860]"
          focused="true" clickable="true" visible-to-user="true" />
    <node index="1" text="" resource-id="com.android.settings:id/second"
          class="android.widget.EditText" bounds="[1000,700][1500,860]"
          focused="true" clickable="true" visible-to-user="true" />
  </node>
</hierarchy>
"""

UI_DUMP_BLANK = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
        bounds="[0,0][1920,1200]" clickable="false" visible-to-user="true" />
</hierarchy>
"""

UI_DUMP_ESCAPE = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
        bounds="[0,0][1920,1200]" clickable="false" visible-to-user="true">
    <node index="0" text="&lt;b&gt;&amp;&quot;x&quot;" resource-id=""
          class="android.widget.Button" bounds="[400,700][700,860]"
          clickable="true" visible-to-user="true" />
  </node>
</hierarchy>
"""


def _png_chunk(kind, payload):
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)
    )


def make_png(w=1920, h=1200, blocks=()):
    """A valid deterministic RGBA PNG, with optional solid rectangles."""
    base = bytes((245, 245, 245, 255)) * w
    raw = bytearray()
    for y in range(h):
        line = bytearray(base)
        for x1, y1, x2, y2, red, green, blue, alpha in blocks:
            if y1 <= y < y2:
                line[max(0, x1) * 4:min(w, x2) * 4] = bytes(
                    (red, green, blue, alpha)
                ) * max(0, min(w, x2) - max(0, x1))
        raw.append(0)
        raw.extend(line)
    header = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", header)
        + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 6))
        + _png_chunk(b"IEND", b"")
    )


class RenderedPage(HTMLParser):
    """Record the visible text, tags and POST form fields of real HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.tags = []
        self.forms = []
        self.form_starts = 0
        self.form_ends = 0
        self.attribute_values = []
        self._open_forms = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append(tag)
        self.attribute_values.extend(
            value for value in attrs.values() if value is not None
        )
        if tag == "form":
            self.form_starts += 1
            form = {"attrs": attrs, "inputs": []}
            self.forms.append(form)
            self._open_forms.append(form)
        elif tag == "input" and self._open_forms:
            self._open_forms[-1]["inputs"].append(attrs)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "form":
            self.form_ends += 1
            if self._open_forms:
                self._open_forms.pop()

    def handle_data(self, data):
        self.text.append(data)

    @property
    def visible_text(self):
        return "".join(self.text)


class ControlSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="bridge-ctl-")
        cls.png = make_png()
        cls.png_path = os.path.join(cls.tmp, "frame.png")
        cls.screen_counter = os.path.join(cls.tmp, "screen-count")
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
        os.environ["FAKE_ADB_HW_SERIAL"] = "R5CT12345678"
        os.environ["FAKE_ADB_MODEL"] = "SM_X210"
        os.environ["FAKE_ADB_FOREGROUND"] = (
            "  mCurrentFocus=Window{2f8e1 u0 "
            "com.android.settings/com.android.settings.Settings}"
        )
        os.environ["FAKE_ADB_SERVER"] = "ok"
        os.environ["FAKE_ADB_SCREENCAP_MODE"] = "ok"
        os.environ["FAKE_ADB_SCREENCAP_FAIL_AFTER"] = "0"
        os.environ["FAKE_ADB_SCREENCAP_SLEEP"] = "0"
        os.environ["FAKE_ADB_SCREENCAP_COUNTER"] = self.screen_counter
        os.environ.pop("FAKE_ADB_UI_DUMP", None)
        os.environ.pop("FAKE_ADB_INPUT_FAIL", None)
        # A stable identified target at the default proposal point (540, 780)
        # keeps the approval path exercised; tests that need an inspection
        # failure remove it explicitly.
        self.set_ui_dump(UI_DUMP_TAP_TARGET)
        adbctl.reset_server_state()
        with open(self.png_path, "wb") as handle:
            handle.write(self.png)
        with open(self.screen_counter, "w") as handle:
            handle.write("0")
        self.server.last_proposal_at = 0.0
        self.server.control_minutes = bridge.CONTROL_MINUTES_DEFAULT
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
        self.server.last_proposal_at = 0.0
        self.server.capture_times.clear()
        _, payload = self.propose(
            "android_tap",
            {"x": 540, "y": 780, "reason": "test harmlessly"},
        )
        text = payload["result"]["content"][0]["text"]
        return json.loads(text)["approval_id"]

    def set_ui_dump(self, xml):
        path = os.path.join(self.tmp, "window_dump.xml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(xml)
        os.environ["FAKE_ADB_UI_DUMP"] = path

    def set_screen(self, data):
        with open(self.png_path, "wb") as handle:
            handle.write(data)
        self.server.capture_times.clear()

    def adb_log(self):
        with open(self.log_path) as fh:
            return fh.read()

    def bearer(self):
        return {"Authorization": "Bearer " + self.token}

    # ---------- proposal ----------

    def test_proposal_requires_control_session(self):
        self.server.viewing_active = True
        self.server.viewing_expires = time.monotonic() + 3600
        _, payload = self.propose(
            "android_tap", {"x": 10, "y": 20, "reason": "test"}
        )
        self.assertTrue(payload["result"]["isError"])
        self.assertEqual(payload["result"]["content"][0]["text"], "control_session_inactive")

    def test_proposal_returns_pending_with_preshot(self):
        self.start_control()
        _, payload = self.propose(
            "android_tap", {"x": 540, "y": 780, "reason": "test click"}
        )
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
                                   "arguments": {"x": 13, "y": 14,
                                                 "reason": "blocked"}}}).encode(),
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
        _, payload = self.propose(
            "android_tap", {"x": 1, "y": 1, "reason": "test"}
        )
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
        self.assertEqual(info["serial"], "R5CT12345678")
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
        self.assertEqual(info["serial"], "R5CT12345678")
        self.assertEqual(info["model"], "SM_X210")

    # ---------- connect saved tablet (no pairing) ----------

    def test_connect_saved_reconnects_without_pairing_and_saves_identity(self):
        cookie, csrf = self.start_control()
        status, _, headers = self.ctl("/control/reconnect", {}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertEqual(
            headers["Location"], self.UI_PREFIX + "/control?flash=reconnected"
        )
        log = self.adb_log()
        self.assertIn("['connect', '192.168.1.50:41234']", log)
        self.assertNotIn("'pair'", log)
        info = bridge.load_device(self.data_dir)
        self.assertEqual(info["serial"], "R5CT12345678")
        self.assertEqual(info["model"], "SM_X210")
        self.assertTrue(self.server.viewing_active)
        self.assertTrue(self.server.control_active)

    def test_connect_saved_requires_ui_session_and_csrf(self):
        status, _, _ = self.form("/control/reconnect", {})
        self.assertEqual(status, 403)
        cookie, _csrf = self.login()
        status, _, _ = self.form("/control/reconnect", {}, cookie)
        self.assertEqual(status, 403)
        status, _, _ = self.req(
            "POST", "/control/reconnect",
            {"Content-Type": "application/x-www-form-urlencoded",
             "Authorization": "Bearer " + self.token},
            b"",
        )
        self.assertEqual(status, 403)

    def test_connect_saved_rejects_a_foreign_origin(self):
        cookie, csrf = self.start_control()
        status, _, _ = self.ctl(
            "/control/reconnect", {}, cookie, csrf,
            origin="https://evil.example",
        )
        self.assertEqual(status, 403)
        self.assertNotIn("'connect'", self.adb_log())

    def test_connect_saved_refuses_conflicting_identity(self):
        cookie, csrf = self.start_control()
        bridge.save_device(
            self.data_dir, "192.168.1.50", "41234",
            {"serial": "192.168.1.50:41234", "model": "SM-T870"},
        )
        path = bridge.device_path(self.data_dir)
        with open(path, "rb") as handle:
            before = handle.read()
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            status, _, headers = self.ctl("/control/reconnect", {}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("flash=reconnect_failed", headers["Location"])
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), before)
        self.assertIn(
            "saved_connect_failed reason=identity_conflict", capture.getvalue()
        )
        self.assertIn("['disconnect', '192.168.1.50:41234']", self.adb_log())

    def test_connect_saved_fails_when_identity_cannot_be_read(self):
        cookie, csrf = self.start_control()
        os.environ["FAKE_ADB_MODEL"] = ""
        self.addCleanup(os.environ.pop, "FAKE_ADB_MODEL", None)
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            status, _, headers = self.ctl("/control/reconnect", {}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("flash=reconnect_failed", headers["Location"])
        self.assertIn(
            "saved_connect_failed reason=identity_unverified", capture.getvalue()
        )
        info = bridge.load_device(self.data_dir)
        self.assertNotIn("serial", info)
        self.assertNotIn("model", info)

    def test_connect_saved_without_a_saved_device(self):
        cookie, csrf = self.start_control()
        os.unlink(bridge.device_path(self.data_dir))
        status, _, headers = self.ctl("/control/reconnect", {}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("flash=reconnect_failed", headers["Location"])
        self.assertNotIn("'connect'", self.adb_log())

    def test_panel_offers_connect_saved(self):
        cookie, _csrf = self.login()
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        self.assertIn(b"Connect saved tablet", page)
        self.assertIn(b"192.168.1.50:41234", page)

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


    # ---------- control page markup ----------

    def render_control_page(self):
        cookie, csrf = self.login()
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        parser = RenderedPage()
        parser.feed(page.decode("utf-8"))
        parser.close()
        return cookie, csrf, page, parser

    def test_control_page_never_shows_the_csrf_token_as_text(self):
        _cookie, csrf, _page, parser = self.render_control_page()
        self.assertTrue(csrf)
        self.assertNotIn(csrf, parser.visible_text)
        # The token is allowed in attributes, never inside injected markup.
        for value in parser.attribute_values:
            self.assertNotIn("<form", value)
            self.assertNotIn("<input", value)

    def test_every_post_form_has_exactly_one_hidden_csrf_field(self):
        _cookie, csrf, _page, parser = self.render_control_page()
        post_forms = [
            form for form in parser.forms
            if form["attrs"].get("method", "").lower() == "post"
        ]
        self.assertTrue(post_forms)
        actions = [form["attrs"].get("action", "") for form in post_forms]
        self.assertIn("pair", actions)
        self.assertIn("control/reconnect", actions)
        self.assertIn("control/session", actions)
        self.assertIn("control/stop", actions)
        self.assertIn("disconnect", actions)
        for form in post_forms:
            hidden = [
                field for field in form["inputs"]
                if field.get("type", "").lower() == "hidden"
                and field.get("name") == "csrf"
            ]
            self.assertEqual(
                len(hidden), 1, "form %r" % form["attrs"].get("action")
            )
            self.assertEqual(hidden[0].get("value"), csrf)

    def test_control_page_has_no_stray_quote_or_broken_tags(self):
        _cookie, _csrf, _page, parser = self.render_control_page()
        text = parser.visible_text
        self.assertNotIn("'>", text)
        self.assertNotIn('">', text)
        self.assertNotIn("<form", text)
        self.assertNotIn("</form", text)
        self.assertNotIn("<input", text)
        self.assertEqual(parser.form_starts, parser.form_ends)
        self.assertEqual(parser.form_starts, len(parser.forms))

    def test_reconnect_form_escapes_saved_host_and_port(self):
        bridge.save_device(
            self.data_dir,
            "10.0.0.1'><script>alert(1)</script>",
            "41'234",
        )
        _cookie, _csrf, page, parser = self.render_control_page()
        self.assertNotIn("script", parser.tags)
        self.assertIn(
            b"10.0.0.1&#x27;&gt;&lt;script&gt;alert(1)&lt;/script&gt;", page
        )
        self.assertIn(b"41&#x27;234", page)

    def test_parsed_reconnect_form_submits_successfully(self):
        cookie, csrf, _page, parser = self.render_control_page()
        forms = [
            form for form in parser.forms
            if form["attrs"].get("action", "").endswith("control/reconnect")
        ]
        self.assertEqual(len(forms), 1)
        form = forms[0]
        data = {}
        for field in form["inputs"]:
            name = field.get("name")
            if name:
                data[name] = field.get("value", "")
        # Only fields actually present in the rendered HTML are submitted.
        self.assertEqual(data, {"csrf": csrf})
        path = urllib.parse.urljoin("/control", form["attrs"]["action"])
        status, _, headers = self.form(path, data, headers=dict(cookie))
        self.assertEqual(status, 303)
        self.assertEqual(
            headers["Location"], self.UI_PREFIX + "/control?flash=reconnected"
        )
        self.assertIn("['connect', '192.168.1.50:41234']", self.adb_log())
        self.assertNotIn("'pair'", self.adb_log())



    # ---------- 0.3.17 physical identity ----------

    def test_connect_saved_enrols_hardware_identity_from_transport_legacy_record(self):
        cookie, csrf = self.start_control()
        bridge.save_device(
            self.data_dir, "192.168.1.50", "41234",
            {"serial": "192.168.1.50:41234", "model": "SM_X210"},
        )
        status, _, headers = self.ctl("/control/reconnect", {}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("flash=reconnected", headers["Location"])
        info = bridge.load_device(self.data_dir)
        self.assertEqual(info["serial"], "R5CT12345678")
        self.assertNotEqual(info["serial"], "192.168.1.50:41234")
        self.assertEqual(info["model"], "SM_X210")

    def test_connect_saved_does_not_overwrite_verified_hardware_identity(self):
        cookie, csrf = self.start_control()
        bridge.save_device(
            self.data_dir, "192.168.1.50", "41234",
            {"serial": "R5CT12345678", "model": "SM_X210"},
        )
        path = bridge.device_path(self.data_dir)
        with open(path, "rb") as handle:
            before = handle.read()
        status, _, headers = self.ctl("/control/reconnect", {}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("flash=reconnected", headers["Location"])
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_connect_saved_refuses_hardware_serial_mismatch_byte_for_byte(self):
        cookie, csrf = self.start_control()
        bridge.save_device(
            self.data_dir, "192.168.1.50", "41234",
            {"serial": "R5CT00000000", "model": "SM_X210"},
        )
        path = bridge.device_path(self.data_dir)
        with open(path, "rb") as handle:
            before = handle.read()
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            status, _, headers = self.ctl("/control/reconnect", {}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("flash=reconnect_failed", headers["Location"])
        self.assertIn(
            "saved_connect_failed reason=identity_conflict", capture.getvalue()
        )
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_connect_saved_refuses_empty_or_address_like_ro_serialno(self):
        cookie, csrf = self.start_control()
        for value in ("", "192.168.1.50:41234"):
            with self.subTest(value=value):
                os.environ["FAKE_ADB_HW_SERIAL"] = value
                adbctl.reset_server_state()
                bridge.save_device(self.data_dir, "192.168.1.50", "41234")
                path = bridge.device_path(self.data_dir)
                with open(path, "rb") as handle:
                    before = handle.read()
                capture = io.StringIO()
                with contextlib.redirect_stderr(capture):
                    status, _, headers = self.ctl(
                        "/control/reconnect", {}, cookie, csrf
                    )
                self.assertEqual(status, 303)
                self.assertIn("flash=reconnect_failed", headers["Location"])
                self.assertIn(
                    "saved_connect_failed reason=identity_unverified",
                    capture.getvalue(),
                )
                with open(path, "rb") as handle:
                    self.assertEqual(handle.read(), before)
        os.environ["FAKE_ADB_HW_SERIAL"] = "R5CT12345678"

    def test_connect_saved_accepts_samsung_model_with_hyphen(self):
        cookie, csrf = self.start_control()
        bridge.save_device(
            self.data_dir, "192.168.1.50", "41234",
            {"model": "SM_X210"},
        )
        os.environ["FAKE_ADB_MODEL"] = "SM-X210"
        self.addCleanup(os.environ.__setitem__, "FAKE_ADB_MODEL", "SM_X210")
        status, _, headers = self.ctl("/control/reconnect", {}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("flash=reconnected", headers["Location"])
        info = bridge.load_device(self.data_dir)
        self.assertEqual(info["serial"], "R5CT12345678")



    def test_connect_saved_reproduces_real_samsung_adb_responses(self):
        cookie, csrf = self.start_control()
        os.environ["FAKE_ADB_SERIAL"] = "192.168.18.34:46337"
        os.environ["FAKE_ADB_MODEL"] = "SM-X210"
        os.environ["FAKE_ADB_HW_SERIAL"] = "R5CT12345678"
        bridge.save_device(self.data_dir, "192.168.18.34", "46337")
        status, _, headers = self.ctl("/control/reconnect", {}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("flash=reconnected", headers["Location"])
        info = bridge.load_device(self.data_dir)
        self.assertEqual(info["serial"], "R5CT12345678")
        self.assertNotEqual(info["serial"], "192.168.18.34:46337")
        self.assertEqual(info["model"], "SM-X210")
        log = self.adb_log()
        self.assertIn("['connect', '192.168.18.34:46337']", log)
        self.assertNotIn("'pair'", log)
        self.assertNotIn("'get-serialno'", log)


    def test_connect_saved_reports_daemon_failure_not_connection_refused(self):
        cookie, csrf = self.start_control()
        os.environ["FAKE_ADB_SERVER"] = "down"
        adbctl.reset_server_state()
        path = bridge.device_path(self.data_dir)
        with open(path, "rb") as handle:
            before = handle.read()
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            status, _, headers = self.ctl("/control/reconnect", {}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("flash=reconnect_failed", headers["Location"])
        output = capture.getvalue()
        self.assertIn(
            "saved_connect_failed reason=adb_server_unavailable", output
        )
        self.assertNotIn("connection_refused", output)
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), before)


    # ---------- 0.3.19 safe tap ----------

    def test_tap_reason_is_required_and_bounded(self):
        cookie, _csrf = self.start_control()
        for arguments in (
            {"x": 10, "y": 20},
            {"x": 10, "y": 20, "reason": ""},
            {"x": 10, "y": 20, "reason": "   "},
        ):
            with self.subTest(arguments=arguments):
                self.server.last_proposal_at = 0.0
                self.server.capture_times.clear()
                _, payload = self.propose("android_tap", arguments)
                self.assertTrue(payload["result"]["isError"])
                self.assertIn(
                    "reason is required",
                    payload["result"]["content"][0]["text"],
                )
        with self.assertRaises(control_actions.ActionError):
            control_actions.validate_reason("x" * 201)
        self.assertEqual(len(control_actions.validate_reason("x" * 200)), 200)

    def test_tap_reason_is_html_escaped(self):
        cookie, _csrf = self.start_control()
        reason = '<script>alert(1)</script> & "quoted"'
        self.server.last_proposal_at = 0.0
        self.server.capture_times.clear()
        _, payload = self.propose(
            "android_tap", {"x": 540, "y": 780, "reason": reason}
        )
        self.assertFalse(payload["result"]["isError"])
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        text = page.decode("utf-8")
        self.assertIn(
            "&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;quoted&quot;",
            text,
        )
        self.assertNotIn("<script>alert(1)</script>", text)

    def test_device_is_html_escaped_on_card(self):
        cookie, _csrf = self.login()
        self.server.approvals.clear()
        action = control_actions.validate_tap(10, 10, 100, 100, "safe test")
        self.server.approvals.create(
            action, '<img src=x onerror=alert(1)>', self.png,
            100, 100, "Landscape", "R5CT12345678",
        )
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        self.assertNotIn(b"<img src=x", page)
        self.assertIn(b"&lt;img src=x", page)

    def test_crosshair_uses_percentages_and_original_coordinates(self):
        cookie, _csrf = self.start_control()
        self.new_proposal()
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        text = page.decode("utf-8")
        self.assertIn("left:28.1250%;top:65.0000%", text)
        self.assertIn("X=540, Y=780", text)
        self.assertIn("max-width:100%;height:auto", text)
        self.assertIn("1920 × 1200 — Landscape", text)

    def test_portrait_screen_is_reported(self):
        cookie, _csrf = self.start_control()
        self.set_screen(make_png(1200, 1920))
        self.server.last_proposal_at = 0.0
        _, payload = self.propose(
            "android_tap",
            {"x": 600, "y": 900, "reason": "portrait check"},
        )
        self.assertFalse(payload["result"]["isError"])
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        self.assertIn("1200 × 1920 — Portrait", page.decode("utf-8"))

    def test_out_of_bounds_and_non_integer_taps_are_rejected(self):
        self.start_control()
        cases = (
            (1920, 10), (-1, 10), (10, 1200), (10, -1),
            (1.5, 10), ("10", 10), (True, 10), (10, False),
        )
        for x, y in cases:
            with self.subTest(x=x, y=y):
                self.server.last_proposal_at = 0.0
                self.server.capture_times.clear()
                _, payload = self.propose(
                    "android_tap", {"x": x, "y": y, "reason": "bounds"}
                )
                self.assertTrue(payload["result"]["isError"])
                self.assertIn(
                    payload["result"]["content"][0]["text"],
                    ("coordinate out of range", "invalid coordinate"),
                )
        self.assertEqual(self.server.approvals.pending(), [])

    def test_changed_target_area_refuses_execution(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        self.set_screen(
            make_png(1920, 1200, blocks=[(500, 740, 580, 820, 0, 0, 0, 255)])
        )
        status, _, headers = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("flash=screen_changed", headers["Location"])
        self.assertNotIn("'input'", self.adb_log())
        record = self.server.approvals.get(key)
        self.assertEqual(record["state"], "failed")
        self.assertEqual(record["detail"], "screen_changed")
        _, page, _ = self.req("GET", "/control", cookie)
        self.assertIn("Screen changed — ask again.", page.decode("utf-8"))

    def test_rotated_screen_refuses_execution(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        self.set_screen(make_png(1200, 1920))
        status, _, headers = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("flash=screen_changed", headers["Location"])
        self.assertNotIn("'input'", self.adb_log())

    def test_fresh_screenshot_failure_refuses_execution(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        os.environ["FAKE_ADB_SCREENCAP_FAIL_AFTER"] = "1"
        status, _, headers = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("flash=screen_changed", headers["Location"])
        self.assertNotIn("'input'", self.adb_log())

    def test_invalid_fresh_screenshot_refuses_execution(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        os.environ["FAKE_ADB_SCREENCAP_MODE"] = "garbage"
        status, _, headers = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("flash=screen_changed", headers["Location"])
        self.assertNotIn("'input'", self.adb_log())

    def test_invalid_proposal_screenshot_is_refused(self):
        self.start_control()
        os.environ["FAKE_ADB_SCREENCAP_MODE"] = "garbage"
        self.server.last_proposal_at = 0.0
        self.server.capture_times.clear()
        _, payload = self.propose(
            "android_tap", {"x": 10, "y": 20, "reason": "bad shot"}
        )
        self.assertTrue(payload["result"]["isError"])
        self.assertEqual(self.server.approvals.pending(), [])

    def test_hardware_identity_mismatch_at_approval_is_refused(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        os.environ["FAKE_ADB_HW_SERIAL"] = "R5CT00000000"
        status, _, headers = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("flash=error", headers["Location"])
        self.assertNotIn("'input'", self.adb_log())
        self.assertEqual(
            self.server.approvals.get(key)["detail"], "identity_mismatch"
        )

    def test_saved_hardware_identity_mismatch_at_proposal_is_refused(self):
        self.start_control()
        bridge.save_device(
            self.data_dir, "192.168.1.50", "41234",
            {"serial": "R5CT00000000", "model": "SM_X210"},
        )
        self.server.last_proposal_at = 0.0
        self.server.capture_times.clear()
        _, payload = self.propose(
            "android_tap", {"x": 10, "y": 20, "reason": "identity"}
        )
        self.assertTrue(payload["result"]["isError"])
        self.assertEqual(
            payload["result"]["content"][0]["text"], "identity_mismatch"
        )
        self.assertEqual(self.server.approvals.pending(), [])

    def test_missing_hardware_identity_at_approval_is_refused(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        os.environ["FAKE_ADB_HW_SERIAL"] = ""
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertNotIn("'input'", self.adb_log())
        self.assertEqual(
            self.server.approvals.get(key)["detail"], "identity_mismatch"
        )

    def test_control_expiry_blocks_proposals_and_clears_pending(self):
        cookie, _csrf = self.start_control()
        key = self.new_proposal()
        self.server.control_expires = time.monotonic() - 1
        self.server.last_proposal_at = 0.0
        self.server.capture_times.clear()
        _, payload = self.propose(
            "android_tap", {"x": 10, "y": 20, "reason": "expired"}
        )
        self.assertEqual(
            payload["result"]["content"][0]["text"], "control_session_inactive"
        )
        self.assertIsNone(self.server.approvals.get(key))
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        self.assertIn("Control session: <b>off</b>", page.decode("utf-8"))

    def test_control_expiry_during_approval_refuses_execution(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        self.server.control_expires = time.monotonic() - 1
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertNotIn("'input'", self.adb_log())

    def test_control_panel_shows_remaining_time(self):
        cookie, _csrf = self.start_control()
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        self.assertIn("Control session: <b>ON (", page.decode("utf-8"))

    def test_control_off_cancels_pending(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.ctl(
            "/control/session", {"control": "off"}, cookie, csrf
        )
        self.assertEqual(status, 303)
        self.assertIsNone(self.server.approvals.get(key))
        self.assertEqual(self.server.approvals.pending(), [])

    def test_concurrent_approvals_execute_once(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()

        def worker():
            self.ctl("/control/approve", {"id": key}, cookie, csrf)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
        self.assertEqual(self.adb_log().count("'input'"), 1)

    def test_proposal_cooldown(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        self.server.last_proposal_at = time.monotonic()
        self.server.capture_times.clear()
        _, payload = self.propose(
            "android_tap", {"x": 10, "y": 20, "reason": "too soon"}
        )
        self.assertEqual(
            payload["result"]["content"][0]["text"], "proposal_cooldown"
        )
        self.ctl("/control/reject", {"id": key}, cookie, csrf)
        self.server.last_proposal_at = 0.0
        self.server.capture_times.clear()
        _, payload = self.propose(
            "android_tap", {"x": 10, "y": 20, "reason": "allowed"}
        )
        self.assertFalse(payload["result"]["isError"])

    def test_first_test_mode_allows_one_pending(self):
        self.start_control()
        self.assertEqual(self.server.approvals.max_pending, 3)
        self.assertTrue(self.server.first_tap_test)
        self.new_proposal()
        self.server.last_proposal_at = 0.0
        self.server.capture_times.clear()
        _, payload = self.propose(
            "android_tap", {"x": 10, "y": 20, "reason": "second"}
        )
        self.assertEqual(
            payload["result"]["content"][0]["text"],
            "too many pending approvals",
        )

    def test_approvals_class_keeps_three_pending_capability(self):
        approvals = control_actions.Approvals(max_pending=3)
        action = control_actions.validate_tap(1, 1, 100, 100, "test")
        for _ in range(3):
            approvals.create(
                action, "transport", b"shot", 100, 100, "Square", "hardware"
            )
        with self.assertRaises(control_actions.ActionError):
            approvals.create(
                action, "transport", b"shot", 100, 100, "Square", "hardware"
            )

    def test_postshot_failure_reports_executed_without_screenshot(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        os.environ["FAKE_ADB_SCREENCAP_FAIL_AFTER"] = "2"
        status, _, headers = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("flash=executed", headers["Location"])
        record = self.server.approvals.get(key)
        self.assertEqual(record["state"], "executed")
        self.assertEqual(record["detail"], "executed_no_shot")
        self.assertIsNone(record["postshot"])
        _, polled = self.result(key)
        self.assertEqual(
            json.loads(polled["result"]["content"][0]["text"])["state"],
            "executed",
        )
        self.assertEqual(len(polled["result"]["content"]), 1)
        _, page, _ = self.req("GET", "/control", cookie)
        self.assertIn(
            "Executed — post-action screenshot unavailable",
            page.decode("utf-8"),
        )

    def test_approved_result_is_shown_on_the_panel(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        _, page, _ = self.req("GET", "/control", cookie)
        text = page.decode("utf-8")
        self.assertIn("Recent results", text)
        self.assertIn("Executed — Tap (540, 780)", text)
        self.assertIn("AI reason:", text)
        self.assertIn("data:image/png;base64,", text)


    def test_control_ttl_defaults_to_sixty_minutes(self):
        self.assertEqual(bridge.CONTROL_SESSION_TTL_SECONDS, 60 * 60)
        self.start_control()
        self.assertGreater(
            self.server.control_expires, time.monotonic() + 59 * 60
        )

    def test_control_minutes_option_sets_session_length(self):
        for minutes in (5, 240):
            with self.subTest(minutes=minutes):
                self.server.control_minutes = minutes
                self.start_control()
                remaining = self.server.control_expires - time.monotonic()
                self.assertGreater(remaining, minutes * 60 - 5)
                self.assertLessEqual(remaining, minutes * 60)

    def test_invalid_control_minutes_falls_back_to_default(self):
        for value in (0, 4, 241, 9999, True, "60", None):
            with self.subTest(value=value):
                self.server.control_minutes = value
                self.start_control()
                remaining = self.server.control_expires - time.monotonic()
                self.assertGreater(remaining, 59 * 60)
                self.assertLessEqual(remaining, 60 * 60)

    def test_approval_expiry_is_ten_minutes(self):
        self.assertEqual(control_actions.APPROVAL_TTL_SECONDS, 600.0)
        self.start_control()
        _, payload = self.propose(
            "android_tap", {"x": 540, "y": 780, "reason": "ten minutes"}
        )
        summary = json.loads(payload["result"]["content"][0]["text"])
        self.assertEqual(summary["expires_in_seconds"], 600)
        record = self.server.approvals.get(summary["approval_id"])
        remaining = record["expires"] - time.monotonic()
        self.assertGreater(remaining, 599)
        self.assertLessEqual(remaining, 600)

    def test_remaining_time_is_shown_in_minutes_and_seconds(self):
        self.assertEqual(control_actions.format_remaining(600), "10m 00s")
        self.assertEqual(control_actions.format_remaining(125), "2m 05s")
        self.assertEqual(control_actions.format_remaining(59), "0m 59s")
        self.assertEqual(control_actions.format_remaining(-1), "0m 00s")
        cookie, _csrf = self.start_control()
        self.new_proposal()
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        self.assertRegex(
            page.decode("utf-8"), r"expires in 9m 5[0-9]s"
        )

    def test_panel_auto_refreshes_only_for_control_or_pending(self):
        cookie, _csrf = self.login()
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        self.assertNotIn("http-equiv='refresh'", page.decode("utf-8"))

        self.start_control()
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        self.assertIn(
            "<meta http-equiv='refresh' content='5'>", page.decode("utf-8")
        )

        self.new_proposal()
        # Control off while one approval is still pending: keep refreshing so
        # the card can be seen and acted on, but never approve anything.
        self.server.control_active = False
        self.server.control_expires = 0.0
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        text = page.decode("utf-8")
        self.assertIn("<meta http-equiv='refresh' content='5'>", text)
        self.assertIn("Approve", text)

    def test_crosshair_math_is_percentage_based(self):
        for x, y, width, height, expected in (
            (960, 600, 1920, 1200, "left:50.0000%;top:50.0000%"),
            (1919, 1199, 1920, 1200, "left:99.9479%;top:99.9167%"),
        ):
            with self.subTest(x=x, y=y):
                html = bridge.Handler._crosshair_html(
                    None, x, y, width, height
                )
                self.assertIn(expected, html)

    def test_proposal_stores_identity_transport_and_screen(self):
        self.start_control()
        self.new_proposal()
        record = self.server.approvals.pending()[0]
        self.assertEqual(record["hardware_serial"], "R5CT12345678")
        self.assertEqual(record["device"], "192.168.1.50:41234")
        self.assertEqual((record["width"], record["height"]), (1920, 1200))
        self.assertEqual(record["orientation"], "Landscape")
        self.assertEqual(record["action"]["reason"], "test harmlessly")

    def test_control_off_blocks_exposed_tap(self):
        self.assertIn("android_tap", self.server.exposed_tools)
        self.server.viewing_active = True
        self.server.viewing_expires = time.monotonic() + 60
        self.server.control_active = False
        _, payload = self.propose(
            "android_tap", {"x": 10, "y": 20, "reason": "blocked"}
        )
        self.assertEqual(
            payload["result"]["content"][0]["text"], "control_session_inactive"
        )


    def test_concurrent_proposal_is_refused(self):
        self.start_control()
        self.server.proposal_lock.acquire()
        try:
            _, payload = self.propose(
                "android_tap", {"x": 10, "y": 20, "reason": "busy"}
            )
        finally:
            self.server.proposal_lock.release()
        self.assertEqual(
            payload["result"]["content"][0]["text"], "proposal_busy"
        )
        self.assertEqual(self.server.approvals.pending(), [])

    def test_proposal_uses_capture_rate_limiter(self):
        self.start_control()
        self.server.last_proposal_at = 0.0
        self.server.capture_times[:] = [time.monotonic()]
        _, payload = self.propose(
            "android_tap", {"x": 10, "y": 20, "reason": "rate"}
        )
        self.assertEqual(
            payload["result"]["content"][0]["text"], "rate_limited"
        )

    def test_reject_does_not_reset_the_cooldown(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        self.ctl("/control/reject", {"id": key}, cookie, csrf)
        _, payload = self.propose(
            "android_tap", {"x": 10, "y": 20, "reason": "still cooling"}
        )
        self.assertEqual(
            payload["result"]["content"][0]["text"], "proposal_cooldown"
        )

    def test_text_validation_is_unchanged(self):
        self.assertEqual(
            control_actions.validate_text("hello")["type"], "text"
        )

    def test_swipe_validation_needs_the_captured_screen(self):
        action = control_actions.validate_swipe(
            540, 780, 540, 180, 400, 1920, 1200, "scroll", "scroll a list"
        )
        self.assertEqual(action["type"], "swipe")
        self.assertEqual(action["direction"], "scroll down (swipe upwards)")


    def test_stop_during_proposal_is_refused(self):
        cookie, csrf = self.start_control()
        os.environ["FAKE_ADB_SCREENCAP_SLEEP"] = "0.5"
        result = {}

        def worker():
            result["payload"] = self.propose(
                "android_tap", {"x": 10, "y": 20, "reason": "in flight"}
            )[1]

        thread = threading.Thread(target=worker)
        thread.start()
        time.sleep(0.15)
        self.ctl("/control/stop", {}, cookie, csrf)
        thread.join(timeout=10)
        payload = result["payload"]
        self.assertTrue(payload["result"]["isError"])
        self.assertEqual(
            payload["result"]["content"][0]["text"], "control_session_inactive"
        )
        self.assertEqual(self.server.approvals.pending(), [])
        self.assertNotIn("'input'", self.adb_log())


    def test_result_labels_cover_final_states(self):
        cases = (
            ({"state": "executed", "postshot": b"x", "detail": ""}, "Executed"),
            ({"state": "executed", "postshot": None,
              "detail": "executed_no_shot"},
             "Executed — post-action screenshot unavailable"),
            ({"state": "rejected", "detail": ""}, "Rejected"),
            ({"state": "expired", "detail": ""}, "Expired"),
            ({"state": "failed", "detail": "screen_changed"},
             "Failed — Screen changed — ask again."),
            ({"state": "failed", "detail": "identity_mismatch"},
             "Failed — Device identity changed."),
        )
        for record, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(
                    bridge.Handler._result_label(None, record), expected
                )

    def test_completed_history_is_bounded(self):
        approvals = control_actions.Approvals(max_pending=3)
        action = control_actions.validate_tap(1, 1, 100, 100, "history")
        for _ in range(25):
            record = approvals.create(
                action, "transport", b"shot", 100, 100, "Square", "hardware"
            )
            approvals.complete(record["id"], b"post")
        self.assertLessEqual(len(approvals.records), 20)
        self.assertEqual(len(approvals.recent(5)), 5)


    def test_expired_does_not_reset_the_cooldown(self):
        self.start_control()
        key = self.new_proposal()
        self.server.approvals.get(key)["expires"] = time.monotonic() - 1
        self.server.approvals.pending()
        _, payload = self.propose(
            "android_tap", {"x": 10, "y": 20, "reason": "expired cooldown"}
        )
        self.assertEqual(
            payload["result"]["content"][0]["text"], "proposal_cooldown"
        )


    # ---------- tap target descriptions (0.3.21) ----------

    def test_proposal_reports_the_element_under_the_point(self):
        self.start_control()
        self.set_ui_dump(UI_DUMP_TAP_TARGET)
        self.new_proposal()
        record = self.server.approvals.pending()[0]
        target = record["action"]["target"]
        self.assertEqual(
            target["description"], 'button "Living Room TV" at [400,700][700,860]'
        )
        self.assertEqual(target["bounds"], [400, 700, 700, 860])
        self.assertTrue(target["clickable"])

    def test_proposal_result_names_the_tap_target(self):
        self.start_control()
        self.set_ui_dump(UI_DUMP_TAP_TARGET)
        self.server.last_proposal_at = 0.0
        self.server.capture_times.clear()
        _, payload = self.propose(
            "android_tap", {"x": 540, "y": 780, "reason": "target check"}
        )
        summary = json.loads(payload["result"]["content"][0]["text"])
        self.assertEqual(
            summary["tap_target"], 'button "Living Room TV" at [400,700][700,860]'
        )
        self.assertTrue(summary["tap_target_clickable"])

    def test_dump_failure_is_reported_as_unknown(self):
        self.start_control()
        os.environ.pop("FAKE_ADB_UI_DUMP", None)
        self.new_proposal()
        record = self.server.approvals.pending()[0]
        self.assertEqual(
            record["action"]["target"]["description"],
            "Unknown — could not check.",
        )
        self.assertFalse(record["action"]["target"]["identified"])
        self.assertFalse(record["action"]["target"]["clickable"])

    def test_blank_area_warns_that_controls_may_still_be_there(self):
        cookie, _csrf = self.start_control()
        self.set_ui_dump(UI_DUMP_BLANK)
        self.new_proposal()
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        text = page.decode("utf-8")
        self.assertIn(
            "This will tap: No clickable element detected — verify visually.",
            text,
        )
        self.assertNotIn("Warning: this will press a button", text)
        self.assertIn(
            "Warning: no clickable element detected — this area may still "
            "contain interactive controls.",
            text,
        )
        self.assertNotIn("No button here", text)

    def test_unknown_target_warns_that_controls_may_still_be_there(self):
        cookie, _csrf = self.start_control()
        os.environ.pop("FAKE_ADB_UI_DUMP", None)
        self.new_proposal()
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        text = page.decode("utf-8")
        self.assertIn("This will tap: Unknown — could not check.", text)
        self.assertIn(
            "may still contain interactive controls", text
        )

    def test_card_order_target_warning_screenshot_reason_buttons(self):
        cookie, _csrf = self.start_control()
        self.set_ui_dump(UI_DUMP_TAP_TARGET)
        self.new_proposal()
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        text = page.decode("utf-8")
        markers = (
            "This will tap:",
            "Warning: this will press a button",
            "<img src='data:image/png;base64,",
            "AI reason:",
            "<button>Approve</button>",
            "<button>Reject</button>",
        )
        positions = [text.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(
            positions[0], text.index("Warning: this will press a button")
        )

    def test_red_circle_is_large_and_centred_on_the_tap(self):
        cookie, _csrf = self.start_control()
        self.set_ui_dump(UI_DUMP_TAP_TARGET)
        self.new_proposal()
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        text = page.decode("utf-8")
        self.assertIn("class='tap-circle'", text)
        self.assertIn("width:72px;height:72px", text)
        self.assertIn("border:4px solid #ff0000", text)
        self.assertIn("left:28.1250%;top:65.0000%", text)
        self.assertIn("width:100%;max-width:100%;height:auto", text)

    def test_target_label_is_escaped_on_card(self):
        cookie, _csrf = self.start_control()
        self.set_ui_dump(UI_DUMP_ESCAPE)
        self.new_proposal()
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        self.assertNotIn(b"<b>&\"x\"", page)
        self.assertIn(b"&lt;b&gt;&amp;&quot;x&quot;", page)

    def test_mcp_ui_elements_needs_viewing(self):
        self.server.control_active = False
        self.server.viewing_active = False
        self.set_ui_dump(UI_DUMP_TAP_TARGET)
        status, payload = self.propose("android_ui_elements", {})
        self.assertEqual(status, 403)
        self.assertEqual(payload, {"error": "viewing_session_closed"})

    def test_mcp_ui_elements_lists_clickable_elements(self):
        self.server.viewing_active = True
        self.server.viewing_expires = time.monotonic() + 3600
        self.set_ui_dump(UI_DUMP_TAP_TARGET)
        status, payload = self.propose("android_ui_elements", {})
        self.assertEqual(status, 200)
        self.assertFalse(payload["result"]["isError"])
        body = json.loads(payload["result"]["content"][0]["text"])
        self.assertEqual(
            body["elements"],
            [
                {
                    "name": "Living Room TV",
                    "bounds": [400, 700, 700, 860],
                }
            ],
        )
        self.assertEqual(body["count"], 1)

    def test_mcp_ui_elements_reports_dump_failure(self):
        self.server.viewing_active = True
        self.server.viewing_expires = time.monotonic() + 3600
        os.environ.pop("FAKE_ADB_UI_DUMP", None)
        status, payload = self.propose("android_ui_elements", {})
        self.assertEqual(status, 200)
        self.assertTrue(payload["result"]["isError"])
        self.assertEqual(
            payload["result"]["content"][0]["text"], "ui_dump_failed"
        )


    # ---------- approval-time target recheck (0.3.21 corrections) ----------

    def refuse(self, key, cookie, csrf, detail):
        status, _, headers = self.ctl(
            "/control/approve", {"id": key}, cookie, csrf
        )
        self.assertEqual(status, 303)
        self.assertIn("flash=error", headers["Location"])
        self.assertNotIn("'input'", self.adb_log())
        record = self.server.approvals.get(key)
        self.assertEqual(record["state"], "failed")
        self.assertEqual(record["detail"], detail)

    def test_approval_allows_an_unchanged_target(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("'shell', 'input', 'tap', '540', '780'", self.adb_log())
        _, polled = self.result(key)
        self.assertEqual(
            json.loads(polled["result"]["content"][0]["text"])["state"],
            "executed",
        )

    def test_approval_rejects_a_target_that_disappeared(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        self.set_ui_dump(UI_DUMP_BLANK)
        self.refuse(key, cookie, csrf, "target_changed")

    def test_approval_rejects_changed_target_bounds(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        self.set_ui_dump(UI_DUMP_TARGET_MOVED)
        self.refuse(key, cookie, csrf, "target_changed")

    def test_approval_rejects_a_changed_target_label(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        self.set_ui_dump(UI_DUMP_TARGET_RENAMED)
        self.refuse(key, cookie, csrf, "target_changed")

    def test_approval_rejects_a_new_clickable_element(self):
        cookie, csrf = self.start_control()
        self.set_ui_dump(UI_DUMP_BLANK)
        key = self.new_proposal()
        self.assertEqual(
            self.server.approvals.get(key)["action"]["target"]["description"],
            "No clickable element detected — verify visually.",
        )
        self.set_ui_dump(UI_DUMP_TAP_TARGET)
        self.refuse(key, cookie, csrf, "target_changed")

    def test_approval_fails_closed_when_inspection_fails(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        os.environ.pop("FAKE_ADB_UI_DUMP", None)
        self.refuse(key, cookie, csrf, "target_unverified")
        _, polled = self.result(key)
        payload = json.loads(polled["result"]["content"][0]["text"])
        self.assertEqual(payload["state"], "failed")

    def test_approval_fails_closed_on_an_unparseable_dump(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        self.set_ui_dump("<not a uiautomator dump")
        self.refuse(key, cookie, csrf, "target_unverified")

    def test_approval_allows_an_unidentified_area_that_stays_unidentified(self):
        cookie, csrf = self.start_control()
        self.set_ui_dump(UI_DUMP_BLANK)
        key = self.new_proposal()
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn("'shell', 'input', 'tap', '540', '780'", self.adb_log())

    def test_refused_approval_is_never_retried_or_moved(self):
        cookie, csrf = self.start_control()
        key = self.new_proposal()
        self.set_ui_dump(UI_DUMP_TARGET_MOVED)
        self.refuse(key, cookie, csrf, "target_changed")
        self.assertEqual(self.adb_log().count("'input'"), 0)
        self.assertEqual(
            self.server.approvals.get(key)["state"], "failed"
        )

    def test_failed_target_recheck_is_labelled_on_the_panel(self):
        record = {
            "state": "failed",
            "detail": "target_changed",
            "action": control_actions.validate_tap(1, 1, 10, 10, "x"),
        }
        self.assertEqual(
            bridge.Handler._result_label(None, record),
            "Failed — Target changed — ask again.",
        )
        record["detail"] = "target_unverified"
        self.assertEqual(
            bridge.Handler._result_label(None, record),
            "Failed — Could not verify the target.",
        )


    # ---------- sensitive text and dump hygiene (0.3.21) ----------

    def test_password_contents_never_reach_the_card_or_result(self):
        cookie, _csrf = self.start_control()
        self.set_ui_dump(UI_DUMP_SECRET)
        self.server.last_proposal_at = 0.0
        self.server.capture_times.clear()
        _, payload = self.propose(
            "android_tap", {"x": 540, "y": 780, "reason": "secret check"}
        )
        summary = json.loads(payload["result"]["content"][0]["text"])
        self.assertNotIn("hunter2", summary["tap_target"])
        self.assertIn("com.x:id/pass", summary["tap_target"])
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        self.assertNotIn(b"hunter2", page)
        self.assertIn(b"com.x:id/pass", page)

    def test_ui_elements_never_include_password_contents(self):
        self.server.viewing_active = True
        self.server.viewing_expires = time.monotonic() + 3600
        self.set_ui_dump(UI_DUMP_SECRET)
        _, payload = self.propose("android_ui_elements", {})
        body = json.loads(payload["result"]["content"][0]["text"])
        self.assertEqual(
            body["elements"],
            [{"name": "com.x:id/pass", "bounds": [400, 700, 700, 860]}],
        )
        self.assertNotIn("hunter2", str(body))

    def test_ui_dump_file_is_removed_after_proposal(self):
        self.start_control()
        self.new_proposal()
        log = self.adb_log()
        self.assertIn(
            "'shell', 'rm', '-f', '/sdcard/window_dump.xml'", log
        )

    def test_ui_dump_file_is_removed_when_inspection_fails(self):
        self.start_control()
        os.environ.pop("FAKE_ADB_UI_DUMP", None)
        self.new_proposal()
        log = self.adb_log()
        self.assertIn(
            "'shell', 'rm', '-f', '/sdcard/window_dump.xml'", log
        )
        self.assertIn("'shell', 'uiautomator', 'dump'", log)

    # ---------- swipe (0.3.22) ----------

    SWIPE_PURPOSE = "scroll down one screen"

    def swipe_proposal(self, **overrides):
        arguments = {
            "x1": 540, "y1": 780, "x2": 540, "y2": 180,
            "duration_ms": 400,
            "reason": "scroll the list to reach the next item",
            "purpose": self.SWIPE_PURPOSE,
        }
        arguments.update(overrides)
        self.server.last_proposal_at = 0.0
        self.server.capture_times.clear()
        return self.propose("android_swipe", arguments)

    def swipe_key(self, **overrides):
        _, payload = self.swipe_proposal(**overrides)
        self.assertFalse(payload["result"]["isError"], payload)
        summary = json.loads(payload["result"]["content"][0]["text"])
        return summary["approval_id"]

    def test_swipe_proposal_records_direction_app_and_purpose(self):
        self.start_control()
        _, payload = self.swipe_proposal()
        self.assertFalse(payload["result"]["isError"], payload)
        summary = json.loads(payload["result"]["content"][0]["text"])
        self.assertEqual(summary["state"], "pending")
        self.assertEqual(summary["action"], "Swipe (540, 780) to (540, 180) over 400 ms")
        self.assertEqual(summary["direction"], "scroll down (swipe upwards)")
        self.assertEqual(summary["app"], "Settings")
        self.assertEqual(summary["app_package"], "com.android.settings")
        self.assertEqual(summary["purpose"], self.SWIPE_PURPOSE)
        self.assertEqual(
            summary["start_target"],
            'button "Living Room TV" at [400,700][700,860]',
        )
        self.assertEqual(
            summary["message"],
            "DeepSeek wants to scroll down (swipe upwards) in Settings.",
        )
        self.assertEqual(payload["result"]["content"][1]["type"], "image")
        self.assertNotIn("'input'", self.adb_log())

    def test_swipe_proposal_requires_reason_and_purpose(self):
        self.start_control()
        for overrides in ({"reason": ""}, {"purpose": "  "}, {"purpose": None}):
            with self.subTest(overrides=overrides):
                _, payload = self.swipe_proposal(**overrides)
                self.assertTrue(payload["result"]["isError"], payload)
        self.assertEqual(self.server.approvals.pending(), [])

    def test_swipe_unknown_app_falls_back_to_the_current_app(self):
        self.start_control()
        os.environ["FAKE_ADB_FOREGROUND"] = "no focused window here"
        _, payload = self.swipe_proposal()
        summary = json.loads(payload["result"]["content"][0]["text"])
        self.assertEqual(summary["app"], "the current app")
        self.assertEqual(
            summary["message"],
            "DeepSeek wants to scroll down (swipe upwards) "
            "in the current app.",
        )

    def test_swipe_edge_zone_is_refused(self):
        self.start_control()
        cases = (
            {"x1": 40},
            {"x2": 40},
            {"y1": 1180},
            {"y2": 40},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                _, payload = self.swipe_proposal(**overrides)
                self.assertTrue(payload["result"]["isError"], payload)
                self.assertIn(
                    "edge_zone", payload["result"]["content"][0]["text"]
                )
        self.assertEqual(self.server.approvals.pending(), [])
        self.assertNotIn("'input'", self.adb_log())

    def test_swipe_distance_too_short_and_too_long_are_refused(self):
        self.start_control()
        cases = (
            ({"y2": 720}, "distance"),
            ({"y1": 1100, "y2": 100}, "distance"),
        )
        for overrides, token in cases:
            with self.subTest(overrides=overrides):
                _, payload = self.swipe_proposal(**overrides)
                self.assertTrue(payload["result"]["isError"], payload)
                self.assertIn(token, payload["result"]["content"][0]["text"])
        self.assertEqual(self.server.approvals.pending(), [])

    def test_swipe_duration_out_of_range_is_refused(self):
        self.start_control()
        for value in (299, 1501, "fast"):
            with self.subTest(duration=value):
                _, payload = self.swipe_proposal(duration_ms=value)
                self.assertTrue(payload["result"]["isError"], payload)
                self.assertIn(
                    "duration", payload["result"]["content"][0]["text"]
                )
        self.assertEqual(self.server.approvals.pending(), [])

    def test_swipe_duration_limits_are_inclusive(self):
        self.start_control()
        for value in (300, 1500):
            with self.subTest(duration=value):
                self.server.approvals.clear()
                _, payload = self.swipe_proposal(duration_ms=value)
                self.assertFalse(payload["result"]["isError"], payload)

    def test_swipe_diagonal_is_refused(self):
        self.start_control()
        _, payload = self.swipe_proposal(x2=900, y2=420)
        self.assertTrue(payload["result"]["isError"], payload)
        self.assertIn("diagonal", payload["result"]["content"][0]["text"])
        self.assertEqual(self.server.approvals.pending(), [])

    def test_swipe_within_twenty_degrees_is_accepted(self):
        self.start_control()
        # 600 px vertical with a 200 px horizontal drift: about 18.4 degrees.
        _, payload = self.swipe_proposal(x2=740, y2=180)
        self.assertFalse(payload["result"]["isError"], payload)

    def test_swipe_direction_wording_for_all_four_directions(self):
        cases = (
            ((540, 900, 540, 300), "scroll down (swipe upwards)"),
            ((540, 300, 540, 900), "scroll up (swipe downwards)"),
            ((900, 600, 300, 600), "swipe left"),
            ((300, 600, 900, 600), "swipe right"),
        )
        for points, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(
                    control_actions.swipe_direction(*points), expected
                )

    def test_swipe_card_message_order_and_wording(self):
        cookie, _csrf = self.start_control()
        self.swipe_key()
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        rendered = RenderedPage()
        rendered.feed(page.decode("utf-8"))
        body = rendered.visible_text
        self.assertIn(
            "DeepSeek wants to scroll down (swipe upwards) in Settings.", body
        )
        self.assertIn("Start: (540, 780)", body)
        self.assertIn("End: (540, 180)", body)
        self.assertIn("Action: " + self.SWIPE_PURPOSE, body)
        headline = body.index("DeepSeek wants to")
        start = body.index("Start: (540, 780)")
        end = body.index("End: (540, 180)")
        action = body.index("Action: " + self.SWIPE_PURPOSE)
        reason = body.index("AI reason:")
        approve = body.index("Approve")
        self.assertLess(headline, start)
        self.assertLess(start, end)
        self.assertLess(end, action)
        self.assertLess(action, reason)
        self.assertLess(reason, approve)
        self.assertIsNotNone(re.search(r"expires in \d+m \d\ds", body))

    def test_swipe_card_draws_green_start_red_end_and_arrow(self):
        cookie, _csrf = self.start_control()
        self.swipe_key()
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        body = page.decode("utf-8")
        self.assertIn("class='swipe-start'", body)
        self.assertIn("class='swipe-end'", body)
        self.assertIn("stroke='#00c000'", body)
        self.assertIn("<line x1='540' y1='780' x2='540' y2='180'", body)
        self.assertIn("marker-end='url(#swipe-arrow-", body)
        self.assertIn("<path d='M0,0 L6,3 L0,6 z' fill='#ff0000'/>", body)
        start = body.index("class='swipe-start'")
        end = body.index("class='swipe-end'")
        self.assertLess(body.index("<line "), start)
        self.assertLess(start, end)

    def test_swipe_approve_executes_and_returns_postshot(self):
        cookie, csrf = self.start_control()
        key = self.swipe_key()
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn(
            "'shell', 'input', 'swipe', '540', '780', '540', '180', '400'",
            self.adb_log(),
        )
        _, polled = self.result(key)
        state = json.loads(polled["result"]["content"][0]["text"])
        self.assertEqual(state["state"], "executed")
        self.assertEqual(state["direction"], "scroll down (swipe upwards)")
        self.assertEqual(state["app"], "Settings")
        self.assertEqual(state["purpose"], self.SWIPE_PURPOSE)
        self.assertEqual(polled["result"]["content"][1]["type"], "image")

    def test_swipe_is_single_use(self):
        cookie, csrf = self.start_control()
        key = self.swipe_key()
        self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(self.adb_log().count("'swipe'"), 1)

    def test_swipe_refuses_when_the_screen_changed(self):
        cookie, csrf = self.start_control()
        key = self.swipe_key()
        self.set_screen(
            make_png(blocks=((470, 730, 610, 830, 10, 200, 10, 255),))
        )
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertNotIn("'swipe'", self.adb_log())
        _, polled = self.result(key)
        state = json.loads(polled["result"]["content"][0]["text"])
        self.assertEqual(state["state"], "failed")
        self.assertEqual(state["detail"], "screen_changed")

    def test_swipe_stop_cancels_the_pending_approval(self):
        cookie, csrf = self.start_control()
        key = self.swipe_key()
        status, _, _ = self.ctl("/control/stop", {}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIsNone(self.server.approvals.get(key))
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertNotIn("'swipe'", self.adb_log())

    def test_bearer_cannot_approve_a_swipe(self):
        self.start_control()
        key = self.swipe_key()
        status, _, _ = self.form(
            "/control/approve", {"id": key}, self.bearer()
        )
        self.assertEqual(status, 403)
        self.assertEqual(
            self.server.approvals.get(key)["state"], "pending"
        )
        self.assertNotIn("'swipe'", self.adb_log())

    def test_swipe_is_not_exposed_by_default(self):
        self.assertNotIn("android_swipe", bridge.DEFAULT_EXPOSED_TOOLS)
        empty = tempfile.mkdtemp(prefix="bridge-empty-", dir=self.tmp)
        self.assertNotIn(
            "android_swipe", bridge.load_exposed_tools(empty)
        )
        config_path = os.path.join(os.path.dirname(APP_DIR), "config.yaml")
        with open(config_path, encoding="utf-8") as handle:
            self.assertNotIn("android_swipe", handle.read())




    # ---------- typed text (0.3.23) ----------

    TEXT_PHRASE = "hello world"
    TEXT_PURPOSE = "type a harmless phrase into the settings search box"
    TEXT_REASON = "checking that approved typing reaches only the search field"

    def text_proposal(self, **overrides):
        arguments = {
            "text": self.TEXT_PHRASE,
            "purpose": self.TEXT_PURPOSE,
            "reason": self.TEXT_REASON,
        }
        arguments.update(overrides)
        self.server.last_proposal_at = 0.0
        self.server.capture_times.clear()
        return self.propose("android_text", arguments)

    def text_key(self, **overrides):
        _, payload = self.text_proposal(**overrides)
        self.assertFalse(payload["result"]["isError"], payload)
        summary = json.loads(payload["result"]["content"][0]["text"])
        return summary["approval_id"]

    def text_ready(self):
        cookie, csrf = self.start_control()
        self.set_ui_dump(UI_DUMP_TEXT_FIELD)
        return cookie, csrf

    def test_text_proposal_records_app_field_and_message(self):
        self.start_control()
        self.set_ui_dump(UI_DUMP_TEXT_FIELD)
        _, payload = self.text_proposal()
        self.assertFalse(payload["result"]["isError"], payload)
        summary = json.loads(payload["result"]["content"][0]["text"])
        self.assertEqual(summary["state"], "pending")
        self.assertEqual(summary["action"], "Type 11 characters")
        self.assertEqual(summary["text"], self.TEXT_PHRASE)
        self.assertEqual(summary["app"], "Settings")
        self.assertEqual(summary["app_package"], "com.android.settings")
        self.assertEqual(summary["purpose"], self.TEXT_PURPOSE)
        self.assertEqual(
            summary["field"],
            'text field "com.android.settings:id/search_src_text" '
            "at [400,700][1500,860]",
        )
        self.assertEqual(
            summary["message"], "DeepSeek wants to type in Settings"
        )
        self.assertEqual(payload["result"]["content"][1]["type"], "image")
        self.assertNotIn("'input'", self.adb_log())

    def test_text_proposal_requires_purpose_and_reason(self):
        self.start_control()
        self.set_ui_dump(UI_DUMP_TEXT_FIELD)
        cases = (
            {"purpose": ""},
            {"purpose": "  "},
            {"purpose": None},
            {"reason": " "},
            {"reason": None},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                _, payload = self.text_proposal(**overrides)
                self.assertTrue(payload["result"]["isError"], payload)
        self.assertEqual(self.server.approvals.pending(), [])

    def test_text_rejects_unsupported_characters_and_length(self):
        self.start_control()
        self.set_ui_dump(UI_DUMP_TEXT_FIELD)
        for value in (
            "hello; rm -rf /",
            "$(id)",
            "a|b",
            "back\\slash",
            "quote\"mark",
            "line\nbreak",
            "caf\u00e9",
            "x" * 201,
            "   ",
            "",
            "issue #42",
            "what?",
        ):
            with self.subTest(value=value[:20]):
                _, payload = self.text_proposal(text=value)
                self.assertTrue(payload["result"]["isError"], payload)
        self.assertEqual(self.server.approvals.pending(), [])
        self.assertNotIn("'input'", self.adb_log())

    def test_text_limits_are_inclusive(self):
        self.start_control()
        self.set_ui_dump(UI_DUMP_TEXT_FIELD)
        phrase = "a" * 200
        _, payload = self.text_proposal(text=phrase)
        self.assertFalse(payload["result"]["isError"], payload)
        summary = json.loads(payload["result"]["content"][0]["text"])
        self.assertEqual(summary["text"], phrase)

    def test_text_is_trimmed_before_approval(self):
        self.start_control()
        self.set_ui_dump(UI_DUMP_TEXT_FIELD)
        _, payload = self.text_proposal(text="  hello world  ")
        summary = json.loads(payload["result"]["content"][0]["text"])
        self.assertEqual(summary["text"], "hello world")

    def test_text_refuses_without_a_focused_field(self):
        self.start_control()
        self.set_ui_dump(UI_DUMP_TAP_TARGET)
        _, payload = self.text_proposal()
        self.assertTrue(payload["result"]["isError"])
        self.assertEqual(
            payload["result"]["content"][0]["text"], "no_focused_text_field"
        )
        self.assertEqual(self.server.approvals.pending(), [])
        self.assertNotIn("'input'", self.adb_log())

    def test_text_refuses_an_unfocused_or_hidden_field(self):
        self.start_control()
        for xml in (UI_DUMP_TEXT_FIELD_BLURRED, UI_DUMP_TEXT_FIELD_HIDDEN):
            with self.subTest(xml=xml[:60]):
                self.set_ui_dump(xml)
                _, payload = self.text_proposal()
                self.assertTrue(payload["result"]["isError"], payload)
                self.assertEqual(
                    payload["result"]["content"][0]["text"],
                    "no_focused_text_field",
                )
        self.assertEqual(self.server.approvals.pending(), [])

    def test_text_refuses_two_focused_fields(self):
        self.start_control()
        self.set_ui_dump(UI_DUMP_TWO_FIELDS)
        _, payload = self.text_proposal()
        self.assertTrue(payload["result"]["isError"])
        self.assertEqual(
            payload["result"]["content"][0]["text"], "ambiguous_text_field"
        )
        self.assertEqual(self.server.approvals.pending(), [])

    def test_text_refuses_a_failed_inspection(self):
        self.start_control()
        os.environ.pop("FAKE_ADB_UI_DUMP", None)
        _, payload = self.text_proposal()
        self.assertTrue(payload["result"]["isError"])
        self.assertEqual(
            payload["result"]["content"][0]["text"], "target_unverified"
        )
        self.assertEqual(self.server.approvals.pending(), [])

    def test_text_refuses_password_pin_and_card_fields(self):
        self.start_control()
        for xml, secret in (
            (UI_DUMP_PASSWORD_FIELD, "hunter2"),
            (UI_DUMP_PIN_FIELD, "1234"),
            (UI_DUMP_CARD_FIELD, "4111 1111 1111 1111"),
        ):
            with self.subTest(secret=secret):
                self.set_ui_dump(xml)
                _, payload = self.text_proposal()
                body = str(payload)
                self.assertTrue(payload["result"]["isError"], payload)
                self.assertEqual(
                    payload["result"]["content"][0]["text"],
                    "sensitive_field_refused",
                )
                self.assertNotIn(secret, body)
        self.assertEqual(self.server.approvals.pending(), [])
        self.assertNotIn("'input'", self.adb_log())

    def test_text_card_shows_complete_text_field_purpose_and_reason(self):
        cookie, _csrf = self.text_ready()
        self.text_key()
        status, page, _ = self.req("GET", "/control", cookie)
        self.assertEqual(status, 200)
        text = page.decode("utf-8")
        self.assertIn("DeepSeek wants to type in Settings", text)
        self.assertIn("Destination field:", text)
        self.assertIn(
            "com.android.settings:id/search_src_text", text
        )
        self.assertIn("Text to enter (11 characters):", text)
        self.assertIn(">hello world<", text)
        self.assertIn(self.TEXT_PURPOSE, text)
        self.assertIn(self.TEXT_REASON, text)
        self.assertIn("border:4px solid #00c000", text)
        self.assertIn("Approve", text)
        self.assertIn("Reject", text)
        self.assertNotIn("Search settings", text)

    def test_text_card_order_is_documented(self):
        cookie, _csrf = self.text_ready()
        self.text_key()
        status, page, _ = self.req("GET", "/control", cookie)
        text = page.decode("utf-8")
        order = [
            "DeepSeek wants to type in Settings",
            "Destination field:",
            "Text to enter",
            "Purpose:",
            "AI reason:",
            "border:4px solid #00c000",
            "Approve",
            "Reject",
        ]
        positions = [text.index(marker) for marker in order]
        self.assertEqual(positions, sorted(positions))

    def test_text_card_escapes_purpose_and_reason(self):
        cookie, _csrf = self.text_ready()
        self.text_key(
            purpose="<script>alert(1)</script>",
            reason="<b>bold</b>",
        )
        status, page, _ = self.req("GET", "/control", cookie)
        text = page.decode("utf-8")
        self.assertNotIn("<script>alert(1)</script>", text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", text)
        self.assertNotIn("<b>bold</b>", text)

    def test_text_approve_executes_fixed_input_and_returns_postshot(self):
        cookie, csrf = self.text_ready()
        key = self.text_key()
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIn(
            "'shell', 'input', 'text', 'hello%sworld'", self.adb_log()
        )
        _, polled = self.result(key)
        state = json.loads(polled["result"]["content"][0]["text"])
        self.assertEqual(state["state"], "executed")
        self.assertEqual(state["text_length"], len(self.TEXT_PHRASE))
        self.assertNotIn("text", state)
        self.assertNotIn(self.TEXT_PHRASE, json.dumps(state))
        self.assertEqual(state["purpose"], self.TEXT_PURPOSE)
        self.assertEqual(state["app"], "Settings")
        self.assertIn("search_src_text", state["field"])
        self.assertEqual(polled["result"]["content"][1]["type"], "image")

    def test_text_reject_never_types(self):
        cookie, csrf = self.text_ready()
        key = self.text_key()
        status, _, _ = self.ctl("/control/reject", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertNotIn("'text'", self.adb_log())
        _, polled = self.result(key)
        state = json.loads(polled["result"]["content"][0]["text"])
        self.assertEqual(state["state"], "rejected")

    def test_text_stop_cancels_the_pending_approval(self):
        cookie, csrf = self.text_ready()
        key = self.text_key()
        status, _, _ = self.ctl("/control/stop", {}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertIsNone(self.server.approvals.get(key))
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertNotIn("'text'", self.adb_log())

    def test_text_expiry_refuses_execution(self):
        cookie, csrf = self.text_ready()
        key = self.text_key()
        record = self.server.approvals.get(key)
        record["expires"] = time.monotonic() - 1
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertNotIn("'text'", self.adb_log())

    def test_text_approval_is_single_use(self):
        cookie, csrf = self.text_ready()
        key = self.text_key()
        self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(self.adb_log().count("'text'"), 1)

    def test_text_refuses_a_changed_field_at_approval(self):
        cookie, csrf = self.text_ready()
        key = self.text_key()
        self.set_ui_dump(UI_DUMP_TEXT_FIELD_MOVED)
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        self.assertNotIn("'text'", self.adb_log())
        _, polled = self.result(key)
        state = json.loads(polled["result"]["content"][0]["text"])
        self.assertEqual(state["state"], "failed")
        self.assertEqual(state["detail"], "target_changed")

    def test_text_refuses_a_field_that_lost_focus(self):
        cookie, csrf = self.text_ready()
        key = self.text_key()
        self.set_ui_dump(UI_DUMP_TEXT_FIELD_BLURRED)
        self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertNotIn("'text'", self.adb_log())
        _, polled = self.result(key)
        state = json.loads(polled["result"]["content"][0]["text"])
        self.assertEqual(state["detail"], "target_changed")

    def test_text_refuses_a_field_that_became_sensitive(self):
        cookie, csrf = self.text_ready()
        key = self.text_key()
        self.set_ui_dump(UI_DUMP_PASSWORD_FIELD)
        self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertNotIn("'text'", self.adb_log())
        _, polled = self.result(key)
        state = json.loads(polled["result"]["content"][0]["text"])
        self.assertEqual(state["detail"], "sensitive_field")

    def test_text_refuses_a_changed_app_at_approval(self):
        cookie, csrf = self.text_ready()
        key = self.text_key()
        os.environ["FAKE_ADB_FOREGROUND"] = (
            "  mCurrentFocus=Window{2f8e1 u0 "
            "com.android.chrome/com.android.chrome.Main}"
        )
        self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertNotIn("'text'", self.adb_log())
        _, polled = self.result(key)
        state = json.loads(polled["result"]["content"][0]["text"])
        self.assertEqual(state["detail"], "app_changed")

    def test_text_refuses_when_the_screen_changed(self):
        cookie, csrf = self.text_ready()
        key = self.text_key()
        self.set_screen(
            make_png(blocks=((900, 730, 1000, 830, 10, 200, 10, 255),))
        )
        self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertNotIn("'text'", self.adb_log())
        _, polled = self.result(key)
        state = json.loads(polled["result"]["content"][0]["text"])
        self.assertEqual(state["detail"], "screen_changed")

    def test_text_typing_failure_is_reported(self):
        cookie, csrf = self.text_ready()
        key = self.text_key()
        os.environ["FAKE_ADB_INPUT_FAIL"] = "1"
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        _, polled = self.result(key)
        state = json.loads(polled["result"]["content"][0]["text"])
        self.assertEqual(state["state"], "failed")
        self.assertEqual(state["detail"], "action_failed")
        self.assertFalse(
            any(part["type"] == "image" for part in polled["result"]["content"])
        )

    def test_text_never_appears_in_server_logs(self):
        cookie, csrf = self.text_ready()
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            key = self.text_key()
            self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertNotIn(self.TEXT_PHRASE, buffer.getvalue())

    def test_text_is_not_exposed_by_default(self):
        self.assertNotIn("android_text", bridge.DEFAULT_EXPOSED_TOOLS)
        empty = tempfile.mkdtemp(prefix="bridge-empty-", dir=self.tmp)
        self.assertNotIn("android_text", bridge.load_exposed_tools(empty))
        config_path = os.path.join(os.path.dirname(APP_DIR), "config.yaml")
        with open(config_path, encoding="utf-8") as handle:
            self.assertNotIn("android_text", handle.read())


    def test_text_refuses_hash_and_question_mark(self):
        self.start_control()
        self.set_ui_dump(UI_DUMP_TEXT_FIELD)
        for value in ("issue #42", "#comment", "what?", "a#b"):
            with self.subTest(value=value):
                _, payload = self.text_proposal(text=value)
                self.assertTrue(payload["result"]["isError"], payload)
                self.assertIn(
                    "text contains unsupported characters",
                    payload["result"]["content"][0]["text"],
                )
        self.assertEqual(self.server.approvals.pending(), [])
        self.assertNotIn("'input'", self.adb_log())

    def test_text_proposal_refuses_an_empty_foreground_package(self):
        self.start_control()
        self.set_ui_dump(UI_DUMP_TEXT_FIELD)
        os.environ["FAKE_ADB_FOREGROUND"] = ""
        _, payload = self.text_proposal()
        self.assertTrue(payload["result"]["isError"], payload)
        self.assertEqual(
            payload["result"]["content"][0]["text"], "foreground_unavailable"
        )
        self.assertEqual(self.server.approvals.pending(), [])
        self.assertNotIn("'input'", self.adb_log())

    def test_text_approval_refuses_an_empty_expected_package(self):
        cookie, csrf = self.text_ready()
        key = self.text_key()
        record = self.server.approvals.get(key)
        record["action"]["app_package"] = ""
        record["fingerprint"] = control_actions.fingerprint(
            record["action"], record["device"], record["preshot"]
        )
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        record = self.server.approvals.get(key)
        self.assertEqual(record["state"], "failed")
        self.assertEqual(record["detail"], "app_changed")
        self.assertNotIn("'text'", self.adb_log())

    def test_text_approval_refuses_an_empty_current_package(self):
        cookie, csrf = self.text_ready()
        key = self.text_key()
        os.environ["FAKE_ADB_FOREGROUND"] = ""
        status, _, _ = self.ctl("/control/approve", {"id": key}, cookie, csrf)
        self.assertEqual(status, 303)
        record = self.server.approvals.get(key)
        self.assertEqual(record["state"], "failed")
        self.assertEqual(record["detail"], "app_changed")
        self.assertNotIn("'text'", self.adb_log())

    def test_text_result_reports_length_not_text(self):
        cookie, csrf = self.text_ready()
        key = self.text_key()
        self.ctl("/control/approve", {"id": key}, cookie, csrf)
        _, polled = self.result(key)
        state = json.loads(polled["result"]["content"][0]["text"])
        self.assertEqual(state["state"], "executed")
        self.assertEqual(state["text_length"], len(self.TEXT_PHRASE))
        self.assertNotIn("text", state)
        self.assertNotIn(self.TEXT_PHRASE, json.dumps(state))

    def test_text_version_is_bumped(self):
        config_path = os.path.join(os.path.dirname(APP_DIR), "config.yaml")
        with open(config_path, encoding="utf-8") as handle:
            self.assertIn('version: "0.3.25"', handle.read())
        self.assertEqual(bridge.VERSION, "0.3.25")

    # ---------- app labels (0.3.25) ----------

    APP_LABEL_CASES = {
        "com.android.settings.intelligence": "Settings search",
        "com.android.settings": "Settings",
        "io.homeassistant.companion.android": "Home Assistant",
        "com.android.chrome": "Chrome",
        "com.sec.android.app.launcher": "Home screen",
        "com.samsung.android.app.routines": "Modes and Routines",
    }

    def test_app_label_known_packages(self):
        for package, label in self.APP_LABEL_CASES.items():
            with self.subTest(package=package):
                self.assertEqual(
                    control_actions.app_label(package), label
                )

    def test_app_label_unknown_package_keeps_readable_fallback(self):
        self.assertEqual(
            control_actions.app_label("com.example.someapp"), "Someapp"
        )
        self.assertEqual(
            control_actions.app_label("com.example.some_app"), "Some App"
        )
        self.assertEqual(control_actions.app_label(""), "")
        self.assertEqual(control_actions.app_label(None), "")

    def test_text_headline_names_settings_search(self):
        action = {
            "type": "text",
            "app": control_actions.app_label(
                "com.android.settings.intelligence"
            ),
        }
        self.assertEqual(
            control_actions.approval_headline(action),
            "DeepSeek wants to type in Settings search.",
        )
        self.assertEqual(
            control_actions.text_headline(action),
            "DeepSeek wants to type in Settings search",
        )


    # ---------- pending summary (0.3.24) ----------

    CORE_PEER = "172.30.32.1"

    def summary(self, headers=None):
        status, body, response_headers = self.req(
            "GET", "/pending_summary", headers
        )
        return status, json.loads(body), body, response_headers

    def test_pending_summary_is_open_to_core_with_nothing_pending(self):
        self.set_peer(self.CORE_PEER)
        status, data, _body, headers = self.summary()
        self.assertEqual(status, 200)
        self.assertEqual(
            data, {"pending": 0, "headline": "", "oldest_id": ""}
        )
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_pending_summary_forbids_every_other_peer(self):
        for peer in (
            "172.30.32.2",   # Supervisor ingress
            "172.30.32.9",   # another add-on (for example OpenCode)
            "172.30.33.4",   # unknown hassio peer
            "192.168.18.20", # LAN
            "127.0.0.1",
        ):
            with self.subTest(peer=peer):
                self.set_peer(peer)
                status, data, _body, _headers = self.summary()
                self.assertEqual(status, 403)
                self.assertEqual(data, {"error": "forbidden"})

    def test_pending_summary_ignores_forwarding_headers(self):
        self.set_peer("172.30.33.4")
        status, data, _body, _headers = self.summary(
            {
                "X-Forwarded-For": self.CORE_PEER,
                "X-Real-IP": self.CORE_PEER,
                "Forwarded": "for=" + self.CORE_PEER,
            }
        )
        self.assertEqual(status, 403)
        self.assertEqual(data, {"error": "forbidden"})

        self.set_peer(self.CORE_PEER)
        status, data, _body, _headers = self.summary(
            {"X-Forwarded-For": "192.168.18.20"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["pending"], 0)

    def test_pending_summary_tap_headline_has_no_coordinates(self):
        self.start_control()
        self.set_ui_dump(UI_DUMP_TAP_TARGET)
        key = self.new_proposal()
        self.set_peer(self.CORE_PEER)
        status, data, _body, _headers = self.summary()
        self.assertEqual(status, 200)
        self.assertEqual(data["pending"], 1)
        self.assertEqual(data["oldest_id"], key)
        self.assertEqual(
            data["headline"], 'This will tap: button "Living Room TV"'
        )
        self.assertNotIn("[", data["headline"])
        self.assertNotIn("540", data["headline"])

    def test_pending_summary_swipe_headline(self):
        self.start_control()
        self.set_ui_dump(UI_DUMP_TAP_TARGET)
        key = self.swipe_key()
        self.set_peer(self.CORE_PEER)
        status, data, _body, _headers = self.summary()
        self.assertEqual(status, 200)
        self.assertEqual(data["pending"], 1)
        self.assertEqual(data["oldest_id"], key)
        self.assertEqual(
            data["headline"],
            "DeepSeek wants to scroll down (swipe upwards) in Settings.",
        )
        self.assertNotIn("540, 780", data["headline"])

    def test_pending_summary_text_headline_has_no_typed_text(self):
        self.start_control()
        self.set_ui_dump(UI_DUMP_TEXT_FIELD)
        key = self.text_key()
        self.set_peer(self.CORE_PEER)
        status, data, body, _headers = self.summary()
        self.assertEqual(status, 200)
        self.assertEqual(data["pending"], 1)
        self.assertEqual(data["oldest_id"], key)
        self.assertEqual(
            data["headline"], "DeepSeek wants to type in Settings."
        )
        self.assertEqual(
            sorted(data), ["headline", "oldest_id", "pending"]
        )
        raw = body.decode("utf-8")
        self.assertNotIn(self.TEXT_PHRASE, raw)
        self.assertNotIn("192.168.1.50", raw)
        self.assertNotIn(self.token, raw)

    def test_pending_summary_counts_all_types_and_names_the_oldest(self):
        self.start_control()
        self.server.first_tap_test = False
        self.set_ui_dump(UI_DUMP_TAP_TARGET)
        tap_key = self.new_proposal()
        self.set_ui_dump(UI_DUMP_TAP_TARGET)
        self.swipe_key()
        self.set_ui_dump(UI_DUMP_TEXT_FIELD)
        self.text_key()
        self.set_peer(self.CORE_PEER)
        status, data, body, _headers = self.summary()
        self.assertEqual(status, 200)
        self.assertEqual(data["pending"], 3)
        self.assertEqual(data["oldest_id"], tap_key)
        self.assertEqual(
            data["headline"], 'This will tap: button "Living Room TV"'
        )
        raw = body.decode("utf-8")
        self.assertNotIn(self.TEXT_PHRASE, raw)
        self.assertNotIn("192.168.1.50", raw)
        self.assertNotIn(self.token, raw)

    def test_pending_summary_never_runs_adb_or_changes_state(self):
        self.start_control()
        self.set_ui_dump(UI_DUMP_TAP_TARGET)
        key = self.new_proposal()
        before = self.adb_log()
        self.set_peer(self.CORE_PEER)
        for _ in range(3):
            status, _data, _body, _headers = self.summary()
            self.assertEqual(status, 200)
        self.assertEqual(self.adb_log(), before)
        self.assertEqual(
            self.server.approvals.get(key)["state"], "pending"
        )
        self.assertNotIn("'input'", self.adb_log())


if __name__ == "__main__":
    unittest.main()
