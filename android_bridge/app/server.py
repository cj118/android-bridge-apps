"""Android Bridge - read-only screen viewing over wireless ADB.

Exposes: /health, /status, /screenshot, /pair (form), POST /pair,
POST /connect, POST /disconnect. No shell, no input injection.
"""

from __future__ import annotations

import base64
import errno
import hmac
import http.client
import json
import os
import re
import secrets
import socket
import stat
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import adbctl
import control as control_actions
import pngcheck

VERSION = "0.3.8"
PORT = 8791
DEFAULT_DATA_DIR = "/data"

MAX_BODY_BYTES = 8 * 1024
MAX_URI_LENGTH = 2048
MAX_TOKEN_FILE_BYTES = 512
MAX_CAPTURE_BYTES = 12 * 1024 * 1024
AUTH_FAIL_DELAY_SECONDS = 0.2
SOCKET_TIMEOUT_SECONDS = 15
MAX_CONNECTIONS = 16
CAPTURE_MIN_INTERVAL_SECONDS = 2.0
CAPTURE_WINDOW_SECONDS = 60.0
CAPTURE_WINDOW_MAX = 6

SELFTEST_DELAY_SECONDS = 0.5
SELFTEST_TIMEOUT_SECONDS = 5.0
SELFTEST_MAX_ATTEMPTS = 3
SELFTEST_PATH = "/status"

# Container DNS names allowed to call /mcp without a bearer token.
# The credential is the container's network identity, not a shared secret.
MCP_ALLOWED_HOSTS = (
    "f5588468-ha-opencode",
    "f5588468-ha-opencode-beta",
)
MCP_ALLOWLIST_TTL_SECONDS = 30.0
UI_SESSION_TTL_SECONDS = 8 * 3600
LOGIN_NONCE_TTL_SECONDS = 300
# Home Assistant ingress reaches an app from the Supervisor at 172.30.32.2.
# That single TCP peer is the only network evidence accepted for the
# null/missing-origin exception. X-Forwarded-For is never trusted.
INGRESS_PEERS = frozenset({"172.30.32.2"})
_INGRESS_PATH_RE = re.compile(r"\A/api/hassio_ingress/[A-Za-z0-9_-]{1,64}\Z")
_TRACKED_HEADERS = (
    "origin",
    "referer",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "x-ingress-path",
    "x-forwarded-for",
)
ACTION_SETTLE_SECONDS = 0.6
_ALLOWLIST = {"ips": frozenset(), "at": 0.0}


def _resolve_host_ips(host):
    try:
        return {info[4][0] for info in socket.getaddrinfo(host, None)}
    except OSError:
        return set()


def refresh_mcp_allowlist(force=False):
    now = time.monotonic()
    if (
        not force
        and _ALLOWLIST["ips"]
        and now - _ALLOWLIST["at"] < MCP_ALLOWLIST_TTL_SECONDS
    ):
        return _ALLOWLIST["ips"]
    ips = set()
    for host in MCP_ALLOWED_HOSTS:
        ips |= _resolve_host_ips(host)
    _ALLOWLIST["ips"] = frozenset(ips)
    _ALLOWLIST["at"] = now
    return _ALLOWLIST["ips"]


def mcp_source_allowed(address):
    return address in refresh_mcp_allowlist()

_TOKEN_RE = re.compile(r"\A[A-Za-z0-9_-]{32,128}\Z")
_LOGGABLE_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_DUMMY_TOKEN = b"x" * 43

_PAIR_PAGE = (
    "<!doctype html><html><head><meta charset='utf-8'>"
    "<title>Android Bridge - pair</title></head>"
    "<body style='font-family:system-ui;max-width:34rem;margin:3rem auto'>"
    "<h1>Pair tablet</h1>"
    "<p>On the tablet: Settings &rarr; Developer options &rarr; Wireless debugging."
    " The tablet shows a pairing port and a separate connect port.</p>"
    "<form method='post' action='pair'>"
    "<p><label>Bearer token<br><input name='token' type='password' size='54'></label></p>"
    "<p><label>Tablet IP<br><input name='host' size='30'></label></p>"
    "<p><label>Pairing port<br><input name='pairing_port' size='8'></label></p>"
    "<p><label>6-digit pairing code<br><input name='code' size='8'></label></p>"
    "<p><label>Connect port<br><input name='connect_port' size='8'></label></p>"
    "<p><button type='submit'>Pair and connect</button></p>"
    "</form></body></html>"
).encode("utf-8")


_CONTROL_LOGIN_HEAD = (
    "<!doctype html><html><head><meta charset='utf-8'>"
    "<title>Android Bridge - control sign in</title></head>"
    "<body style='font-family:system-ui;max-width:30rem;margin:3rem auto'>"
    "<h1>Control sign in</h1>"
    "<form method='post' action='control'>"
)
_CONTROL_LOGIN_TAIL = (
    "<p>Sign-in uses your Home Assistant user. No token is entered here.</p>"
    "<p><button type='submit'>Continue</button></p>"
    "</form></body></html>"
)


class TokenError(RuntimeError):
    """The private token store is missing, unsafe or malformed."""


# ---------------------------------------------------------------- token store


def private_dir(data_dir: str = DEFAULT_DATA_DIR) -> str:
    return os.path.join(data_dir, "private")


def token_path(data_dir: str = DEFAULT_DATA_DIR) -> str:
    return os.path.join(private_dir(data_dir), "token")


def device_path(data_dir: str = DEFAULT_DATA_DIR) -> str:
    return os.path.join(private_dir(data_dir), "device.json")


def _ensure_private_dir(data_dir: str) -> str:
    if not os.path.isdir(data_dir) or os.path.islink(data_dir):
        raise TokenError("data directory is missing or unsafe")
    path = private_dir(data_dir)
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
    except OSError:
        raise TokenError("private directory cannot be created") from None
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise TokenError("private directory is a symlink")
    if not stat.S_ISDIR(info.st_mode):
        raise TokenError("private path is not a directory")
    if info.st_uid != os.geteuid():
        raise TokenError("private directory has an unexpected owner")
    if stat.S_IMODE(info.st_mode) != 0o700:
        os.chmod(path, 0o700)
    return path


def _read_token_file(path: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise TokenError("token file is a symlink") from None
        if exc.errno == errno.ENOENT:
            raise TokenError("token file disappeared during startup") from None
        raise TokenError("token file cannot be opened") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise TokenError("token file is not a regular file")
        if info.st_uid != os.geteuid():
            raise TokenError("token file has an unexpected owner")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise TokenError("token file permissions are too open")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, 256)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_TOKEN_FILE_BYTES:
                raise TokenError("token file is too large")
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks).strip()
    if not raw:
        raise TokenError("token file is empty")
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError:
        raise TokenError("token file is not ASCII") from None
    if not _TOKEN_RE.match(value):
        raise TokenError("token file content is malformed")
    return value.encode("ascii")


def _create_token_file(path: str) -> bytes | None:
    token = secrets.token_urlsafe(32).encode("ascii")
    directory = os.path.dirname(path)
    temporary = os.path.join(directory, ".token.%s.tmp" % secrets.token_hex(8))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
    except OSError:
        raise TokenError("temporary token file cannot be created") from None
    try:
        os.write(descriptor, token + b"\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path)
    except FileExistsError:
        return None
    except OSError:
        raise TokenError("token file cannot be committed") from None
    finally:
        try:
            os.unlink(temporary)
        except OSError:
            pass
    return token


def load_allowed_users(data_dir: str = DEFAULT_DATA_DIR):
    """Home Assistant usernames permitted to open the browser control session."""
    path = os.path.join(data_dir, "options.json")
    try:
        with open(path, "rb") as handle:
            options = json.loads(handle.read(65536))
    except (OSError, ValueError):
        return frozenset()
    if not isinstance(options, dict):
        return frozenset()
    values = options.get("allowed_ha_users")
    if not isinstance(values, list):
        return frozenset()
    return frozenset(
        value.strip() for value in values
        if isinstance(value, str) and value.strip()
    )


def load_or_create_token(data_dir: str = DEFAULT_DATA_DIR) -> bytes:
    _ensure_private_dir(data_dir)
    path = token_path(data_dir)
    if os.path.lexists(path):
        return _read_token_file(path)
    created = _create_token_file(path)
    if created is not None:
        return created
    return _read_token_file(path)


# --------------------------------------------------------------- device state


def load_device(data_dir: str = DEFAULT_DATA_DIR) -> dict:
    try:
        with open(device_path(data_dir), "rb") as handle:
            info = json.loads(handle.read(2048))
        host = info.get("host")
        port = info.get("connect_port")
        if isinstance(host, str) and isinstance(port, str):
            return {"host": host, "connect_port": port}
    except (OSError, ValueError):
        pass
    return {}


def save_device(data_dir: str, host: str, connect_port: str) -> None:
    _ensure_private_dir(data_dir)
    path = device_path(data_dir)
    temporary = path + ".tmp"
    payload = json.dumps({"host": host, "connect_port": connect_port}).encode("utf-8")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


# ---------------------------------------------------------------- self-test


def run_auth_selftest(port, token, host="127.0.0.1", timeout=SELFTEST_TIMEOUT_SECONDS):
    """Loopback request through the normal bearer authentication path."""
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(
            "GET",
            SELFTEST_PATH,
            headers={"Authorization": "Bearer " + token.decode("ascii")},
        )
        response = connection.getresponse()
        response.read()
        return response.status
    except (OSError, ValueError, http.client.HTTPException):
        return None
    finally:
        try:
            connection.close()
        except OSError:
            pass


def _schedule_auth_selftest(server, port: int) -> None:
    def worker():
        status = None
        time.sleep(SELFTEST_DELAY_SECONDS)
        for attempt in range(SELFTEST_MAX_ATTEMPTS):
            status = run_auth_selftest(port, server.token)
            if status is not None:
                break
            if attempt + 1 < SELFTEST_MAX_ATTEMPTS:
                time.sleep(SELFTEST_DELAY_SECONDS)
        if status == 200:
            sys.stderr.write("auth_selftest=PASS http=%d\n" % status)
        else:
            sys.stderr.write("auth_selftest=FAIL\n")

    threading.Thread(target=worker, name="auth-selftest", daemon=True).start()


# -------------------------------------------------------------------- handler


class Handler(BaseHTTPRequestHandler):
    server_version = "AndroidBridge/" + VERSION
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = SOCKET_TIMEOUT_SECONDS

    _ROUTE_LABELS = {
        "/health": "health",
        "/status": "status",
        "/screenshot": "screenshot",
        "/pair": "pair",
        "/connect": "connect",
        "/disconnect": "disconnect",
        "/mcp": "mcp",
        "/window": "window",
        "/control": "control",
        "/control/session": "control-session",
        "/control/approve": "control-approve",
        "/control/reject": "control-reject",
        "/control/stop": "control-stop",
    }

    def _send_json(self, code, payload, extra_headers=None):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_png(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_request(self, code="-", size="-"):
        method = self.command if self.command in _LOGGABLE_METHODS else "OTHER"
        label = self._ROUTE_LABELS.get(self._path_only(), "other")
        sys.stderr.write(
            "%s %s %s %s\n" % (self.log_date_time_string(), method, label, code)
        )

    def log_message(self, fmt, *args):
        sys.stderr.write("%s http: detail suppressed\n" % self.log_date_time_string())

    def _path_only(self) -> str:
        return self.path.split("?", 1)[0]

    def _content_length(self) -> int:
        raw = self.headers.get("Content-Length")
        if raw is None:
            return 0
        try:
            return int(raw)
        except (TypeError, ValueError):
            return -1

    def _token_matches(self, candidate: str) -> bool:
        if not candidate or not _TOKEN_RE.match(candidate):
            hmac.compare_digest(_DUMMY_TOKEN, self.server.token)
            return False
        return hmac.compare_digest(candidate.encode("ascii"), self.server.token)

    def _presented_token(self):
        values = self.headers.get_all("Authorization") or []
        if len(values) != 1:
            return None
        parts = values[0].split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        return parts[1]

    def _authorized(self, form_token=None) -> bool:
        candidate = self._presented_token()
        if candidate is not None:
            return self._token_matches(candidate)
        if form_token is not None:
            return self._token_matches(form_token)
        hmac.compare_digest(_DUMMY_TOKEN, self.server.token)
        return False

    def _mcp_gate(self):
        """Return (allowed, error). Bearer wins; otherwise address AND window."""
        values = self.headers.get_all("Authorization") or []
        if values:
            return self._authorized(), "unauthorized"
        if not mcp_source_allowed(self.client_address[0]):
            return False, "unauthorized"
        if not self.server.viewing_active:
            return False, "viewing_session_closed"
        return True, None

    def _require_auth(self, form_token=None) -> bool:
        if self._authorized(form_token):
            return True
        time.sleep(AUTH_FAIL_DELAY_SECONDS)
        self._send_json(
            401,
            {"error": "unauthorized"},
            {"WWW-Authenticate": 'Bearer realm="android-bridge"'},
        )
        return False

    def _resolve_device(self):
        info = load_device(self.server.data_dir)
        if not info:
            return info, None
        try:
            devices = adbctl.list_devices()
        except adbctl.AdbError:
            return info, None
        matches = [d for d in devices if d["serial"].startswith(info["host"] + ":")]
        if len(matches) != 1:
            return info, None
        return info, matches[0]

    # ---------- GET ----------

    def do_GET(self):
        if len(self.path) > MAX_URI_LENGTH:
            self.close_connection = True
            self._send_json(414, {"error": "uri_too_long"})
            return
        try:
            self._route_get()
        except Exception as exc:
            sys.stderr.write("android-bridge: handler error: %s\n" % type(exc).__name__)
            try:
                self._send_json(500, {"error": "internal_error"})
            except Exception:
                self.close_connection = True

    def _route_get(self):
        path = self._path_only()

        if path in ("/", "/index.html"):
            prefix = self.headers.get("X-Ingress-Path", "").rstrip("/")
            self.send_response(302)
            self.send_header("Location", prefix + "/control")
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return

        if path == "/health":
            self._send_json(200, {"status": "ok"})
            return

        if path == "/pair":
            self._send_html(_PAIR_PAGE)
            return

        if path == "/control":
            nonce = self._ui_session()
            if not nonce:
                body, cookie = self._login_page()
                self._send_html_with(body, {"Set-Cookie": cookie})
                return
            query = urllib.parse.parse_qs(self.path.partition("?")[2])
            flash = (query.get("flash") or [""])[0]
            self._send_html(self._control_page(nonce, flash))
            return

        if path == "/status":
            if not self._require_auth():
                return
            info = load_device(self.server.data_dir)
            device = None
            if info:
                try:
                    _info, device = self._resolve_device()
                except adbctl.AdbError:
                    device = None
            self._send_json(
                200,
                {
                    "status": "ok",
                    "version": VERSION,
                    "stage": "read-only-screenshot",
                    "paired": bool(info),
                    "connected": device is not None,
                    "device_model": device["model"] if device else "",
                    "screenshot_enabled": True,
                    "uptime_seconds": int(
                        time.monotonic() - self.server.started_monotonic
                    ),
                },
            )
            return

        if path == "/screenshot":
            if not self._require_auth():
                return
            self._handle_screenshot()
            return

        self._send_json(404, {"error": "not_found"})

    _ERROR_STATUS = {
        "capture_busy": 429,
        "rate_limited": 429,
        "device_not_paired": 409,
        "device_not_connected": 409,
        "capture_timeout": 504,
        "image_too_large": 502,
        "capture_failed": 502,
        "invalid_image": 502,
    }

    def _capture_bytes(self):
        """Capture once with rate limiting. Returns (png_or_None, error_code)."""
        if not self.server.capture_lock.acquire(blocking=False):
            return None, "capture_busy"
        try:
            now = time.monotonic()
            times = self.server.capture_times
            while times and now - times[0] > CAPTURE_WINDOW_SECONDS:
                times.pop(0)
            if len(times) >= CAPTURE_WINDOW_MAX:
                return None, "rate_limited"
            if times and now - times[-1] < CAPTURE_MIN_INTERVAL_SECONDS:
                return None, "rate_limited"

            info = load_device(self.server.data_dir)
            if not info:
                return None, "device_not_paired"
            _info, device = self._resolve_device()
            if device is None:
                self._end_sessions()
                return None, "device_not_connected"

            try:
                data = adbctl.screencap(device["serial"], timeout=20.0)
                pngcheck.validate(data, max_bytes=MAX_CAPTURE_BYTES)
            except adbctl.AdbError as exc:
                if str(exc) == "timeout":
                    return None, "capture_timeout"
                if str(exc) == "output too large":
                    return None, "image_too_large"
                return None, "capture_failed"
            except pngcheck.PngError:
                return None, "invalid_image"

            times.append(now)
            return data, None
        finally:
            self.server.capture_lock.release()

    def _handle_screenshot(self):
        data, error = self._capture_bytes()
        if error is not None:
            status = self._ERROR_STATUS.get(error, 502)
            headers = {"Retry-After": "5"} if status == 429 else None
            self._send_json(status, {"error": error}, headers)
            return
        self._send_png(data)

    # ---------- MCP (read-only tools) ----------

    MCP_TOOLS = [
        {
            "name": "android_screenshot",
            "description": (
                "Capture the connected Android tablet screen once and return it "
                "as a PNG image. Read-only; no input is sent to the device."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        {
            "name": "android_status",
            "description": "Report whether the tablet is paired and connected.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        {
            "name": "android_tap",
            "description": (
                "Propose a tap. It does not execute: a human must approve it in "
                "the bridge Control page. Poll android_action_result afterwards."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "x": {"type": "integer", "minimum": 0, "maximum": 4095},
                    "y": {"type": "integer", "minimum": 0, "maximum": 4095},
                },
                "required": ["x", "y"],
                "additionalProperties": False,
            },
        },
        {
            "name": "android_swipe",
            "description": "Propose a swipe. Requires human approval in the bridge Control page.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "x1": {"type": "integer", "minimum": 0, "maximum": 4095},
                    "y1": {"type": "integer", "minimum": 0, "maximum": 4095},
                    "x2": {"type": "integer", "minimum": 0, "maximum": 4095},
                    "y2": {"type": "integer", "minimum": 0, "maximum": 4095},
                    "duration_ms": {"type": "integer", "minimum": 50, "maximum": 5000},
                },
                "required": ["x1", "y1", "x2", "y2"],
                "additionalProperties": False,
            },
        },
        {
            "name": "android_text",
            "description": "Propose typing text. Requires human approval in the bridge Control page.",
            "inputSchema": {
                "type": "object",
                "properties": {"text": {"type": "string", "maxLength": 200}},
                "required": ["text"],
                "additionalProperties": False,
            },
        },
        {
            "name": "android_action_result",
            "description": "Poll a proposed action by id; returns state and the post-action screenshot.",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "string", "maxLength": 32}},
                "required": ["id"],
                "additionalProperties": False,
            },
        },
    ]

    def _handle_mcp(self, body):
        try:
            message = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            self._send_json(
                200,
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32700, "message": "parse error"}},
            )
            return

        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or "method" not in message:
            self._send_json(
                200,
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32600, "message": "invalid request"}},
            )
            return

        method = message.get("method")
        message_id = message.get("id")

        if method.startswith("notifications/"):
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "android-bridge", "version": VERSION},
            }
        elif method == "tools/list":
            result = {"tools": self.MCP_TOOLS}
        elif method == "ping":
            result = {}
        elif method == "tools/call":
            self._mcp_tool_call(message, message_id)
            return
        else:
            self._send_json(
                200,
                {"jsonrpc": "2.0", "id": message_id,
                 "error": {"code": -32601, "message": "method not found"}},
            )
            return

        self._send_json(200, {"jsonrpc": "2.0", "id": message_id, "result": result})

    def _mcp_tool_call(self, message, message_id):
        params = message.get("params") or {}
        if not isinstance(params, dict):
            params = {}
        name = params.get("name")

        if name == "android_status":
            info = load_device(self.server.data_dir)
            _info, device = self._resolve_device()
            payload = {
                "paired": bool(info),
                "connected": device is not None,
                "device_model": device["model"] if device else "",
            }
            result = {
                "content": [{"type": "text", "text": json.dumps(payload)}],
                "isError": False,
            }
            self._send_json(200, {"jsonrpc": "2.0", "id": message_id, "result": result})
            return

        if name == "android_screenshot":
            data, error = self._capture_bytes()
            if error is not None:
                result = {
                    "content": [{"type": "text", "text": error}],
                    "isError": True,
                }
            else:
                result = {
                    "content": [
                        {
                            "type": "image",
                            "data": base64.b64encode(data).decode("ascii"),
                            "mimeType": "image/png",
                        }
                    ],
                    "isError": False,
                }
            self._send_json(200, {"jsonrpc": "2.0", "id": message_id, "result": result})
            return

        if name in ("android_tap", "android_swipe", "android_text"):
            self._mcp_propose(name, params, message_id)
            return

        if name == "android_action_result":
            self._mcp_action_result(params, message_id)
            return

        self._send_json(
            200,
            {"jsonrpc": "2.0", "id": message_id,
             "error": {"code": -32602, "message": "unknown tool"}},
        )

    def _mcp_error(self, message_id, text):
        self._send_json(
            200,
            {"jsonrpc": "2.0", "id": message_id,
             "result": {"content": [{"type": "text", "text": text}], "isError": True}},
        )

    def _mcp_propose(self, name, params, message_id):
        if not self.server.control_active:
            self._mcp_error(message_id, "control_session_inactive")
            return
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            arguments = {}
        try:
            if name == "android_tap":
                action = control_actions.validate_tap(arguments.get("x"), arguments.get("y"))
            elif name == "android_swipe":
                action = control_actions.validate_swipe(
                    arguments.get("x1"), arguments.get("y1"),
                    arguments.get("x2"), arguments.get("y2"),
                    arguments.get("duration_ms", 300),
                )
            else:
                action = control_actions.validate_text(arguments.get("text"))
        except control_actions.ActionError as exc:
            self._mcp_error(message_id, str(exc))
            return

        _info, device = self._resolve_device()
        if device is None:
            self._end_sessions()
            self._mcp_error(message_id, "device_not_connected")
            return

        try:
            preshot = adbctl.screencap(device["serial"], timeout=20.0)
            pngcheck.validate(preshot, max_bytes=MAX_CAPTURE_BYTES)
        except (adbctl.AdbError, pngcheck.PngError):
            self._mcp_error(message_id, "capture_failed")
            return

        try:
            record = self.server.approvals.create(action, device["serial"], preshot)
        except control_actions.ActionError as exc:
            self._mcp_error(message_id, str(exc))
            return

        summary = {
            "approval_id": record["id"],
            "state": "pending",
            "action": control_actions.describe(action),
            "device": device["serial"],
            "expires_in_seconds": int(control_actions.APPROVAL_TTL_SECONDS),
            "next": "await human approval in the Control page, then call android_action_result",
        }
        content = [
            {"type": "text", "text": json.dumps(summary)},
            {"type": "image", "data": base64.b64encode(preshot).decode("ascii"),
             "mimeType": "image/png"},
        ]
        self._send_json(
            200,
            {"jsonrpc": "2.0", "id": message_id,
             "result": {"content": content, "isError": False}},
        )

    def _mcp_action_result(self, params, message_id):
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            arguments = {}
        key = str(arguments.get("id") or "")
        record = self.server.approvals.get(key)
        if record is None:
            self._mcp_error(message_id, "unknown_approval")
            return
        payload = {
            "id": key,
            "state": record["state"],
            "action": control_actions.describe(record["action"]),
            "detail": record.get("detail", ""),
        }
        content = [{"type": "text", "text": json.dumps(payload)}]
        if record.get("postshot"):
            content.append(
                {"type": "image",
                 "data": base64.b64encode(record["postshot"]).decode("ascii"),
                 "mimeType": "image/png"}
            )
        self._send_json(
            200,
            {"jsonrpc": "2.0", "id": message_id,
             "result": {"content": content, "isError": False}},
        )

    # ---------- POST ----------

    def do_POST(self):
        self._browser_mode = False
        if len(self.path) > MAX_URI_LENGTH:
            self.close_connection = True
            self._send_json(414, {"error": "uri_too_long"})
            return
        length = self._content_length()
        if length < 0:
            self.close_connection = True
            self._send_json(400, {"error": "bad_content_length"})
            return
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            self._send_json(413, {"error": "payload_too_large"}, {"Connection": "close"})
            return
        body = self.rfile.read(length) if length else b""
        try:
            self._route_post(body)
        except Exception as exc:
            sys.stderr.write("android-bridge: handler error: %s\n" % type(exc).__name__)
            try:
                self._send_json(500, {"error": "internal_error"})
            except Exception:
                self.close_connection = True

    def _route_post(self, body: bytes):
        path = self._path_only()
        if path == "/mcp":
            allowed, error = self._mcp_gate()
            if not allowed:
                time.sleep(AUTH_FAIL_DELAY_SECONDS)
                status = 401 if error == "unauthorized" else 403
                self._send_json(
                    status,
                    {"error": error},
                    {"WWW-Authenticate": 'Bearer realm="android-bridge"'},
                )
                return
            self._handle_mcp(body)
            return
        if path not in (
            "/pair", "/connect", "/disconnect", "/window",
            "/control", "/control/session", "/control/approve",
            "/control/reject", "/control/stop",
        ):
            self.close_connection = True
            self._send_json(405, {"error": "method_not_allowed"}, {"Allow": "GET"})
            return

        fields = {}
        try:
            parsed = urllib.parse.parse_qs(
                body.decode("utf-8", "replace"), keep_blank_values=True
            )
            fields = {key: values[0] for key, values in parsed.items() if values}
        except ValueError:
            fields = {}

        if path == "/control":
            self._do_login(fields)
            return
        if path.startswith("/control/"):
            nonce = self._ui_session()
            csrf = fields.get("csrf")

            if path == "/control/stop":
                # Emergency stop: a valid CSRF-bound session, or the bearer token.
                if (
                    nonce
                    and self._ui_csrf_ok(nonce, csrf)
                    and self._origin_error(nonce) is None
                ):
                    self._browser_mode = True
                    self._do_stop()
                    return
                if self._authorized(fields.get("token")):
                    self._do_stop()
                    return
                self._control_denied("stop")
                return

            if not nonce:
                self._control_denied("session")
                return
            if not self._ui_csrf_ok(nonce, csrf):
                self._control_denied("csrf")
                return
            blocked = self._origin_error(nonce)
            if blocked:
                self._control_denied(blocked)
                return

            self._browser_mode = True
            if path == "/control/session":
                self._do_session(fields)
            elif path == "/control/approve":
                self._do_approve(fields)
            else:
                self._do_reject(fields)
            return

        if not self._require_auth(fields.get("token")):
            return
        fields.pop("token", None)

        if path == "/window":
            self._do_window(fields)
        elif path == "/pair":
            self._do_pair(fields)
        elif path == "/connect":
            self._do_connect(fields)
        else:
            self._do_disconnect()

    def _do_window(self, fields):
        """Start or stop the viewing session. No fixed duration."""
        action = (fields.get("action") or "").strip().lower()
        minutes = (fields.get("minutes") or "").strip()
        stop = action == "stop" or minutes == "0"
        self.server.viewing_active = not stop
        self._send_json(200, {"viewing": "active" if self.server.viewing_active else "stopped"})

    # ---------- human control surface ----------

    def _ui_session(self):
        """Return the first validated UI session nonce, or None.

        Browsers can hold several ab_ui cookies (different ingress paths, or
        left over from an earlier build). A stale one must not mask a live one.
        """
        header = self.headers.get("Cookie", "")
        for part in header.split(";"):
            name, _, value = part.strip().partition("=")
            if name != "ab_ui" or not value:
                continue
            nonce, _, signature = value.partition(".")
            if not nonce or not signature:
                continue
            expected = hmac.new(
                self.server.token, nonce.encode("ascii", "ignore"), "sha256"
            ).hexdigest()
            if not hmac.compare_digest(expected, signature):
                continue
            session = self.server.ui_sessions.get(nonce)
            if not session or session["expires"] <= time.monotonic():
                continue
            return nonce
        return None

    def _ui_csrf_ok(self, nonce, provided):
        session = self.server.ui_sessions.get(nonce) or {}
        if not provided or not session.get("csrf"):
            return False
        return hmac.compare_digest(session["csrf"], provided)

    @staticmethod
    def _normalise_origin(value):
        """Return scheme://host[:port] in lower case, or None if unusable."""
        if not value:
            return None
        value = value.strip()
        if not value or value.lower() == "null":
            return None
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return None
        return "%s://%s" % (parsed.scheme, parsed.netloc.lower())

    @staticmethod
    def _log_site(value):
        """Reduce Sec-Fetch-Site to a fixed vocabulary before logging."""
        if not value:
            return "missing"
        value = value.strip().lower()
        if value in ("same-origin", "same-site", "cross-site", "none"):
            return value
        return "other"

    def _origin_error(self, nonce):
        """Cross-site rejection for control actions.

        Host and X-Forwarded-Host are rewritten by the Home Assistant ingress
        and by upstream proxies, so they are not trust anchors. Two things are:
        the origin captured when the session was created, and the browser's own
        Sec-Fetch-Site. An opaque or absent Origin is accepted only when the
        browser states same-origin.
        """
        site = self.headers.get("Sec-Fetch-Site")
        raw = self.headers.get("Origin")
        presented = self._normalise_origin(raw)

        if raw is not None and presented is None and raw.strip().lower() != "null":
            return "origin_invalid"

        if raw is None or presented is None:
            # Missing or "null": the browser gave no origin at all.
            if site == "same-origin":
                return None
            if site is None and self._from_ingress():
                sys.stderr.write(
                    "reason=origin_null_ingress_ok peer=%s\n" % self._peer()
                )
                return None
            return "origin_null"

        if site is not None and site != "same-origin":
            return "cross_site" if site == "cross-site" else "sfs_not_same_origin"

        session = self.server.ui_sessions.get(nonce) or {}
        bound = session.get("origin")
        if bound is None:
            return "origin_unbound"
        if presented != bound:
            return "origin_mismatch"
        return None

    def _send_html_with(self, body, headers=None):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _peer(self):
        address = self.client_address[0]
        if address.startswith("::ffff:"):
            address = address[7:]
        return address

    def _from_ingress(self):
        return self._peer() in INGRESS_PEERS

    def _ingress_prefix(self):
        """Return the validated ingress prefix, '' if malformed, None if absent."""
        raw = (self.headers.get("X-Ingress-Path") or "").strip()
        if not raw:
            return None
        if not _INGRESS_PATH_RE.match(raw):
            return ""
        return raw

    def _present_header_names(self):
        names = [name for name in _TRACKED_HEADERS if self.headers.get(name) is not None]
        return ",".join(names) if names else "none"

    def _cookie_value(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            key, _, value = part.strip().partition("=")
            if key == name and value:
                return value
        return None

    def _login_page(self):
        now = time.monotonic()
        if len(self.server.login_nonces) > 64:
            for key in [k for k, v in self.server.login_nonces.items() if v <= now]:
                self.server.login_nonces.pop(key, None)
        nonce = secrets.token_hex(16)
        self.server.login_nonces[nonce] = time.monotonic() + LOGIN_NONCE_TTL_SECONDS
        body = (
            _CONTROL_LOGIN_HEAD
            + "<input type='hidden' name='nonce' value='%s'>" % nonce
            + _CONTROL_LOGIN_TAIL
        ).encode("utf-8")
        # Home Assistant rotates the ingress token, so the cookie is scoped to
        # the stable ingress root rather than to one token-specific prefix.
        if self._ingress_prefix():
            path = "/api/hassio_ingress/"
        else:
            path = "/"
        cookie = "ab_login=%s; Path=%s; HttpOnly; SameSite=Strict; Max-Age=%d" % (
            nonce,
            path,
            LOGIN_NONCE_TTL_SECONDS,
        )
        return body, cookie

    def _consume_login_nonce(self, fields):
        value = (fields.get("nonce") or "").strip()
        cookie = self._cookie_value("ab_login")
        if not value or not cookie:
            return False
        if not hmac.compare_digest(value, cookie):
            return False
        expires = self.server.login_nonces.pop(value, None)
        if expires is None or expires <= time.monotonic():
            return False
        return True

    def _do_login(self, fields):
        """Browser sign-in. Home Assistant identity only; the bearer is excluded."""
        if not self._from_ingress():
            self._login_denied("peer")
            return
        if not self._consume_login_nonce(fields):
            self._login_denied("login_nonce")
            return

        user = (self.headers.get("X-Remote-User-Name") or "").strip()
        if not user:
            self._login_denied("ha_user_missing")
            return
        if user not in self.server.allowed_users:
            self._login_denied("ha_user_not_allowed", user=user)
            return

        site = self.headers.get("Sec-Fetch-Site")
        raw_origin = self.headers.get("Origin")
        bound_origin = self._normalise_origin(raw_origin)
        if bound_origin is not None and site is not None and site != "same-origin":
            self._login_denied("sfs_not_same_origin")
            return

        prefix = self._ingress_prefix()
        if prefix is None:
            self._login_denied("ingress_path_missing")
            return
        if prefix == "":
            self._login_denied("ingress_path_invalid")
            return

        nonce = secrets.token_hex(16)
        csrf = hmac.new(
            self.server.token, (nonce + ":csrf").encode("ascii"), "sha256"
        ).hexdigest()[:32]
        self.server.ui_sessions[nonce] = {
            "expires": time.monotonic() + UI_SESSION_TTL_SECONDS,
            "csrf": csrf,
            "origin": bound_origin,
            "user": user,
        }
        signature = hmac.new(
            self.server.token, nonce.encode("ascii"), "sha256"
        ).hexdigest()
        cookie = "ab_ui=%s.%s; Path=%s/; HttpOnly; SameSite=Strict; Max-Age=%d" % (
            nonce,
            signature,
            prefix,
            int(UI_SESSION_TTL_SECONDS),
        )
        body = (
            "<html><body style='font-family:system-ui;margin:2rem'>"
            "<p>Signed in as <b>%s</b>.</p>"
            "<p><a href='control'>Open control</a></p></body></html>"
            % self._safe_text(user)
        ).encode("utf-8")
        self._send_html_with(body, {"Set-Cookie": cookie})

    @staticmethod
    def _safe_text(value):
        return "".join(ch for ch in value if ch.isalnum() or ch in "._-@ ")[:64]

    def _send_html_with(self, body, headers=None):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _peer(self):
        address = self.client_address[0]
        if address.startswith("::ffff:"):
            address = address[7:]
        return address

    def _from_ingress(self):
        return self._peer() in INGRESS_PEERS

    def _present_header_names(self):
        names = [name for name in _TRACKED_HEADERS if self.headers.get(name) is not None]
        return ",".join(names) if names else "none"

    def _cookie_value(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            key, _, value = part.strip().partition("=")
            if key == name and value:
                return value
        return None

    def _login_page(self):
        now = time.monotonic()
        if len(self.server.login_nonces) > 64:
            for key in [k for k, v in self.server.login_nonces.items() if v <= now]:
                self.server.login_nonces.pop(key, None)
        nonce = secrets.token_hex(16)
        self.server.login_nonces[nonce] = time.monotonic() + LOGIN_NONCE_TTL_SECONDS
        body = (
            _CONTROL_LOGIN_HEAD
            + "<input type='hidden' name='nonce' value='%s'>" % nonce
            + _CONTROL_LOGIN_TAIL
        ).encode("utf-8")
        # Home Assistant rotates the ingress token, so the cookie is scoped to
        # the stable ingress root rather than to one token-specific prefix.
        if self.headers.get("X-Ingress-Path"):
            path = "/api/hassio_ingress/"
        else:
            path = "/"
        cookie = "ab_login=%s; Path=%s; HttpOnly; SameSite=Strict; Max-Age=%d" % (
            nonce,
            path,
            LOGIN_NONCE_TTL_SECONDS,
        )
        return body, cookie

    def _consume_login_nonce(self, fields):
        value = (fields.get("nonce") or "").strip()
        cookie = self._cookie_value("ab_login")
        if not value or not cookie:
            return False
        if not hmac.compare_digest(value, cookie):
            return False
        expires = self.server.login_nonces.pop(value, None)
        if expires is None or expires <= time.monotonic():
            return False
        return True

    def _do_session(self, fields):
        view = (fields.get("view") or "").strip().lower()
        ctl = (fields.get("control") or "").strip().lower()
        with self.server.control_lock:
            if view in ("on", "off"):
                self.server.viewing_active = view == "on"
            if ctl in ("on", "off"):
                self.server.control_active = ctl == "on"
                if ctl == "off":
                    self.server.approvals.clear()
        self._respond(
            {
                "viewing": self.server.viewing_active,
                "control": self.server.control_active,
            },
            flash="session",
        )

    def _control_redirect(self, flash=None):
        prefix = self._ingress_prefix()
        if self._from_ingress():
            if prefix is None:
                sys.stderr.write(
                    "redirect_blocked reason=ingress_path_missing peer=%s\n"
                    % self._peer()
                )
                self._send_json(400, {"error": "ingress_path_missing"})
                return
            if prefix == "":
                sys.stderr.write(
                    "redirect_blocked reason=ingress_path_invalid peer=%s\n"
                    % self._peer()
                )
                self._send_json(400, {"error": "ingress_path_invalid"})
                return
            location = prefix + "/control"
        else:
            location = "/control"
        if flash:
            location += "?flash=" + urllib.parse.quote(flash, safe="")
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _respond(self, payload, status=200, flash=None):
        """Browsers get a redirect back to the panel; API clients get JSON."""
        if getattr(self, "_browser_mode", False):
            self._control_redirect(flash or ("ok" if status < 400 else "error"))
        else:
            self._send_json(status, payload)

    def _control_denied(self, reason):
        """Log which guard rejected the request. Header names only, no values."""
        sys.stderr.write(
            "control_forbidden reason=%s sfs=%s peer=%s hdrs=%s\n"
            % (
                reason,
                self._log_site(self.headers.get("Sec-Fetch-Site")),
                self._peer(),
                self._present_header_names(),
            )
        )
        time.sleep(AUTH_FAIL_DELAY_SECONDS)
        self._send_json(403, {"error": "forbidden"})

    def _login_denied(self, reason, user=None):
        """Reject sign-in. Header names only; never tokens or cookie values."""
        line = "login_forbidden reason=%s sfs=%s peer=%s hdrs=%s" % (
            reason,
            self._log_site(self.headers.get("Sec-Fetch-Site")),
            self._peer(),
            self._present_header_names(),
        )
        if user:
            line += " user=%s" % self._safe_text(user)
        sys.stderr.write(line + "\n")
        time.sleep(AUTH_FAIL_DELAY_SECONDS)
        self._send_json(403, {"error": "forbidden"})

    def _do_stop(self):
        with self.server.control_lock:
            self.server.control_active = False
            self.server.approvals.clear()
        self._respond({"control": False, "pending": 0}, flash="stopped")

    def _end_sessions(self):
        with self.server.control_lock:
            self.server.viewing_active = False
            self.server.control_active = False
            self.server.approvals.clear()

    def _do_approve(self, fields):
        key = (fields.get("id") or "").strip()
        with self.server.control_lock:
            if not self.server.control_active:
                self._respond({"error": "control_inactive"}, 409, flash="error")
                return
            try:
                record = self.server.approvals.approve(key)
            except control_actions.ActionError as exc:
                self._respond({"error": str(exc)}, 409, flash="error")
                return
            if record["expires"] <= time.monotonic():
                self.server.approvals.fail(key, "expired")
                self._respond({"error": "approval expired"}, 409, flash="error")
                return
            if (
                control_actions.fingerprint(
                    record["action"], record["device"], record["preshot"]
                )
                != record["fingerprint"]
            ):
                self.server.approvals.fail(key, "binding_mismatch")
                self._respond({"error": "binding mismatch"}, 409, flash="error")
                return
            _info, device = self._resolve_device()
            if device is None:
                self.server.approvals.fail(key, "device_unavailable")
                self._end_sessions()
                self._respond({"error": "device_unavailable"}, 409, flash="error")
                return
            if device["serial"] != record["device"]:
                self.server.approvals.fail(key, "device_mismatch")
                self._respond({"error": "device mismatch"}, 409, flash="error")
                return
            try:
                adbctl.run_input(
                    control_actions.adb_args(record["action"], device["serial"])
                )
            except adbctl.AdbError:
                self.server.approvals.fail(key, "action_failed")
                self._respond({"error": "action_failed"}, 502, flash="error")
                return

        time.sleep(ACTION_SETTLE_SECONDS)
        try:
            shot = adbctl.screencap(device["serial"], timeout=20.0)
            pngcheck.validate(shot, max_bytes=MAX_CAPTURE_BYTES)
        except (adbctl.AdbError, pngcheck.PngError):
            self.server.approvals.complete(key, None, "executed_no_shot")
            self._respond(
                {"status": "executed", "screenshot": "unavailable"}, flash="executed"
            )
            return
        self.server.approvals.complete(key, shot)
        self._respond({"status": "executed"}, flash="executed")

    def _do_reject(self, fields):
        key = (fields.get("id") or "").strip()
        try:
            self.server.approvals.reject(key)
        except control_actions.ActionError as exc:
            self._respond({"error": str(exc)}, 409, flash="error")
            return
        self._respond({"status": "rejected"}, flash="rejected")

    def _control_page(self, nonce, flash=""):
        session = self.server.ui_sessions.get(nonce) or {}
        csrf = session.get("csrf", "")
        flash_html = (
            "<p style='padding:.5rem;background:#223;color:#cfe'>%s</p>"
            % _safe_text(flash)
            if flash
            else ""
        )
        pending = self.server.approvals.pending()
        cards = []
        for record in pending:
            image = base64.b64encode(record["preshot"]).decode("ascii")
            remaining = max(0, int(record["expires"] - time.monotonic()))
            cards.append(
                "<div style='border:1px solid #555;padding:1rem;margin:1rem 0'>"
                "<h3>%s</h3><p>Device %s &middot; id %s &middot; expires in %ds</p>"
                "<img src='data:image/png;base64,%s' style='max-width:100%%'>"
                "<form method='post' action='control/approve' style='display:inline'>"
                "<input type='hidden' name='csrf' value='%s'>"
                "<input type='hidden' name='id' value='%s'><button>Approve</button></form> "
                "<form method='post' action='control/reject' style='display:inline'>"
                "<input type='hidden' name='csrf' value='%s'>"
                "<input type='hidden' name='id' value='%s'><button>Reject</button></form>"
                "</div>"
                % (
                    control_actions.describe(record["action"]),
                    record["device"],
                    record["id"],
                    remaining,
                    image,
                    csrf,
                    record["id"],
                    csrf,
                    record["id"],
                )
            )
        viewing = "ON" if self.server.viewing_active else "off"
        control = "ON" if self.server.control_active else "off"
        body = (
            "<html><body style='font-family:system-ui;max-width:60rem;margin:2rem auto'>"
            "<h1>Android Bridge control</h1>"
            "%s"
            "<p>Viewing session: <b>%s</b> &middot; Control session: <b>%s</b></p>"
            "<form method='post' action='control/session'>"
            "<input type='hidden' name='csrf' value='%s'>"
            "<button name='view' value='%s'>Viewing %s</button> "
            "<button name='control' value='%s'>Control %s</button></form>"
            "<form method='post' action='control/stop' style='margin-top:1rem'>"
            "<input type='hidden' name='csrf' value='%s'>"
            "<button style='background:#a00;color:#fff;padding:.6rem 2rem'>STOP</button>"
            "</form><h2>Pending approvals</h2>%s</body></html>"
            % (
                flash_html,
                viewing,
                control,
                csrf,
                "off" if self.server.viewing_active else "on",
                "ON" if self.server.viewing_active else "start",
                "off" if self.server.control_active else "on",
                "ON" if self.server.control_active else "start",
                csrf,
                "".join(cards) or "<p>None.</p>",
            )
        )
        return body.encode("utf-8")

    def _do_pair(self, fields):
        host = (fields.get("host") or "").strip()
        pairing_port = (fields.get("pairing_port") or "").strip()
        code = (fields.get("code") or "").strip()
        connect_port = (fields.get("connect_port") or "").strip()
        try:
            adbctl.pair(host, pairing_port, code)
            adbctl.connect(host, connect_port)
        except adbctl.AdbError:
            self._send_json(400, {"error": "pairing_failed"})
            return
        try:
            save_device(self.server.data_dir, host, connect_port)
        except OSError:
            self._send_json(500, {"error": "state_write_failed"})
            return
        self._send_json(200, {"status": "paired"})

    def _do_connect(self, fields):
        host = (fields.get("host") or "").strip()
        port = (fields.get("connect_port") or "").strip()
        try:
            adbctl.connect(host, port)
        except adbctl.AdbError:
            self._send_json(400, {"error": "connect_failed"})
            return
        try:
            save_device(self.server.data_dir, host, port)
        except OSError:
            self._send_json(500, {"error": "state_write_failed"})
            return
        self._send_json(200, {"status": "connected"})

    def _do_disconnect(self):
        self._end_sessions()
        try:
            for device in adbctl.list_devices():
                adbctl.disconnect(device["serial"])
        except adbctl.AdbError:
            self._send_json(502, {"error": "disconnect_failed"})
            return
        self._send_json(200, {"status": "disconnected"})

    def _reject_method(self):
        self.close_connection = True
        self._send_json(405, {"error": "method_not_allowed"}, {"Allow": "GET, POST"})

    def do_PUT(self):
        self._reject_method()

    def do_PATCH(self):
        self._reject_method()

    def do_DELETE(self):
        self._reject_method()


class BridgeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32
    max_connections = MAX_CONNECTIONS

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._slots = threading.BoundedSemaphore(self.max_connections)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                pass
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        finally:
            self._slots.release()


def create_server(host="0.0.0.0", port=PORT, data_dir=DEFAULT_DATA_DIR):
    token = load_or_create_token(data_dir)
    server = BridgeServer((host, port), Handler)
    server.token = token
    server.data_dir = data_dir
    server.capture_lock = threading.Lock()
    server.capture_times = []
    server.viewing_active = False
    server.control_active = False
    server.ui_sessions = {}
    server.login_nonces = {}
    server.allowed_users = load_allowed_users(data_dir)
    server.control_lock = threading.Lock()
    server.approvals = control_actions.Approvals()
    server.started_monotonic = time.monotonic()
    return server


def main() -> int:
    try:
        server = create_server()
    except TokenError as exc:
        sys.stderr.write("android-bridge: fatal: %s\n" % exc)
        return 1
    except OSError as exc:
        sys.stderr.write(
            "android-bridge: fatal: startup failed (%s)\n" % type(exc).__name__
        )
        return 1

    sys.stderr.write(
        "android-bridge %s listening on %d (bearer auth enabled)\n"
        % (VERSION, PORT)
    )
    _schedule_auth_selftest(server, server.server_address[1])
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
