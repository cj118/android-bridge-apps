"""Android Bridge - read-only screen viewing over wireless ADB.

Exposes: /health, /status, /screenshot, /pair (form), POST /pair,
POST /connect, POST /disconnect. No shell, no input injection.
"""

from __future__ import annotations

import base64
import errno
import hmac
import html
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
import options_bridge
import pngcheck
import reconnect as reconnect_module

VERSION = "0.3.21"
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
CONTROL_MINUTES_DEFAULT = options_bridge.CONTROL_MINUTES_DEFAULT
CONTROL_MINUTES_MIN = options_bridge.CONTROL_MINUTES_MIN
CONTROL_MINUTES_MAX = options_bridge.CONTROL_MINUTES_MAX
CONTROL_MINUTES_FILENAME = options_bridge.CONTROL_MINUTES_FILENAME
CONTROL_SESSION_TTL_SECONDS = CONTROL_MINUTES_DEFAULT * 60
PROPOSAL_COOLDOWN_SECONDS = 5.0
# First live tap test: only one pending proposal. Set False for the 3 cap.
FIRST_TAP_TEST_MODE = True
LOGIN_NONCE_TTL_SECONDS = 300
# Home Assistant ingress reaches an app from the Supervisor at 172.30.32.2.
# That single TCP peer is the only network evidence accepted for the
# null/missing-origin exception. X-Forwarded-For is never trusted.
INGRESS_PEERS = frozenset({"172.30.32.2"})
_FLASH_MESSAGES = {
    "session": "Session updated.",
    "executed": "Action approved and executed.",
    "rejected": "Action rejected.",
    "stopped": "STOP: control disabled and pending approvals cancelled.",
    "ok": "Done.",
    "error": "The action was not completed. Check the log.",
    "paired": "Tablet paired and connected.",
    "pair_failed": "Pairing failed. Check the IP, ports and code.",
    "disconnected": "Tablet disconnected.",
    "reconnected": "Connected to the saved tablet.",
    "reconnect_failed": (
        "Could not verify the saved tablet. Nothing was changed."
    ),
    "screen_changed": "Screen changed — ask again.",
}
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

# MCP tools the server knows how to run. Exposure is configured separately;
# the default is the read-only tools only.
DEFAULT_EXPOSED_TOOLS = (
    "android_screenshot",
    "android_status",
    "android_ui_elements",
)
EXPOSE_TOOLS_FILENAME = "expose_tools.json"


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


def tools_path(data_dir: str = DEFAULT_DATA_DIR) -> str:
    return os.path.join(private_dir(data_dir), EXPOSE_TOOLS_FILENAME)


def control_minutes_path(data_dir: str = DEFAULT_DATA_DIR) -> str:
    return os.path.join(private_dir(data_dir), CONTROL_MINUTES_FILENAME)


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
    """Home Assistant usernames permitted to open the browser control session.

    Reads only the private handoff written at startup by options_bridge.py.
    /data/options.json is Supervisor-managed, root-only, and never read here.
    """
    path = os.path.join(private_dir(data_dir), "allowed_users.json")
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            return frozenset()
        if info.st_uid != os.geteuid():
            return frozenset()
        if stat.S_IMODE(info.st_mode) & 0o077:
            return frozenset()
        with open(path, "rb") as handle:
            data = json.loads(handle.read(65536))
    except (OSError, ValueError):
        return frozenset()
    if not isinstance(data, dict):
        return frozenset()
    values = data.get("allowed_ha_users")
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


def _safe_option_name(value):
    """Reduce a configured tool name to log-safe characters."""
    if not isinstance(value, str):
        return "non_string"
    cleaned = re.sub(r"[^A-Za-z0-9_.*-]", "", value)[:40]
    return cleaned or "empty"


def load_exposed_tools(data_dir: str = DEFAULT_DATA_DIR):
    """Return the MCP tools this server may expose.

    Only the private handoff written at startup is read. Missing, malformed,
    loosely permissioned or wrongly typed settings fall back to the read-only
    default. Unknown names are dropped and logged. An explicitly empty list
    stays empty.
    """
    fallback = tuple(DEFAULT_EXPOSED_TOOLS)
    path = tools_path(data_dir)
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            return fallback
        if info.st_uid != os.geteuid():
            return fallback
        if stat.S_IMODE(info.st_mode) & 0o077:
            return fallback
        with open(path, "rb") as handle:
            data = json.loads(handle.read(65536))
    except (OSError, ValueError):
        return fallback
    if not isinstance(data, dict):
        return fallback
    values = data.get("expose_tools")
    if not isinstance(values, list):
        return fallback
    selected = []
    for value in values:
        name = value.strip() if isinstance(value, str) else None
        if name is None or name not in KNOWN_MCP_TOOLS:
            sys.stderr.write(
                "mcp_tool_ignored name=%s\n" % _safe_option_name(value)
            )
            continue
        if name not in selected:
            selected.append(name)
    return tuple(selected)


def load_control_minutes(data_dir: str = DEFAULT_DATA_DIR) -> int:
    """Return the configured Control session length in minutes.

    Only the private handoff written at startup is read. Missing, malformed,
    loosely permissioned or out-of-range settings fall back to the default.
    """
    fallback = CONTROL_MINUTES_DEFAULT
    path = control_minutes_path(data_dir)
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            return fallback
        if info.st_uid != os.geteuid():
            return fallback
        if stat.S_IMODE(info.st_mode) & 0o077:
            return fallback
        with open(path, "rb") as handle:
            data = json.loads(handle.read(65536))
    except (OSError, ValueError):
        return fallback
    if not isinstance(data, dict):
        return fallback
    value = data.get("control_minutes")
    if isinstance(value, bool) or not isinstance(value, int):
        return fallback
    if not CONTROL_MINUTES_MIN <= value <= CONTROL_MINUTES_MAX:
        return fallback
    return value


# --------------------------------------------------------------- device state


def load_device(data_dir: str = DEFAULT_DATA_DIR) -> dict:
    try:
        with open(device_path(data_dir), "rb") as handle:
            info = json.loads(handle.read(2048))
        host = info.get("host")
        port = info.get("connect_port")
        if isinstance(host, str) and isinstance(port, str):
            device = {"host": host, "connect_port": port}
            for key in ("serial", "model"):
                value = info.get(key)
                if isinstance(value, str) and value.strip():
                    device[key] = value.strip()
            return device
    except (OSError, ValueError):
        pass
    return {}


def save_device(data_dir: str, host: str, connect_port: str, identity=None) -> None:
    """Persist the target. Identity is only ever supplied by a panel connect."""
    _ensure_private_dir(data_dir)
    path = device_path(data_dir)
    temporary = path + ".tmp"
    payload = {"host": host, "connect_port": connect_port}
    for key in ("serial", "model"):
        value = (identity or {}).get(key)
        if isinstance(value, str) and value.strip():
            payload[key] = value.strip()
    encoded = json.dumps(payload).encode("utf-8")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def capture_identity(device, strict=False):
    """Read the hardware identity saved by a human-initiated panel connect.

    ro.serialno is the physical serial. The adb transport address is never
    used as identity. A strict read is for reconnecting to a saved tablet: if
    either identity value cannot be read, return None.
    """
    device = device or {}
    transport = device.get("serial", "")
    model = device.get("model", "")
    serial = ""
    try:
        serial = adbctl.get_hardware_serial(transport)
    except adbctl.AdbError:
        if strict:
            return None
    try:
        read_model = adbctl.get_model(transport)
    except adbctl.AdbError:
        if strict:
            return None
        read_model = ""
    if read_model:
        model = read_model
    elif strict:
        return None
    if strict and (not serial or not (model or "").strip()):
        return None
    identity = {}
    if serial:
        identity["serial"] = serial
    if model:
        identity["model"] = model
    return identity


def same_model(left, right):
    """Compare model names with hyphens and underscores equivalent."""
    def normalise(value):
        value = (value or "").strip().lower()
        value = value.replace("-", " ").replace("_", " ")
        return " ".join(value.split())

    return normalise(left) == normalise(right)


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
        "/control/reconnect": "control-reconnect",
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

    def _viewing_open(self):
        """Fail closed: a missing, zero, invalid or past expiry is not open."""
        if not self.server.viewing_active:
            return False
        try:
            expires = float(getattr(self.server, "viewing_expires", 0.0))
        except (TypeError, ValueError):
            return False
        if expires <= 0.0:
            return False
        return time.monotonic() < expires

    def _control_open_locked(self):
        """Control must be active and unexpired. Expiry cancels pending work."""
        if not self.server.control_active:
            return False
        try:
            expires = float(getattr(self.server, "control_expires", 0.0))
        except (TypeError, ValueError):
            expires = 0.0
        if expires <= 0.0:
            # Compatibility for callers/tests that set the legacy boolean.
            return True
        if time.monotonic() < expires:
            return True
        self.server.control_active = False
        self.server.control_expires = 0.0
        self.server.approvals.clear()
        self.server.safety_epoch = getattr(self.server, "safety_epoch", 0) + 1
        return False

    def _control_open(self):
        with self.server.control_lock:
            return self._control_open_locked()

    def _control_session_seconds(self):
        """Validate the configured Control length; never trust a bad value."""
        minutes = getattr(
            self.server, "control_minutes", CONTROL_MINUTES_DEFAULT
        )
        if isinstance(minutes, bool) or not isinstance(minutes, int):
            minutes = CONTROL_MINUTES_DEFAULT
        if not CONTROL_MINUTES_MIN <= minutes <= CONTROL_MINUTES_MAX:
            minutes = CONTROL_MINUTES_DEFAULT
        return minutes * 60

    def _mcp_source_ok(self):
        """Only the TCP peer address counts. Forwarding headers are ignored."""
        return mcp_source_allowed(self.client_address[0])

    def _mcp_deny(self, error):
        time.sleep(AUTH_FAIL_DELAY_SECONDS)
        status = 401 if error == "unauthorized" else 403
        self._send_json(
            status,
            {"error": error},
            {"WWW-Authenticate": 'Bearer realm="android-bridge"'},
        )

    _MCP_PASSIVE_METHODS = ("initialize", "tools/list", "ping")

    def _mcp_passive(self, method):
        """Discovery and protocol liveness. Never touches ADB or screen data."""
        return (
            method in self._MCP_PASSIVE_METHODS
            or method.startswith("notifications/")
        )

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

    def _adb_key_state(self):
        path = os.path.join(self.server.data_dir, ".android", "adbkey")
        try:
            info = os.lstat(path)
        except OSError:
            return "missing"
        if not stat.S_ISREG(info.st_mode):
            return "unreadable"
        if info.st_uid != os.geteuid():
            return "unreadable"
        if stat.S_IMODE(info.st_mode) & 0o077:
            return "unreadable"
        try:
            with open(path, "rb") as handle:
                handle.read(1)
        except OSError:
            return "unreadable"
        return "ok"

    def _resolve_target(self, host):
        try:
            devices = adbctl.list_devices()
        except adbctl.AdbError:
            return None
        matches = [d for d in devices if d["serial"].startswith(host + ":")]
        if len(matches) != 1:
            return None
        return matches[0]

    def _resolve_device(self):
        info = load_device(self.server.data_dir)
        if not info:
            return info, None
        return info, self._resolve_target(info["host"])

    def _resolve_after_reconnect(self):
        """Resolve the device, trying one bounded reconnect if it is absent."""
        info, device = self._resolve_device()
        if device is not None or not info:
            return info, device
        if self.server.reconnector.lazy(info):
            return self._resolve_device()
        return info, None

    # ---------- GET ----------

    def do_GET(self):
        if len(self.path) > MAX_URI_LENGTH:
            self.close_connection = True
            self._send_json(414, {"error": "uri_too_long"})
            return
        try:
            self._route_get()
        except Exception as exc:
            self._log_handler_error(exc)
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
                    _info, device = self._resolve_after_reconnect()
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
            if not self._viewing_open():
                self._send_json(403, {"error": "viewing_session_closed"})
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

    def _capture_frame(self):
        """Capture once with rate limiting. Returns (png, error, device)."""
        if not self.server.capture_lock.acquire(blocking=False):
            return None, "capture_busy", None
        try:
            now = time.monotonic()
            times = self.server.capture_times
            while times and now - times[0] > CAPTURE_WINDOW_SECONDS:
                times.pop(0)
            if len(times) >= CAPTURE_WINDOW_MAX:
                return None, "rate_limited", None
            if times and now - times[-1] < CAPTURE_MIN_INTERVAL_SECONDS:
                return None, "rate_limited", None

            info = load_device(self.server.data_dir)
            if not info:
                return None, "device_not_paired", None
            _info, device = self._resolve_after_reconnect()
            if device is None:
                self._end_sessions()
                return None, "device_not_connected", None

            try:
                data = adbctl.screencap(device["serial"], timeout=20.0)
                pngcheck.validate(data, max_bytes=MAX_CAPTURE_BYTES)
            except adbctl.AdbError as exc:
                if str(exc) == "timeout":
                    return None, "capture_timeout", None
                if str(exc) == "output too large":
                    return None, "image_too_large", None
                return None, "capture_failed", None
            except pngcheck.PngError:
                return None, "invalid_image", None

            times.append(now)
            return data, None, device
        finally:
            self.server.capture_lock.release()

    def _capture_bytes(self):
        """Compatibility wrapper for screenshot callers."""
        data, error, _device = self._capture_frame()
        return data, error

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
            "name": "android_ui_elements",
            "description": (
                "List visible clickable elements with names and bounds so a "
                "target can be chosen instead of guessed. Read-only; needs "
                "Viewing and a connected tablet."
            ),
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
                "the bridge Control page. The result names the element found at "
                "the given point. Poll android_action_result afterwards."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "x": {"type": "integer", "minimum": 0, "maximum": 4095},
                    "y": {"type": "integer", "minimum": 0, "maximum": 4095},
                    "reason": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 200,
                        "description": "Human-readable explanation shown on the approval card.",
                    },
                },
                "required": ["x", "y", "reason"],
                "additionalProperties": False,
            },
        },
        {
            "name": "android_swipe",
            "description": (
                "Propose a swipe. It does not execute: a human must approve it "
                "in the bridge Control page. Both points must be at least 80 px "
                "from every screen edge, 100 px to 70% of the screen apart and "
                "within 20 degrees of an axis, over 300-1500 ms. The result names "
                "the direction, the foreground app and the element under the "
                "start point. Poll android_action_result afterwards."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "x1": {"type": "integer", "minimum": 0, "maximum": 4095},
                    "y1": {"type": "integer", "minimum": 0, "maximum": 4095},
                    "x2": {"type": "integer", "minimum": 0, "maximum": 4095},
                    "y2": {"type": "integer", "minimum": 0, "maximum": 4095},
                    "duration_ms": {
                        "type": "integer",
                        "minimum": 300,
                        "maximum": 1500,
                        "description": "Swipe duration in milliseconds.",
                    },
                    "reason": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 200,
                        "description": "Human-readable explanation shown on the approval card.",
                    },
                    "purpose": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 200,
                        "description": "Plain-English account of what the gesture does.",
                    },
                },
                "required": ["x1", "y1", "x2", "y2", "reason", "purpose"],
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

    def _handle_mcp_gated(self, body):
        """Source allowlist for everything; Viewing for everything but discovery.

        A bearer token is never accepted as a substitute for either control.
        """
        if not self._mcp_source_ok():
            self._mcp_deny("unauthorized")
            return

        message, error = self._parse_mcp(body)
        if error is not None:
            self._send_json(200, {"jsonrpc": "2.0", "id": None, "error": error})
            return
        if not self._mcp_passive(message["method"]) and not self._viewing_open():
            self._mcp_deny("viewing_session_closed")
            return
        self._handle_mcp_message(message)

    def _parse_mcp(self, body):
        """Return (message, error) without logging or touching the device."""
        try:
            message = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            return None, {"code": -32700, "message": "parse error"}
        if (
            not isinstance(message, dict)
            or message.get("jsonrpc") != "2.0"
            or not isinstance(message.get("method"), str)
        ):
            return None, {"code": -32600, "message": "invalid request"}
        return message, None

    def _handle_mcp_message(self, message):
        method = message["method"]
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
            result = {"tools": self._advertised_tools()}
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

    def _advertised_tools(self):
        exposed = self.server.exposed_tools
        return [tool for tool in self.MCP_TOOLS if tool["name"] in exposed]

    def _mcp_tool_call(self, message, message_id):
        params = message.get("params") or {}
        if not isinstance(params, dict):
            params = {}
        name = params.get("name")

        # Enforced before any device, capture or input work. Not-exposed and
        # unknown names share one answer so exposure cannot be probed.
        if not isinstance(name, str) or name not in self.server.exposed_tools:
            self._send_json(
                200,
                {"jsonrpc": "2.0", "id": message_id,
                 "error": {"code": -32602, "message": "unknown tool"}},
            )
            return

        if name == "android_status":
            info = load_device(self.server.data_dir)
            _info, device = self._resolve_after_reconnect()
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

        if name == "android_ui_elements":
            self._mcp_ui_elements(message_id)
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

    def _mcp_ui_elements(self, message_id):
        """Read-only target list. Viewing is enforced by the tools/call gate."""
        _info, device = self._resolve_after_reconnect()
        if device is None:
            self._mcp_error(message_id, "device_not_connected")
            return
        try:
            xml = adbctl.ui_dump(device["serial"])
        except adbctl.AdbError as exc:
            if str(exc) == "timeout":
                self._mcp_error(message_id, "ui_dump_timeout")
            else:
                self._mcp_error(message_id, "ui_dump_failed")
            return
        payload = control_actions.list_clickable(xml)
        result = {
            "content": [{"type": "text", "text": json.dumps(payload)}],
            "isError": False,
        }
        self._send_json(
            200, {"jsonrpc": "2.0", "id": message_id, "result": result}
        )

    def _tap_target(self, device, x, y):
        """What sits under the proposed point, from a fresh UI dump."""
        try:
            xml = adbctl.ui_dump(device["serial"])
        except adbctl.AdbError:
            return control_actions.unknown_target()
        return control_actions.describe_target(xml, x, y)

    def _mcp_propose(self, name, params, message_id):
        if not self._control_open():
            self._mcp_error(message_id, "control_session_inactive")
            return
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            arguments = {}

        reason = None
        purpose = None
        if name == "android_tap":
            try:
                reason = control_actions.validate_reason(arguments.get("reason"))
            except control_actions.ActionError as exc:
                self._mcp_error(message_id, str(exc))
                return
        elif name == "android_swipe":
            try:
                reason = control_actions.validate_reason(
                    arguments.get("reason")
                )
                purpose = control_actions.validate_purpose(
                    arguments.get("purpose")
                )
            except control_actions.ActionError as exc:
                self._mcp_error(message_id, str(exc))
                return

        if not self.server.proposal_lock.acquire(blocking=False):
            self._mcp_error(message_id, "proposal_busy")
            return
        try:
            now = time.monotonic()
            if now - self.server.last_proposal_at < PROPOSAL_COOLDOWN_SECONDS:
                self._mcp_error(message_id, "proposal_cooldown")
                return
            self.server.last_proposal_at = now
            safety_epoch = getattr(self.server, "safety_epoch", 0)
            if (
                self.server.first_tap_test
                and self.server.approvals.in_flight_count() >= 1
            ):
                self._mcp_error(message_id, "too many pending approvals")
                return

            data, error, device = self._capture_frame()
            if error is not None:
                self._mcp_error(message_id, error)
                return
            try:
                image = pngcheck.decode(data, max_bytes=MAX_CAPTURE_BYTES)
            except pngcheck.PngError:
                self._mcp_error(message_id, "invalid_image")
                return

            try:
                if name == "android_tap":
                    action = control_actions.validate_tap(
                        arguments.get("x"), arguments.get("y"),
                        image.width, image.height, reason,
                    )
                elif name == "android_swipe":
                    action = control_actions.validate_swipe(
                        arguments.get("x1"), arguments.get("y1"),
                        arguments.get("x2"), arguments.get("y2"),
                        arguments.get("duration_ms", 300),
                        image.width, image.height, reason, purpose,
                    )
                else:
                    action = control_actions.validate_text(arguments.get("text"))
            except control_actions.ActionError as exc:
                self._mcp_error(message_id, str(exc))
                return

            if action.get("type") == "tap":
                action["target"] = self._tap_target(
                    device, action["x"], action["y"]
                )
            elif action.get("type") == "swipe":
                action["start_target"] = self._tap_target(
                    device, action["x1"], action["y1"]
                )
                try:
                    package = adbctl.foreground_package(device["serial"])
                except adbctl.AdbError:
                    package = ""
                action["app_package"] = package
                action["app"] = (
                    control_actions.app_label(package) or "the current app"
                )

            info = load_device(self.server.data_dir)
            saved_serial = (info.get("serial") or "").strip()
            try:
                hardware_serial = adbctl.get_hardware_serial(device["serial"])
            except adbctl.AdbError:
                self._mcp_error(message_id, "identity_unverified")
                return
            if (
                adbctl.is_hardware_serial(saved_serial)
                and saved_serial != hardware_serial
            ):
                self._mcp_error(message_id, "identity_mismatch")
                return

            if (
                not self._control_open()
                or getattr(self.server, "safety_epoch", 0) != safety_epoch
            ):
                self._mcp_error(message_id, "control_session_inactive")
                return

            orientation = pngcheck.orientation(image.width, image.height)
            try:
                record = self.server.approvals.create(
                    action, device["serial"], data, image.width, image.height,
                    orientation, hardware_serial,
                    getattr(self.server, "safety_epoch", 0),
                )
            except control_actions.ActionError as exc:
                self._mcp_error(message_id, str(exc))
                return
        finally:
            self.server.proposal_lock.release()

        target = action.get("target") or {}
        summary = {
            "approval_id": record["id"],
            "state": "pending",
            "action": control_actions.describe(action),
            "tap_target": target.get("description", ""),
            "tap_target_clickable": bool(target.get("clickable", False)),
            "reason": action.get("reason", ""),
            "device": device["serial"],
            "width": image.width,
            "height": image.height,
            "orientation": orientation,
            "expires_in_seconds": int(control_actions.APPROVAL_TTL_SECONDS),
            "next": "await human approval in the Control page, then call android_action_result",
        }
        if action.get("type") == "swipe":
            start_target = action.get("start_target") or {}
            summary.update(
                {
                    "direction": action["direction"],
                    "app": action["app"],
                    "app_package": action.get("app_package", ""),
                    "purpose": action["purpose"],
                    "distance": action.get("distance", 0),
                    "start_target": start_target.get("description", ""),
                    "message": control_actions.swipe_headline(action),
                }
            )
        content = [
            {"type": "text", "text": json.dumps(summary)},
            {"type": "image", "data": base64.b64encode(data).decode("ascii"),
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
        target = record["action"].get("target") or {}
        payload = {
            "id": key,
            "state": record["state"],
            "action": control_actions.describe(record["action"]),
            "tap_target": target.get("description", ""),
            "tap_target_clickable": bool(target.get("clickable", False)),
            "reason": record["action"].get("reason", ""),
            "width": record.get("width", 0),
            "height": record.get("height", 0),
            "orientation": record.get("orientation", ""),
            "detail": record.get("detail", ""),
        }
        if record["action"].get("type") == "swipe":
            start_target = record["action"].get("start_target") or {}
            payload.update(
                {
                    "direction": record["action"].get("direction", ""),
                    "app": record["action"].get("app", ""),
                    "app_package": record["action"].get("app_package", ""),
                    "purpose": record["action"].get("purpose", ""),
                    "distance": record["action"].get("distance", 0),
                    "start_target": start_target.get("description", ""),
                    "message": control_actions.swipe_headline(
                        record["action"]
                    ),
                }
            )
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
            self._handle_mcp_gated(body)
            return
        if path not in (
            "/pair", "/connect", "/disconnect", "/window",
            "/control", "/control/session", "/control/approve",
            "/control/reject", "/control/stop", "/control/reconnect",
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
        if path in ("/pair", "/connect", "/disconnect", "/window") or path.startswith("/control/"):
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
            elif path == "/control/reject":
                self._do_reject(fields)
            elif path == "/pair":
                self._do_pair(fields)
            elif path == "/connect":
                self._do_connect(fields)
            elif path == "/control/reconnect":
                self._do_connect_saved()
            elif path == "/disconnect":
                self._do_disconnect()
            else:
                self._do_window(fields)
            return

        self.close_connection = True
        self._send_json(405, {"error": "method_not_allowed"}, {"Allow": "GET, POST"})

    def _do_window(self, fields):
        """Start or stop the viewing session. No fixed duration."""
        action = (fields.get("action") or "").strip().lower()
        minutes = (fields.get("minutes") or "").strip()
        stop = action == "stop" or minutes == "0"
        self.server.viewing_active = not stop
        self.server.viewing_expires = (
            0.0 if stop else time.monotonic() + UI_SESSION_TTL_SECONDS
        )
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
                self.server.viewing_expires = (
                    time.monotonic() + UI_SESSION_TTL_SECONDS if view == "on" else 0.0
                )
            if ctl in ("on", "off"):
                self.server.control_active = ctl == "on"
                if ctl == "on":
                    self.server.control_expires = (
                        time.monotonic() + self._control_session_seconds()
                    )
                else:
                    self.server.control_expires = 0.0
                    self.server.approvals.clear()
                    self.server.safety_epoch = (
                        getattr(self.server, "safety_epoch", 0) + 1
                    )
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

    def _log_handler_error(self, exc):
        """Type, file and line only. Never request data, cookies or paths."""
        traceback = exc.__traceback__
        while traceback is not None and traceback.tb_next is not None:
            traceback = traceback.tb_next
        if traceback is None:
            sys.stderr.write(
                "android-bridge: handler error: %s\n" % type(exc).__name__
            )
            return
        frame = traceback.tb_frame
        sys.stderr.write(
            "android-bridge: handler error: %s at %s:%d\n"
            % (
                type(exc).__name__,
                os.path.basename(frame.f_code.co_filename),
                traceback.tb_lineno,
            )
        )

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
            self.server.control_expires = 0.0
            self.server.viewing_active = False
            self.server.viewing_expires = 0.0
            self.server.approvals.clear()
            self.server.safety_epoch = (
                getattr(self.server, "safety_epoch", 0) + 1
            )
        self._respond({"control": False, "pending": 0}, flash="stopped")

    def _end_sessions(self):
        with self.server.control_lock:
            self.server.viewing_active = False
            self.server.viewing_expires = 0.0
            self.server.control_active = False
            self.server.control_expires = 0.0
            self.server.approvals.clear()
            self.server.safety_epoch = (
                getattr(self.server, "safety_epoch", 0) + 1
            )

    def _do_approve(self, fields):
        key = (fields.get("id") or "").strip()
        with self.server.control_lock:
            if not self._control_open_locked():
                self._respond({"error": "control_inactive"}, 409, flash="error")
                return
            record = self.server.approvals.get(key)
            if record is None or record["state"] != "pending":
                self._respond(
                    {"error": "approval is not pending"}, 409, flash="error"
                )
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
            if record.get("safety_epoch", 0) != getattr(
                self.server, "safety_epoch", 0
            ):
                self.server.approvals.fail(key, "cancelled")
                self._respond({"error": "approval cancelled"}, 409, flash="error")
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

            if record["action"].get("type") in ("tap", "swipe"):
                info = load_device(self.server.data_dir)
                saved_serial = (info.get("serial") or "").strip()
                try:
                    hardware_serial = adbctl.get_hardware_serial(
                        device["serial"]
                    )
                except adbctl.AdbError:
                    self.server.approvals.fail(key, "identity_mismatch")
                    self._respond(
                        {"error": "identity_mismatch"}, 409, flash="error"
                    )
                    return
                if (
                    not adbctl.is_hardware_serial(hardware_serial)
                    or hardware_serial != record.get("hardware_serial")
                    or (
                        adbctl.is_hardware_serial(saved_serial)
                        and saved_serial != hardware_serial
                    )
                ):
                    self.server.approvals.fail(key, "identity_mismatch")
                    self._respond(
                        {"error": "identity_mismatch"}, 409, flash="error"
                    )
                    return

                try:
                    fresh = adbctl.screencap(device["serial"], timeout=20.0)
                    pngcheck.validate(fresh, max_bytes=MAX_CAPTURE_BYTES)
                except (adbctl.AdbError, pngcheck.PngError):
                    self.server.approvals.fail(key, "screen_changed")
                    self._respond(
                        {"error": "screen_changed"}, 409,
                        flash="screen_changed",
                    )
                    return
                try:
                    before = pngcheck.decode(
                        record["preshot"], max_bytes=MAX_CAPTURE_BYTES
                    )
                    after = pngcheck.decode(
                        fresh, max_bytes=MAX_CAPTURE_BYTES
                    )
                except pngcheck.PngError:
                    self.server.approvals.fail(key, "screen_changed")
                    self._respond(
                        {"error": "screen_changed"}, 409,
                        flash="screen_changed",
                    )
                    return
                original_orientation = pngcheck.orientation(
                    before.width, before.height
                )
                current_orientation = pngcheck.orientation(
                    after.width, after.height
                )
                if record["action"].get("type") == "swipe":
                    x = int(record["action"].get("x1", -1))
                    y = int(record["action"].get("y1", -1))
                else:
                    x = int(record["action"].get("x", -1))
                    y = int(record["action"].get("y", -1))
                if (
                    before.width != after.width
                    or before.height != after.height
                    or original_orientation != current_orientation
                    or pngcheck.region_changed(before, after, x, y)
                ):
                    self.server.approvals.fail(key, "screen_changed")
                    self._respond(
                        {"error": "screen_changed"}, 409,
                        flash="screen_changed",
                    )
                    return

                # Re-inspect the target immediately before input. An
                # unreadable dump fails closed; a vanished, changed or newly
                # covering clickable element refuses execution. Nothing is
                # retried and no alternative location is ever tapped.
                if record["action"].get("type") == "swipe":
                    proposed_target = record["action"].get("start_target") or {}
                else:
                    proposed_target = record["action"].get("target") or {}
                try:
                    xml = adbctl.ui_dump(device["serial"])
                except adbctl.AdbError:
                    self.server.approvals.fail(key, "target_unverified")
                    self._respond(
                        {"error": "target_unverified"}, 409,
                        flash="error",
                    )
                    return
                current_target = control_actions.describe_target(xml, x, y)
                if (
                    current_target.get("description")
                    == control_actions.UNKNOWN_TARGET
                ):
                    self.server.approvals.fail(key, "target_unverified")
                    self._respond(
                        {"error": "target_unverified"}, 409,
                        flash="error",
                    )
                    return
                if not control_actions.targets_match(
                    proposed_target, current_target
                ):
                    self.server.approvals.fail(key, "target_changed")
                    self._respond(
                        {"error": "target_changed"}, 409,
                        flash="error",
                    )
                    return

            try:
                record = self.server.approvals.approve(key)
            except control_actions.ActionError as exc:
                self._respond({"error": str(exc)}, 409, flash="error")
                return

            # Last check immediately before any ADB input. STOP and Control
            # expiry cannot interleave while this lock is held.
            if (
                not self._control_open_locked()
                or record.get("safety_epoch", 0)
                != getattr(self.server, "safety_epoch", 0)
            ):
                self.server.approvals.fail(key, "cancelled")
                self._respond(
                    {"error": "control_inactive"}, 409, flash="error"
                )
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
                {"status": "executed", "screenshot": "unavailable"},
                flash="executed",
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

    def _crosshair_html(self, x, y, width, height):
        if width <= 0 or height <= 0:
            return ""
        left = x * 100.0 / width
        top = y * 100.0 / height
        common = (
            "position:absolute;left:%.4f%%;top:%.4f%%;"
            "transform:translate(-50%%,-50%%);background:#ffd400;"
            "box-shadow:0 0 0 2px #111;pointer-events:none"
        ) % (left, top)
        return (
            "<span class='tap-crosshair' style='%s;width:32px;height:2px'></span>"
            "<span class='tap-crosshair' style='%s;width:2px;height:32px'></span>"
            % (common, common)
        )

    def _tap_overlay_html(self, x, y, width, height):
        """Large red circle plus the crosshair, positioned from real pixels."""
        if width <= 0 or height <= 0:
            return ""
        common = (
            "position:absolute;left:%.4f%%;top:%.4f%%;"
            "transform:translate(-50%%,-50%%);pointer-events:none"
        ) % (x * 100.0 / width, y * 100.0 / height)
        circle = (
            "<span class='tap-circle' style='%s;width:72px;height:72px;"
            "border:4px solid #ff0000;border-radius:50%%;"
            "box-sizing:border-box;background:rgba(255,0,0,0.12)'></span>"
            % common
        )
        return circle + self._crosshair_html(x, y, width, height)

    def _result_label(self, record):
        state = record["state"]
        detail = record.get("detail", "")
        if state == "executed":
            if record.get("postshot"):
                return "Executed"
            return "Executed — post-action screenshot unavailable"
        if state == "rejected":
            return "Rejected"
        if state == "expired":
            return "Expired"
        if state == "cancelled":
            return "Cancelled"
        if state == "failed":
            if detail == "screen_changed":
                return "Failed — Screen changed — ask again."
            if detail == "identity_mismatch":
                return "Failed — Device identity changed."
            if detail == "target_changed":
                return "Failed — Target changed — ask again."
            if detail == "target_unverified":
                return "Failed — Could not verify the target."
            return "Failed"
        return state.replace("_", " ").title()

    def _result_cards(self):
        results = self.server.approvals.recent(5)
        cards = []
        for record in results:
            action = record["action"]
            reason = html.escape(str(action.get("reason", "")), quote=True)
            label = html.escape(self._result_label(record), quote=True)
            description = html.escape(
                control_actions.describe(action), quote=True
            )
            device = html.escape(str(record["device"]), quote=True)
            detail = html.escape(str(record.get("detail", "")), quote=True)
            image = ""
            if record.get("postshot"):
                encoded = base64.b64encode(record["postshot"]).decode("ascii")
                image = (
                    "<img src='data:image/png;base64,%s' "
                    "style='display:block;max-width:100%%;height:auto;"
                    "margin-top:.5rem'>" % encoded
                )
            detail_html = (
                "<p><b>Detail:</b> %s</p>" % detail if detail else ""
            )
            purpose_html = ""
            if action.get("purpose"):
                purpose_html = (
                    "<p><b>Action:</b> %s</p>"
                    % html.escape(str(action["purpose"]), quote=True)
                )
            cards.append(
                "<div style='border:1px solid #444;padding:.75rem;"
                "margin:.75rem 0'>"
                "<h3>%s — %s</h3>"
                "<p>Device: %s &middot; id %s</p>"
                "<p><b>AI reason:</b> %s</p>%s%s%s</div>"
                % (
                    label,
                    description,
                    device,
                    html.escape(record["id"], quote=True),
                    reason,
                    purpose_html,
                    detail_html,
                    image,
                )
            )
        return "".join(cards) or "<p>None.</p>"

    def _swipe_overlay_html(self, action, width, height, key):
        """Green start circle, red end circle and an arrow between them.

        Drawn in the screenshot's own pixel space so the marks stay on the
        gesture at any card width.
        """
        if width <= 0 or height <= 0:
            return ""
        try:
            x1 = int(action.get("x1", 0))
            y1 = int(action.get("y1", 0))
            x2 = int(action.get("x2", 0))
            y2 = int(action.get("y2", 0))
        except (TypeError, ValueError):
            return ""
        token = re.sub(r"[^A-Za-z0-9_-]", "", str(key)) or "x"
        marker = "swipe-arrow-%s" % token
        return (
            "<svg class='swipe-overlay' viewBox='0 0 %d %d' "
            "style='position:absolute;left:0;top:0;width:100%%;height:100%%;"
            "pointer-events:none'>"
            "<defs><marker id='%s' markerWidth='6' markerHeight='6' "
            "refX='3' refY='3' orient='auto'>"
            "<path d='M0,0 L6,3 L0,6 z' fill='#ff0000'/></marker></defs>"
            "<line x1='%d' y1='%d' x2='%d' y2='%d' stroke='#ff0000' "
            "stroke-width='6' marker-end='url(#%s)'/>"
            "<circle class='swipe-start' cx='%d' cy='%d' r='26' fill='none' "
            "stroke='#00c000' stroke-width='6'/>"
            "<circle class='swipe-end' cx='%d' cy='%d' r='26' fill='none' "
            "stroke='#ff0000' stroke-width='6'/>"
            "</svg>"
            % (
                width, height,
                marker,
                x1, y1, x2, y2, marker,
                x1, y1,
                x2, y2,
            )
        )

    def _swipe_card_html(self, record, image, remaining, csrf_attr):
        """Approval card for a swipe, in the documented order.

        Headline sentence, start, end, purpose, the screenshot with the green
        start circle, red end circle and arrow, the AI reason, then the two
        decision buttons. Every free-text field is HTML-escaped.
        """
        action = record["action"]
        width = int(record.get("width", 0))
        height = int(record.get("height", 0))
        try:
            x1 = int(action.get("x1", 0))
            y1 = int(action.get("y1", 0))
            x2 = int(action.get("x2", 0))
            y2 = int(action.get("y2", 0))
        except (TypeError, ValueError):
            x1 = y1 = x2 = y2 = 0
        direction = html.escape(
            str(action.get("direction") or "swipe"), quote=True
        )
        app = html.escape(
            str(action.get("app") or "the current app"), quote=True
        )
        purpose = html.escape(
            str(action.get("purpose", "")), quote=True
        )
        reason = html.escape(str(action.get("reason", "")), quote=True)
        device = html.escape(str(record["device"]), quote=True)
        record_id = html.escape(record["id"], quote=True)
        line_style = "font-size:1.25rem;font-weight:600;margin:0 0 .35rem"
        return (
            "<div style='border:1px solid #555;padding:1rem;"
            "margin:1rem 0'>"
            "<p style='font-size:1.7rem;font-weight:700;line-height:1.3;"
            "margin:0 0 .75rem'>DeepSeek wants to %s in %s.</p>"
            "<p style='%s'><b>Start:</b> (%d, %d)</p>"
            "<p style='%s'><b>End:</b> (%d, %d)</p>"
            "<p style='%s'><b>Action:</b> %s</p>"
            "<div style='position:relative;display:block;width:100%%;"
            "max-width:100%%;line-height:0'>"
            "<img src='data:image/png;base64,%s' "
            "style='display:block;width:100%%;max-width:100%%;height:auto'>"
            "%s</div>"
            "<p><b>AI reason:</b> %s</p>"
            "<form method='post' action='control/approve' "
            "style='display:inline'>"
            "<input type='hidden' name='csrf' value='%s'>"
            "<input type='hidden' name='id' value='%s'>"
            "<button>Approve</button></form> "
            "<form method='post' action='control/reject' "
            "style='display:inline'>"
            "<input type='hidden' name='csrf' value='%s'>"
            "<input type='hidden' name='id' value='%s'>"
            "<button>Reject</button></form>"
            "<p style='margin-top:.5rem;color:#aaa'>%d &times; %d &middot; "
            "%s &middot; id %s &middot; expires in %s</p></div>"
            % (
                direction, app,
                line_style, x1, y1,
                line_style, x2, y2,
                line_style, purpose,
                image,
                self._swipe_overlay_html(action, width, height, record["id"]),
                reason,
                csrf_attr, record_id,
                csrf_attr, record_id,
                width, height, device, record_id, remaining,
            )
        )

    def _control_page(self, nonce, flash=""):
        session = self.server.ui_sessions.get(nonce) or {}
        csrf = session.get("csrf", "")
        csrf_attr = html.escape(csrf, quote=True)
        message = _FLASH_MESSAGES.get(flash, "")
        flash_html = (
            "<p style='padding:.5rem;background:#223;color:#cfe'>%s</p>"
            % html.escape(message)
            if message
            else ""
        )
        now = time.monotonic()
        control_open = self._control_open()
        pending = self.server.approvals.pending()
        auto_refresh = control_open or bool(pending)
        refresh_html = (
            "<meta http-equiv='refresh' content='5'>" if auto_refresh else ""
        )
        cards = []
        for record in pending:
            image = base64.b64encode(record["preshot"]).decode("ascii")
            action = record["action"]
            reason = html.escape(str(action.get("reason", "")), quote=True)
            device = html.escape(str(record["device"]), quote=True)
            description = html.escape(
                control_actions.describe(action), quote=True
            )
            width = int(record.get("width", 0))
            height = int(record.get("height", 0))
            orientation = html.escape(
                str(record.get("orientation", "")), quote=True
            )
            remaining = control_actions.format_remaining(record["expires"] - now)
            tap_line = ""
            overlay = ""
            if action.get("type") == "swipe":
                cards.append(
                    self._swipe_card_html(record, image, remaining, csrf_attr)
                )
                continue
            if action.get("type") == "tap":
                x = int(action.get("x", 0))
                y = int(action.get("y", 0))
                target = action.get("target") or {}
                target_text = html.escape(
                    str(target.get("description") or control_actions.UNKNOWN_TARGET),
                    quote=True,
                )
                headline = (
                    "<p style='font-size:1.7rem;font-weight:700;"
                    "line-height:1.3;margin:0 0 .75rem'>"
                    "This will tap: %s</p>" % target_text
                )
                if target.get("clickable"):
                    warning = "Warning: this will press a button"
                else:
                    warning = (
                        "Warning: no clickable element detected — this area "
                        "may still contain interactive controls."
                    )
                headline += (
                    "<p style='font-size:1.2rem;font-weight:700;"
                    "color:#ff2020;margin:0 0 .75rem'>%s</p>" % warning
                )
                tap_line = (
                    "<p><b>Proposed action:</b> TAP &middot; "
                    "X=%d, Y=%d</p>" % (x, y)
                )
                overlay = self._tap_overlay_html(x, y, width, height)
            else:
                headline = "<h3>%s</h3>" % description
            cards.append(
                "<div style='border:1px solid #555;padding:1rem;"
                "margin:1rem 0'>"
                "%s"
                "<div style='position:relative;display:block;width:100%%;"
                "max-width:100%%;line-height:0'>"
                "<img src='data:image/png;base64,%s' "
                "style='display:block;width:100%%;max-width:100%%;height:auto'>"
                "%s</div>"
                "<p><b>AI reason:</b> %s</p>"
                "%s"
                "<p><b>Screen:</b> %d × %d — %s</p>"
                "<p>Device: %s &middot; id %s &middot; expires in %s</p>"
                "<form method='post' action='control/approve' "
                "style='display:inline'>"
                "<input type='hidden' name='csrf' value='%s'>"
                "<input type='hidden' name='id' value='%s'>"
                "<button>Approve</button></form> "
                "<form method='post' action='control/reject' "
                "style='display:inline'>"
                "<input type='hidden' name='csrf' value='%s'>"
                "<input type='hidden' name='id' value='%s'>"
                "<button>Reject</button></form>"
                "</div>"
                % (
                    headline,
                    image,
                    overlay,
                    reason,
                    tap_line,
                    width,
                    height,
                    orientation,
                    device,
                    html.escape(record["id"], quote=True),
                    remaining,
                    csrf_attr,
                    html.escape(record["id"], quote=True),
                    csrf_attr,
                    html.escape(record["id"], quote=True),
                )
            )
        viewing_open = self._viewing_open()
        viewing = "ON" if viewing_open else "off"
        control = "ON" if control_open else "off"
        if control_open:
            expires = float(getattr(self.server, "control_expires", 0.0))
            if expires > 0:
                left = max(0, int(expires - now))
                control = "ON (%dm %02ds)" % (left // 60, left % 60)
        saved = load_device(self.server.data_dir)
        if saved:
            saved_form = (
                "<form method='post' action='control/reconnect' style='margin-top:.5rem'>"
                "<input type='hidden' name='csrf' value='%s'>"
                "<button>Connect saved tablet (%s:%s)</button></form>"
                % (
                    csrf_attr,
                    html.escape(saved["host"], quote=True),
                    html.escape(saved["connect_port"], quote=True),
                )
            )
        else:
            saved_form = "<p>No saved tablet.</p>"
        body = (
            "<html><head><meta charset='utf-8'>"
            "<title>Android Bridge control</title>%s</head>"
            "<body style='font-family:system-ui;max-width:60rem;margin:2rem auto'>"
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
            "</form>"
            "<p style='color:#f88'>STOP cannot undo a tap that has already been sent.</p>"
            "<h2>Device</h2>"
            "<form method='post' action='pair'>"
            "<input type='hidden' name='csrf' value='%s'>"
            "<p>IP <input name='host' size='16'> "
            "Pairing port <input name='pairing_port' size='6'> "
            "Code <input name='code' size='6' autocomplete='off'> "
            "Connect port <input name='connect_port' size='6'></p>"
            "<button>Pair and connect</button></form>"
            "%s"
            "<form method='post' action='disconnect' style='margin-top:.5rem'>"
            "<input type='hidden' name='csrf' value='%s'>"
            "<button>Disconnect</button></form>"
            "<h2>Pending approvals</h2>%s"
            "<h2>Recent results</h2>%s</body></html>"
            % (
                refresh_html,
                flash_html,
                viewing,
                control,
                csrf_attr,
                "off" if viewing_open else "on",
                "ON" if viewing_open else "start",
                "off" if control_open else "on",
                "ON" if control_open else "start",
                csrf_attr,
                csrf_attr,
                saved_form,
                csrf_attr,
                "".join(cards) or "<p>None.</p>",
                self._result_cards(),
            )
        )
        return body.encode("utf-8")

    def _do_pair(self, fields):
        host = (fields.get("host") or "").strip()
        pairing_port = (fields.get("pairing_port") or "").strip()
        code = (fields.get("code") or "").strip()
        connect_port = (fields.get("connect_port") or "").strip()
        try:
            adbctl.validate_target(host, pairing_port, connect_port, code)
        except adbctl.AdbError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        if self._adb_key_state() == "unreadable":
            sys.stderr.write("pairing_failed reason=key_unreadable\n")
            self._respond({"error": "pairing_failed"}, 400, flash="pair_failed")
            return
        try:
            adbctl.pair(host, pairing_port, code)
            adbctl.connect(host, connect_port)
        except adbctl.AdbError as exc:
            sys.stderr.write(
                "pairing_failed reason=%s\n" % (exc.reason or "unknown")
            )
            self._respond({"error": "pairing_failed"}, 400, flash="pair_failed")
            return
        device = self._resolve_target(host)
        identity = capture_identity(device) if device is not None else None
        try:
            save_device(self.server.data_dir, host, connect_port, identity)
        except OSError:
            self._send_json(500, {"error": "state_write_failed"})
            return
        self._respond({"status": "paired"}, flash="paired")

    def _do_connect(self, fields):
        host = (fields.get("host") or "").strip()
        port = (fields.get("connect_port") or "").strip()
        try:
            adbctl.validate_target(host, port)
            adbctl.connect(host, port)
        except adbctl.AdbError as exc:
            sys.stderr.write(
                "connect_failed reason=%s\n" % (exc.reason or "unknown")
            )
            self._respond({"error": "connect_failed"}, 400, flash="pair_failed")
            return
        device = self._resolve_target(host)
        identity = capture_identity(device) if device is not None else None
        try:
            save_device(self.server.data_dir, host, port, identity)
        except OSError:
            self._send_json(500, {"error": "state_write_failed"})
            return
        self._send_json(200, {"status": "connected"})

    def _do_connect_saved(self):
        """Reconnect to the saved tablet without pairing, then verify it."""
        info = load_device(self.server.data_dir)
        if not info:
            self._respond(
                {"error": "device_not_paired"}, 409, flash="reconnect_failed"
            )
            return
        host = info["host"]
        port = info["connect_port"]
        try:
            adbctl.validate_target(host, port)
            adbctl.connect(host, port)
        except adbctl.AdbError as exc:
            sys.stderr.write(
                "saved_connect_failed reason=%s\n" % (exc.reason or "unknown")
            )
            self._respond({"error": "connect_failed"}, 400, flash="reconnect_failed")
            return
        device = self._resolve_target(host)
        identity = (
            capture_identity(device, strict=True) if device is not None else None
        )
        saved_serial = (info.get("serial") or "").strip()
        saved_verified = adbctl.is_hardware_serial(saved_serial)
        saved_model = info.get("model")
        error = None
        if identity is None:
            error = "identity_unverified"
        elif saved_verified:
            if identity["serial"] != saved_serial:
                error = "identity_conflict"
            elif saved_model and not same_model(identity["model"], saved_model):
                error = "identity_conflict"
        else:
            # Legacy record: no serial, or an old transport-address serial.
            if saved_model and not same_model(identity["model"], saved_model):
                error = "identity_conflict"
            elif not same_model(
                identity["model"], reconnect_module.LEGACY_UNVERIFIED_MODEL
            ):
                error = "identity_unverified"
        if error is not None:
            # Other paths match the saved target by host, so an unverified
            # tablet must not stay connected.
            if device is not None:
                try:
                    adbctl.disconnect(device["serial"])
                except adbctl.AdbError:
                    pass
            sys.stderr.write("saved_connect_failed reason=%s\n" % error)
            self._respond({"error": error}, 409, flash="reconnect_failed")
            return
        if not saved_verified:
            # A human-initiated panel reconnect may enrol a legacy record, but
            # never overwrite an already verified hardware identity.
            try:
                save_device(self.server.data_dir, host, port, identity)
            except OSError:
                self._send_json(500, {"error": "state_write_failed"})
                return
        self._respond({"status": "connected"}, flash="reconnected")

    def _do_disconnect(self):
        self._end_sessions()
        try:
            for device in adbctl.list_devices():
                adbctl.disconnect(device["serial"])
        except adbctl.AdbError:
            self._respond({"error": "disconnect_failed"}, 502, flash="error")
            return
        self._respond({"status": "disconnected"}, flash="disconnected")

    def _reject_method(self):
        self.close_connection = True
        self._send_json(405, {"error": "method_not_allowed"}, {"Allow": "GET, POST"})

    def do_PUT(self):
        self._reject_method()

    def do_PATCH(self):
        self._reject_method()

    def do_DELETE(self):
        self._reject_method()


# Every tool implementation present in this build. Exposure is a separate,
# server-side decision and never widens this set.
KNOWN_MCP_TOOLS = frozenset(tool["name"] for tool in Handler.MCP_TOOLS)


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
    server.viewing_expires = 0.0
    server.control_active = False
    server.control_expires = 0.0
    server.safety_epoch = 0
    server.proposal_lock = threading.Lock()
    server.last_proposal_at = 0.0
    server.ui_sessions = {}
    server.login_nonces = {}
    server.allowed_users = load_allowed_users(data_dir)
    server.exposed_tools = load_exposed_tools(data_dir)
    server.control_minutes = load_control_minutes(data_dir)
    server.control_lock = threading.RLock()
    server.first_tap_test = FIRST_TAP_TEST_MODE
    server.approvals = control_actions.Approvals()
    server.reconnector = reconnect_module.Reconnector()
    server.started_monotonic = time.monotonic()
    return server


def _log_adb_key_state(data_dir):
    path = os.path.join(data_dir, ".android", "adbkey")
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        sys.stderr.write("adb key missing\n")
        return
    except OSError:
        sys.stderr.write("adb key unreadable\n")
        return
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        sys.stderr.write("adb key unreadable\n")
        return
    try:
        with open(path, "rb") as handle:
            handle.read(1)
    except OSError:
        sys.stderr.write("adb key unreadable\n")
        return
    sys.stderr.write("adb key ok\n")


def _log_adb_version():
    version = adbctl.version()
    if version:
        sys.stderr.write("adb available version=%s\n" % version)
    else:
        sys.stderr.write("adb missing\n")


def startup_reconnect(server):
    """Reconnect to the saved tablet, if any.

    Returns True only when the saved identity is verified. Failures are logged
    by the reconnector; the scheduler keeps any unexpected error away from boot.
    """
    info = load_device(server.data_dir)
    if not info:
        return False
    return server.reconnector.startup(info)


def _schedule_startup_reconnect(server):
    def worker():
        try:
            startup_reconnect(server)
        except Exception:
            # A failed reconnect must never stop the bridge starting.
            sys.stderr.write("adb reconnect failed reason=unknown\n")

    threading.Thread(target=worker, name="adb-reconnect", daemon=True).start()


def main() -> int:
    if os.geteuid() == 0:
        sys.stderr.write("android-bridge: fatal: refusing to run as root\n")
        return 1
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

    _log_adb_version()
    sys.stderr.write("adb home=%s\n" % adbctl.ADB_HOME)
    _log_adb_key_state(DEFAULT_DATA_DIR)
    sys.stderr.write(
        "android-bridge %s listening on %d (HA-user panel, MCP source+viewing gate)\n"
        % (VERSION, PORT)
    )
    _schedule_startup_reconnect(server)
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
