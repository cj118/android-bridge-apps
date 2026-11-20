"""Narrow ADB wrapper for the Android Bridge.

Only the operations below exist. There is no shell passthrough, no arbitrary
command runner and no caller-supplied argument. Every value is validated
against a fixed pattern before it reaches the adb binary.
"""

from __future__ import annotations

import os
import re
import subprocess
import threading

ADB_BINARY = os.environ.get("BRIDGE_ADB_BINARY", "adb")
ADB_HOME = "/data"
ADB_USER_HOME = "/data/.android"
DEFAULT_TIMEOUT = 20.0
PAIR_TIMEOUT = 30.0
IDENTITY_TIMEOUT = 5.0
SERVER_TIMEOUT = 10.0
MAX_OUTPUT_BYTES = 12 * 1024 * 1024
UI_DUMP_TIMEOUT = 12.0
UI_DUMP_CLEANUP_TIMEOUT = 5.0
UI_DUMP_MAX_BYTES = 2 * 1024 * 1024
UI_DUMP_PATH = "/sdcard/window_dump.xml"
FOREGROUND_TIMEOUT = 8.0
FOREGROUND_MAX_BYTES = 1024 * 1024
_SERVER_LOCK = threading.Lock()
_server_ready = False

_HOST_RE = re.compile(r"\A[A-Za-z0-9.-]{1,253}\Z")
_PORT_RE = re.compile(r"\A[0-9]{1,5}\Z")
_CODE_RE = re.compile(r"\A[0-9]{6}\Z")
_SERIAL_RE = re.compile(r"\A[^\s]{1,128}\Z")
_TRANSPORT_RE = re.compile(r"\A[A-Za-z0-9.-]{1,253}:[0-9]{1,5}\Z")
_HARDWARE_SERIAL_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_PACKAGE_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+\Z")
_FOREGROUND_RES = (
    re.compile(
        r"mCurrentFocus=Window\{[^}]*?\s"
        r"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/"
    ),
    re.compile(
        r"mFocusedApp=.*?\s"
        r"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/"
    ),
    re.compile(
        r"mResumedActivity:.*?\s"
        r"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/"
    ),
)
_SERIAL_PLACEHOLDERS = frozenset({"unknown", "null", "none", "n/a", "unavailable"})


class AdbError(RuntimeError):
    """An ADB operation failed. Messages are fixed; no device data leaks."""

    def __init__(self, message, reason=None):
        super().__init__(message)
        self.reason = reason


def classify_error(stderr: bytes) -> str:
    """Map adb stderr to a safe category. Never returns raw output."""
    text = (stderr or b"").decode("utf-8", "replace").lower()
    if "adbkey" in text and "permission denied" in text:
        return "key_unreadable"
    if any(
        marker in text
        for marker in (
            "cannot connect to daemon",
            "failed to start daemon",
            "daemon not running",
            "adb server didn't ack",
            "adb server is out of date",
            "could not install *smartsocket*",
            "failed to connect to adb server",
            "cannot start server",
        )
    ):
        return "adb_server_unavailable"
    if "protocol fault" in text:
        return "protocol_fault"
    if (
        "connection refused" in text
        or "cannot connect to" in text
        or "failed to connect" in text
        or "no route to host" in text
    ):
        return "connection_refused"
    if (
        "failed to authenticate" in text
        or "rejected" in text
        or "wrong password" in text
        or "pairing failed" in text
    ):
        return "pairing_rejected"
    return "unknown"


def _host(value: str) -> str:
    """Only private LAN IPv4 literals are accepted."""
    value = (value or "").strip()
    parts = value.split(".")
    if len(parts) != 4:
        raise AdbError("host must be a private LAN IPv4 address")
    try:
        octets = [int(part) for part in parts]
    except ValueError:
        raise AdbError("host must be a private LAN IPv4 address") from None
    if any(octet < 0 or octet > 255 for octet in octets):
        raise AdbError("host must be a private LAN IPv4 address")
    first, second = octets[0], octets[1]
    if (
        first == 10
        or (first == 172 and 16 <= second <= 31)
        or (first == 192 and second == 168)
    ):
        return value
    raise AdbError("host must be a private LAN IPv4 address")


def _port(value: str) -> str:
    value = str(value or "").strip()
    if not _PORT_RE.match(value) or not 1 <= int(value) <= 65535:
        raise AdbError("invalid port")
    return value


def _serial(value: str) -> str:
    value = (value or "").strip()
    if not _SERIAL_RE.match(value):
        raise AdbError("invalid serial")
    return value


def is_transport_address(value: str) -> bool:
    """True for an adb host:port transport identifier (never a hardware ID)."""
    value = (value or "").strip()
    if not value:
        return False
    if _TRANSPORT_RE.match(value):
        return True
    parts = value.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return all(0 <= int(part) <= 255 for part in parts)
    return False


def is_hardware_serial(value: str) -> bool:
    """True only for a plausible physical serial, never a transport address."""
    value = (value or "").strip()
    if not value or value.lower() in _SERIAL_PLACEHOLDERS:
        return False
    if is_transport_address(value):
        return False
    return bool(_HARDWARE_SERIAL_RE.match(value))


def _mark_server_down() -> None:
    global _server_ready
    _server_ready = False


def reset_server_state() -> None:
    """Forget the cached daemon state (tests and explicit re-init)."""
    global _server_ready
    with _SERVER_LOCK:
        _server_ready = False


def _adb_env():
    """One explicit environment for every adb subprocess.

    HOME and ANDROID_USER_HOME must not depend on the caller's environment:
    the app user's passwd entry or su-exec can otherwise point adb at a
    non-existent /home/app and it aborts before using the existing key store.
    """
    env = os.environ.copy()
    env["HOME"] = ADB_HOME
    env["ANDROID_USER_HOME"] = ADB_USER_HOME
    return env


def _run(args, timeout=DEFAULT_TIMEOUT, stdin_data=None, max_bytes=MAX_OUTPUT_BYTES):
    command = [ADB_BINARY] + list(args)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_adb_env(),
        )
    except OSError:
        raise AdbError("adb unavailable") from None

    try:
        out, _err = process.communicate(stdin_data, timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        raise AdbError("timeout") from None

    if len(out) > max_bytes:
        raise AdbError("output too large")
    if process.returncode != 0 and classify_error(_err) == "adb_server_unavailable":
        _mark_server_down()
    return process.returncode, out, _err


def _start_server_client(timeout: float) -> None:
    """Run and wait for the start-server client without holding a pipe open.

    stdout/stderr go to DEVNULL so a detached daemon cannot inherit the pipe
    and keep the client unreaped. The client itself is explicitly waited on.
    """
    try:
        process = subprocess.Popen(
            [ADB_BINARY, "start-server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_adb_env(),
        )
    except OSError:
        raise AdbError("adb unavailable") from None
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        raise AdbError(
            "adb server unavailable", "adb_server_unavailable"
        ) from None
    if returncode != 0:
        raise AdbError("adb server unavailable", "adb_server_unavailable")


def ensure_server(timeout: float = SERVER_TIMEOUT) -> None:
    """Start the ADB server once, serialised, before server-dependent work.

    The client runs as the same unprivileged application user with an explicit
    HOME=/data and ANDROID_USER_HOME=/data/.android. A daemon failure is a
    distinct category from a tablet connection failure.
    """
    global _server_ready
    with _SERVER_LOCK:
        if _server_ready:
            return
        try:
            _start_server_client(timeout)
        except AdbError:
            _server_ready = False
            raise
        _server_ready = True


def pair(host: str, port: str, code: str, timeout: float = PAIR_TIMEOUT) -> None:
    """Pair with a device. The code is delivered on stdin, never as argv."""
    target = "%s:%s" % (_host(host), _port(port))
    code = (code or "").strip()
    if not _CODE_RE.match(code):
        raise AdbError("invalid pairing code")
    ensure_server()
    returncode, _out, err = _run(
        ["pair", target],
        timeout=timeout,
        stdin_data=(code + "\n").encode("ascii"),
        max_bytes=65536,
    )
    if returncode != 0:
        raise AdbError("pairing failed", classify_error(err))


def connect(host: str, port: str, timeout: float = DEFAULT_TIMEOUT) -> None:
    target = "%s:%s" % (_host(host), _port(port))
    ensure_server()
    returncode, out, err = _run(["connect", target], timeout=timeout, max_bytes=65536)
    if returncode != 0 or b"connected" not in out.lower():
        raise AdbError("connect failed", classify_error(err) if returncode != 0 else "connection_refused")


def validate_target(host: str, port: str, connect_port=None, code=None) -> None:
    """Validate a pairing/connect target before touching adb."""
    _host(host)
    _port(port)
    if connect_port is not None:
        _port(connect_port)
    if code is not None and not _CODE_RE.match((code or "").strip()):
        raise AdbError("pairing code must be 6 digits")


def version(timeout: float = 5.0):
    """Return the adb version string, or None when adb is missing."""
    try:
        returncode, out, _err = _run(["version"], timeout=timeout, max_bytes=4096)
    except AdbError:
        return None
    if returncode != 0:
        return None
    for line in out.decode("utf-8", "replace").splitlines():
        lowered = line.lower()
        if "version" in lowered:
            tail = line[lowered.index("version") + len("version"):].strip()
            return tail.split()[0] if tail else None
    return None


def disconnect(serial: str, timeout: float = 10.0) -> None:
    ensure_server()
    _run(["disconnect", _serial(serial)], timeout=timeout, max_bytes=65536)


def list_devices(timeout: float = 10.0):
    """Return [{'serial': str, 'model': str}] for devices in state 'device'."""
    ensure_server()
    returncode, out, _err = _run(["devices", "-l"], timeout=timeout, max_bytes=65536)
    if returncode != 0:
        raise AdbError("device list failed")

    devices = []
    for line in out.decode("utf-8", "replace").splitlines()[1:]:
        line = line.strip()
        if not line or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 2 or parts[1] != "device":
            continue
        info = {}
        for token in parts[2:]:
            if ":" in token:
                key, value = token.split(":", 1)
                info[key] = value
        devices.append({"serial": parts[0], "model": info.get("model", "")})
    return devices


def get_hardware_serial(serial: str, timeout: float = IDENTITY_TIMEOUT) -> str:
    """Read ro.serialno. Fixed, read-only property; never the transport address."""
    ensure_server()
    returncode, out, _err = _run(
        ["-s", _serial(serial), "shell", "getprop", "ro.serialno"],
        timeout=timeout,
        max_bytes=4096,
    )
    if returncode != 0:
        raise AdbError("identity unavailable")
    value = out.decode("utf-8", "replace").strip()
    if not is_hardware_serial(value):
        raise AdbError("identity unavailable")
    return value


def get_model(serial: str, timeout: float = IDENTITY_TIMEOUT) -> str:
    """Read ro.product.model. Fixed, read-only property; no caller arguments."""
    ensure_server()
    returncode, out, _err = _run(
        ["-s", _serial(serial), "shell", "getprop", "ro.product.model"],
        timeout=timeout,
        max_bytes=4096,
    )
    if returncode != 0:
        raise AdbError("identity unavailable")
    return out.decode("utf-8", "replace").strip()[:64]


def screencap(serial: str, timeout: float = DEFAULT_TIMEOUT):
    """Fixed capture command. No arguments come from the caller."""
    ensure_server()
    returncode, out, _err = _run(
        ["-s", _serial(serial), "exec-out", "screencap", "-p"],
        timeout=timeout,
        max_bytes=MAX_OUTPUT_BYTES,
    )
    if returncode != 0:
        raise AdbError("capture failed")
    if not out:
        raise AdbError("empty capture")
    return out


def _remove_ui_dump(serial: str) -> None:
    """Best-effort removal of the fixed dump file. Never raises."""
    try:
        _run(
            ["-s", serial, "shell", "rm", "-f", UI_DUMP_PATH],
            timeout=UI_DUMP_CLEANUP_TIMEOUT,
            max_bytes=4096,
        )
    except AdbError:
        pass


def ui_dump(serial: str, timeout: float = UI_DUMP_TIMEOUT):
    """Fixed uiautomator dump. Read-only; no caller-supplied paths or options.

    The dump file is removed afterwards whether or not the read succeeded, so
    screen text does not linger on the tablet.
    """
    serial = _serial(serial)
    ensure_server()
    try:
        returncode, _out, _err = _run(
            ["-s", serial, "shell", "uiautomator", "dump", UI_DUMP_PATH],
            timeout=timeout,
            max_bytes=8192,
        )
        if returncode != 0:
            raise AdbError("ui dump failed")
        returncode, out, _err = _run(
            ["-s", serial, "exec-out", "cat", UI_DUMP_PATH],
            timeout=timeout,
            max_bytes=UI_DUMP_MAX_BYTES,
        )
        if returncode != 0 or not out:
            raise AdbError("ui dump failed")
        return out
    finally:
        _remove_ui_dump(serial)


def parse_foreground_package(output) -> str:
    """First focused-window package in dumpsys text, or "".

    Only a well-formed package id is returned; nothing else from the dump is
    kept or logged.
    """
    if isinstance(output, bytes):
        output = output.decode("utf-8", "replace")
    if not isinstance(output, str) or not output:
        return ""
    for pattern in _FOREGROUND_RES:
        match = pattern.search(output)
        if match is None:
            continue
        value = match.group(1)[:128]
        if _PACKAGE_RE.match(value):
            return value
    return ""


def foreground_package(serial: str, timeout: float = FOREGROUND_TIMEOUT) -> str:
    """Read the focused window's package. Fixed, read-only dumpsys command."""
    ensure_server()
    returncode, out, _err = _run(
        ["-s", _serial(serial), "shell", "dumpsys", "window"],
        timeout=timeout,
        max_bytes=FOREGROUND_MAX_BYTES,
    )
    if returncode != 0:
        raise AdbError("foreground unavailable")
    return parse_foreground_package(out)


def run_input(args, timeout: float = 15.0):
    """Execute a fixed input command. Only tap/swipe/text shapes are accepted."""
    args = list(args)
    if (
        len(args) < 6
        or args[2:4] != ["shell", "input"]
        or args[4] not in ("tap", "swipe", "text")
    ):
        raise AdbError("rejected input command")
    ensure_server()
    returncode, _out, _err = _run(args, timeout=timeout, max_bytes=65536)
    if returncode != 0:
        raise AdbError("input failed")
