"""Narrow ADB wrapper for the Android Bridge.

Only the operations below exist. There is no shell passthrough, no arbitrary
command runner and no caller-supplied argument. Every value is validated
against a fixed pattern before it reaches the adb binary.
"""

from __future__ import annotations

import os
import re
import subprocess

ADB_BINARY = os.environ.get("BRIDGE_ADB_BINARY", "adb")
DEFAULT_TIMEOUT = 20.0
PAIR_TIMEOUT = 30.0
IDENTITY_TIMEOUT = 5.0
MAX_OUTPUT_BYTES = 12 * 1024 * 1024

_HOST_RE = re.compile(r"\A[A-Za-z0-9.-]{1,253}\Z")
_PORT_RE = re.compile(r"\A[0-9]{1,5}\Z")
_CODE_RE = re.compile(r"\A[0-9]{6}\Z")
_SERIAL_RE = re.compile(r"\A[^\s]{1,128}\Z")


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


def _run(args, timeout=DEFAULT_TIMEOUT, stdin_data=None, max_bytes=MAX_OUTPUT_BYTES):
    command = [ADB_BINARY] + list(args)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
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
    return process.returncode, out, _err


def pair(host: str, port: str, code: str, timeout: float = PAIR_TIMEOUT) -> None:
    """Pair with a device. The code is delivered on stdin, never as argv."""
    target = "%s:%s" % (_host(host), _port(port))
    code = (code or "").strip()
    if not _CODE_RE.match(code):
        raise AdbError("invalid pairing code")
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
    _run(["disconnect", _serial(serial)], timeout=timeout, max_bytes=65536)


def list_devices(timeout: float = 10.0):
    """Return [{'serial': str, 'model': str}] for devices in state 'device'."""
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


def get_serialno(serial: str, timeout: float = IDENTITY_TIMEOUT) -> str:
    """Return the device's adb serial. Fixed command, no caller arguments."""
    returncode, out, _err = _run(
        ["-s", _serial(serial), "get-serialno"], timeout=timeout, max_bytes=4096
    )
    if returncode != 0:
        raise AdbError("identity unavailable")
    value = out.decode("utf-8", "replace").strip()
    if not _SERIAL_RE.match(value):
        raise AdbError("identity unavailable")
    return value


def get_model(serial: str, timeout: float = IDENTITY_TIMEOUT) -> str:
    """Read ro.product.model. Fixed, read-only property; no caller arguments."""
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


def run_input(args, timeout: float = 15.0):
    """Execute a fixed input command. Only tap/swipe/text shapes are accepted."""
    args = list(args)
    if (
        len(args) < 6
        or args[2:4] != ["shell", "input"]
        or args[4] not in ("tap", "swipe", "text")
    ):
        raise AdbError("rejected input command")
    returncode, _out, _err = _run(args, timeout=timeout, max_bytes=65536)
    if returncode != 0:
        raise AdbError("input failed")
