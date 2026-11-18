"""Android Bridge - stage 1: authenticated control surface only.

No ADB. No device access. No screenshot capture.
The screenshot endpoint is a disabled placeholder.
"""

from __future__ import annotations

import errno
import hmac
import http.client
import json
import os
import re
import secrets
import stat
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.2.1"
PORT = 8791
DEFAULT_DATA_DIR = "/data"

MAX_BODY_BYTES = 8 * 1024
MAX_URI_LENGTH = 2048
MAX_TOKEN_FILE_BYTES = 512
AUTH_FAIL_DELAY_SECONDS = 0.2
SOCKET_TIMEOUT_SECONDS = 10
MAX_CONNECTIONS = 16
SELFTEST_DELAY_SECONDS = 0.5
SELFTEST_TIMEOUT_SECONDS = 5.0
SELFTEST_MAX_ATTEMPTS = 3
SELFTEST_PATH = "/status"

_TOKEN_RE = re.compile(r"\A[A-Za-z0-9_-]{32,128}\Z")
_LOGGABLE_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_DUMMY_TOKEN = b"x" * 43


class TokenError(RuntimeError):
    """The private token store is missing, unsafe or malformed."""


def private_dir(data_dir: str = DEFAULT_DATA_DIR) -> str:
    return os.path.join(data_dir, "private")


def token_path(data_dir: str = DEFAULT_DATA_DIR) -> str:
    return os.path.join(private_dir(data_dir), "token")


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
    """Atomically create the token; returns None if another writer won."""
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

    try:
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass

    return token


def load_or_create_token(data_dir: str = DEFAULT_DATA_DIR) -> bytes:
    _ensure_private_dir(data_dir)
    path = token_path(data_dir)

    if os.path.lexists(path):
        return _read_token_file(path)

    created = _create_token_file(path)
    if created is not None:
        return created
    return _read_token_file(path)


class Handler(BaseHTTPRequestHandler):
    server_version = "AndroidBridge/" + VERSION
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = SOCKET_TIMEOUT_SECONDS

    _ROUTE_LABELS = {
        "/health": "health",
        "/status": "status",
        "/screenshot": "screenshot",
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

    def _presented_token(self):
        values = self.headers.get_all("Authorization") or []
        if len(values) != 1:
            return None
        parts = values[0].split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        candidate = parts[1]
        if not _TOKEN_RE.match(candidate):
            return None
        return candidate.encode("ascii")

    def _authorized(self) -> bool:
        candidate = self._presented_token()
        if candidate is None:
            hmac.compare_digest(_DUMMY_TOKEN, self.server.token)
            return False
        return hmac.compare_digest(candidate, self.server.token)

    def _require_auth(self) -> bool:
        if self._authorized():
            return True
        time.sleep(AUTH_FAIL_DELAY_SECONDS)
        self._send_json(
            401,
            {"error": "unauthorized"},
            {"WWW-Authenticate": 'Bearer realm="android-bridge"'},
        )
        return False

    def do_GET(self):
        if len(self.path) > MAX_URI_LENGTH:
            self.close_connection = True
            self._send_json(414, {"error": "uri_too_long"})
            return
        try:
            self._route_get()
        except Exception as exc:
            sys.stderr.write(
                "android-bridge: handler error: %s\n" % type(exc).__name__
            )
            try:
                self._send_json(500, {"error": "internal_error"})
            except Exception:
                self.close_connection = True

    def _route_get(self):
        path = self._path_only()

        if path == "/health":
            self._send_json(200, {"status": "ok"})
            return

        if path == "/status":
            if not self._require_auth():
                return
            self._send_json(
                200,
                {
                    "status": "ok",
                    "version": VERSION,
                    "stage": "auth-only",
                    "paired": False,
                    "connected": False,
                    "screenshot_enabled": False,
                    "uptime_seconds": int(
                        time.monotonic() - self.server.started_monotonic
                    ),
                },
            )
            return

        if path == "/screenshot":
            if not self._require_auth():
                return
            self._send_json(
                503,
                {"error": "screenshot_unavailable", "reason": "not_implemented"},
            )
            return

        self._send_json(404, {"error": "not_found"})

    def _reject_method(self):
        length = self._content_length()
        self.close_connection = True
        if length < 0:
            self._send_json(400, {"error": "bad_content_length"})
            return
        if length > MAX_BODY_BYTES:
            self._send_json(
                413, {"error": "payload_too_large"}, {"Connection": "close"}
            )
            return
        self._send_json(405, {"error": "method_not_allowed"}, {"Allow": "GET"})

    def do_POST(self):
        self._reject_method()

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


def run_auth_selftest(
    port: int,
    token: bytes,
    host: str = "127.0.0.1",
    timeout: float = SELFTEST_TIMEOUT_SECONDS,
):
    """Exercise normal bearer authentication over loopback without logging token."""
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
        connection.close()


def _schedule_auth_selftest(server, port: int) -> None:
    """Run a single startup check, retrying only connection failures."""
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
            sys.stderr.write("auth_selftest=PASS http=200\n")
        else:
            sys.stderr.write("auth_selftest=FAIL\n")

    threading.Thread(target=worker, name="auth-selftest", daemon=True).start()


def create_server(
    host: str = "0.0.0.0",
    port: int = PORT,
    data_dir: str = DEFAULT_DATA_DIR,
) -> BridgeServer:
    token = load_or_create_token(data_dir)
    server = BridgeServer((host, port), Handler)
    server.token = token
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
