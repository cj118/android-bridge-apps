
"""Stage-1 tests: token store, authentication, limits, log hygiene.

Run from the repository root:
    python3 -m unittest discover -s android_bridge/tests -v
"""

import contextlib
import io
import os
import socket
import stat
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


class TokenStoreTests(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="bridge-token-")

    def token_file(self):
        return bridge.token_path(self.data_dir)

    def private(self):
        return bridge.private_dir(self.data_dir)

    def test_creates_private_regular_file(self):
        token = bridge.load_or_create_token(self.data_dir)
        info = os.lstat(self.token_file())
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_uid, os.geteuid())
        self.assertRegex(token.decode("ascii"), r"\A[A-Za-z0-9_-]{32,128}\Z")

    def test_is_idempotent(self):
        first = bridge.load_or_create_token(self.data_dir)
        second = bridge.load_or_create_token(self.data_dir)
        self.assertEqual(first, second)

    def test_rejects_symlink(self):
        os.makedirs(self.private(), mode=0o700, exist_ok=True)
        target = os.path.join(self.data_dir, "elsewhere")
        with open(target, "wb") as handle:
            handle.write(b"A" * 43)
        os.chmod(target, 0o600)
        os.symlink(target, self.token_file())
        with self.assertRaises(bridge.TokenError):
            bridge.load_or_create_token(self.data_dir)

    def test_rejects_loose_permissions(self):
        bridge.load_or_create_token(self.data_dir)
        os.chmod(self.token_file(), 0o644)
        with self.assertRaises(bridge.TokenError):
            bridge.load_or_create_token(self.data_dir)

    def test_rejects_truncated_token(self):
        os.makedirs(self.private(), mode=0o700, exist_ok=True)
        with open(self.token_file(), "wb") as handle:
            handle.write(b"short")
        os.chmod(self.token_file(), 0o600)
        with self.assertRaises(bridge.TokenError):
            bridge.load_or_create_token(self.data_dir)

    def test_rejects_empty_file(self):
        os.makedirs(self.private(), mode=0o700, exist_ok=True)
        open(self.token_file(), "wb").close()
        os.chmod(self.token_file(), 0o600)
        with self.assertRaises(bridge.TokenError):
            bridge.load_or_create_token(self.data_dir)

    def test_rejects_non_ascii(self):
        os.makedirs(self.private(), mode=0o700, exist_ok=True)
        with open(self.token_file(), "wb") as handle:
            handle.write(b"\xff" * 43)
        os.chmod(self.token_file(), 0o600)
        with self.assertRaises(bridge.TokenError):
            bridge.load_or_create_token(self.data_dir)

    def test_rejects_directory_at_token_path(self):
        root = self.private()
        os.makedirs(root, mode=0o700, exist_ok=True)
        os.chmod(root, 0o700)
        os.mkdir(self.token_file(), 0o700)
        with self.assertRaises(bridge.TokenError):
            bridge.load_or_create_token(self.data_dir)

    @unittest.skipUnless(os.geteuid() == 0, "requires root to change ownership")
    def test_rejects_foreign_owner(self):
        bridge.load_or_create_token(self.data_dir)
        os.chown(self.token_file(), 12345, 12345)
        with self.assertRaises(bridge.TokenError):
            bridge.load_or_create_token(self.data_dir)

    def test_no_leftover_temp_files(self):
        bridge.load_or_create_token(self.data_dir)
        self.assertEqual(os.listdir(self.private()), ["token"])


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="bridge-srv-")
        cls.server = bridge.create_server("127.0.0.1", 0, data_dir=cls.data_dir)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(
            target=cls.server.serve_forever, daemon=True
        )
        cls.thread.start()
        with open(bridge.token_path(cls.data_dir), "rb") as handle:
            cls.token = handle.read().strip().decode("ascii")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method="GET", path="/", headers=None, body=None):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def raw(self, payload: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks)

    def auth(self):
        return {"Authorization": "Bearer " + self.token}

    def test_health_requires_no_auth(self):
        status, body, _ = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"status":"ok"}')

    def test_unknown_path_is_404(self):
        status, body, _ = self.request("GET", "/nope")
        self.assertEqual(status, 404)
        self.assertIn(b"not_found", body)

    def test_post_is_405(self):
        status, body, _ = self.request("POST", "/status", body=b"")
        self.assertEqual(status, 405)
        self.assertIn(b"method_not_allowed", body)

    def test_status_without_token_is_401(self):
        status, _, headers = self.request("GET", "/status")
        self.assertEqual(status, 401)
        self.assertIn("Bearer", headers.get("WWW-Authenticate", ""))

    def test_status_with_valid_token_is_200(self):
        status, body, _ = self.request("GET", "/status", self.auth())
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn('"paired":false', text)
        self.assertIn('"screenshot_enabled":false', text)
        self.assertNotIn(self.token, text)

    def test_malformed_and_incorrect_tokens_are_401(self):
        candidates = [
            None,
            "",
            "Bearer",
            "Bearer ",
            "Basic " + self.token,
            "Bearer short",
            "Bearer " + "A" * 200,
            "Bearer " + self.token + ",other",
            "Bearer " + self.token[:-1],
        ]
        for candidate in candidates:
            headers = {} if candidate is None else {"Authorization": candidate}
            with self.subTest(candidate=candidate):
                status, _, _ = self.request("GET", "/status", headers)
                self.assertEqual(status, 401)

    def test_duplicate_authorization_headers_are_rejected(self):
        payload = (
            "GET /status HTTP/1.1\r\n"
            "Host: test\r\n"
            "Authorization: Bearer %s\r\n"
            "Authorization: Bearer %s\r\n"
            "\r\n" % (self.token, self.token)
        ).encode("ascii")
        response = self.raw(payload)
        self.assertTrue(response.startswith(b"HTTP/1.1 401"), response[:40])

    def test_wrong_scheme_case_is_accepted(self):
        status, _, _ = self.request(
            "GET", "/status", {"Authorization": "bearer " + self.token}
        )
        self.assertEqual(status, 200)

    def test_screenshot_without_token_is_401(self):
        status, _, _ = self.request("GET", "/screenshot")
        self.assertEqual(status, 401)

    def test_screenshot_with_token_is_controlled_503(self):
        status, body, _ = self.request("GET", "/screenshot", self.auth())
        self.assertEqual(status, 503)
        self.assertIn(b"screenshot_unavailable", body)

    def test_oversize_declared_body_is_413(self):
        payload = (
            "POST /status HTTP/1.1\r\n"
            "Host: test\r\n"
            "Content-Length: 999999\r\n"
            "\r\n"
        ).encode("ascii")
        response = self.raw(payload)
        self.assertTrue(response.startswith(b"HTTP/1.1 413"), response[:40])

    def test_oversize_uri_is_414(self):
        status, body, _ = self.request("GET", "/" + "a" * 4096)
        self.assertEqual(status, 414)

    def test_bad_content_length_is_400(self):
        payload = (
            "POST /status HTTP/1.1\r\n"
            "Host: test\r\n"
            "Content-Length: not-a-number\r\n"
            "\r\n"
        ).encode("ascii")
        response = self.raw(payload)
        self.assertTrue(response.startswith(b"HTTP/1.1 400"), response[:40])

    def test_no_secret_or_uri_in_logs(self):
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.request("GET", "/status?access_token=" + self.token)
            self.request("GET", "/status", self.auth())
            self.request("GET", "/" + self.token)
            self.request(
                "GET", "/status", {"Authorization": "Bearer " + self.token + "x"}
            )
        output = capture.getvalue()
        self.assertNotIn(self.token, output)
        self.assertNotIn("access_token", output)
        self.assertNotIn("Authorization", output)
        self.assertNotIn("?", output)

    def test_handler_does_not_log_query_strings(self):
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.request("GET", "/health?probe=/etc/passwd")
        self.assertNotIn("probe", capture.getvalue())
        self.assertNotIn("/etc/passwd", capture.getvalue())


    def test_selftest_succeeds_with_running_token(self):
        status = bridge.run_auth_selftest(self.port, self.server.token)
        self.assertEqual(status, 200)

    def test_selftest_rejects_incorrect_token(self):
        wrong = b"A" * 43
        self.assertNotEqual(wrong, self.server.token)
        self.assertEqual(bridge.run_auth_selftest(self.port, wrong), 401)

    def test_selftest_does_not_log_the_token(self):
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            bridge.run_auth_selftest(self.port, self.server.token)
        self.assertNotIn(self.token, capture.getvalue())

    def test_selftest_returns_none_when_unreachable(self):
        probe = socket.socket()
        try:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        finally:
            probe.close()
        self.assertIsNone(
            bridge.run_auth_selftest(port, self.server.token, timeout=0.5)
        )

    def test_scheduled_selftest_logs_pass_without_token(self):
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            bridge._schedule_auth_selftest(self.server, self.port)
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                if "auth_selftest=" in capture.getvalue():
                    break
                time.sleep(0.05)
        output = capture.getvalue()
        self.assertIn("auth_selftest=PASS http=200", output)
        self.assertNotIn(self.token, output)
        self.assertNotIn("Authorization", output)


if __name__ == "__main__":
    unittest.main()
