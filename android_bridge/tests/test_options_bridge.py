"""Startup allowlist handoff: root-only options.json to private app file."""

import json
import os
import re
import stat
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.client import HTTPConnection

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(os.path.dirname(HERE), "app")
sys.path.insert(0, APP_DIR)

import options_bridge  # noqa: E402
import server as bridge  # noqa: E402


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="bridge-opt-")
        os.makedirs(bridge.private_dir(self.data_dir), mode=0o700)
        self.options = os.path.join(self.data_dir, "options.json")
        self.target = os.path.join(bridge.private_dir(self.data_dir), "allowed_users.json")

    def write_options(self, payload, mode=0o600):
        with open(self.options, "w", encoding="utf-8") as handle:
            if isinstance(payload, str):
                handle.write(payload)
            else:
                json.dump(payload, handle)
        os.chmod(self.options, mode)

    def test_extracts_only_allowed_users(self):
        self.write_options({
            "allowed_ha_users": ["carlj", "second"],
            "access_token": "must-not-be-copied",
            "env_vars": [{"name": "SECRET", "value": "nope"}],
        })
        count = options_bridge.extract(
            self.options, self.target, os.geteuid(), os.getegid()
        )
        self.assertEqual(count, 2)
        with open(self.target, encoding="utf-8") as handle:
            content = handle.read()
        self.assertEqual(
            json.loads(content), {"allowed_ha_users": ["carlj", "second"]}
        )
        self.assertNotIn("must-not-be-copied", content)
        self.assertNotIn("SECRET", content)

    def test_handoff_is_private_and_owned_by_app_user(self):
        self.write_options({"allowed_ha_users": ["carlj"]})
        options_bridge.extract(self.options, self.target, os.geteuid(), os.getegid())
        info = os.lstat(self.target)
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_uid, os.geteuid())

    def test_missing_options_yields_empty_allowlist(self):
        options_bridge.extract(self.options, self.target, os.geteuid(), os.getegid())
        with open(self.target, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle), {"allowed_ha_users": []})

    def test_malformed_options_yields_empty_allowlist(self):
        self.write_options("{not json")
        options_bridge.extract(self.options, self.target, os.geteuid(), os.getegid())
        with open(self.target, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle), {"allowed_ha_users": []})

    def test_wrong_type_yields_empty_allowlist(self):
        self.write_options({"allowed_ha_users": "carlj"})
        options_bridge.extract(self.options, self.target, os.geteuid(), os.getegid())
        with open(self.target, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle), {"allowed_ha_users": []})

    def test_server_ignores_a_readable_options_file(self):
        # Even a world-readable options.json must not be read by the app.
        self.write_options({"allowed_ha_users": ["carlj"]}, mode=0o644)
        self.assertEqual(bridge.load_allowed_users(self.data_dir), frozenset())

    def test_server_reads_the_handoff(self):
        self.write_options({"allowed_ha_users": ["carlj"]})
        options_bridge.extract(self.options, self.target, os.geteuid(), os.getegid())
        self.assertEqual(bridge.load_allowed_users(self.data_dir), frozenset({"carlj"}))

    def test_handoff_with_loose_permissions_is_rejected(self):
        self.write_options({"allowed_ha_users": ["carlj"]})
        options_bridge.extract(self.options, self.target, os.geteuid(), os.getegid())
        os.chmod(self.target, 0o644)
        self.assertEqual(bridge.load_allowed_users(self.data_dir), frozenset())

    @unittest.skipUnless(os.geteuid() == 0, "requires root to change ownership")
    def test_handoff_with_foreign_owner_is_rejected(self):
        self.write_options({"allowed_ha_users": ["carlj"]})
        options_bridge.extract(self.options, self.target, os.geteuid(), os.getegid())
        os.chown(self.target, 12345, 12345)
        self.assertEqual(bridge.load_allowed_users(self.data_dir), frozenset())


class ToolHandoffTests(unittest.TestCase):
    """expose_tools crosses the root-only boundary in its own 0600 file."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="bridge-opt-tools-")
        os.makedirs(bridge.private_dir(self.data_dir), mode=0o700)
        self.options = os.path.join(self.data_dir, "options.json")
        self.target = os.path.join(bridge.private_dir(self.data_dir), "allowed_users.json")
        self.tools = os.path.join(bridge.private_dir(self.data_dir), "expose_tools.json")

    def write_options(self, payload):
        with open(self.options, "w", encoding="utf-8") as handle:
            if isinstance(payload, str):
                handle.write(payload)
            else:
                json.dump(payload, handle)
        os.chmod(self.options, 0o600)

    def extract(self):
        options_bridge.extract(
            self.options, self.target, os.geteuid(), os.getegid()
        )

    def read_tools(self):
        with open(self.tools, encoding="utf-8") as handle:
            return json.load(handle)

    def test_explicit_list_is_handed_over_unchanged(self):
        self.write_options({"expose_tools": ["android_status", "android_status"]})
        self.extract()
        self.assertEqual(
            self.read_tools(), {"expose_tools": ["android_status", "android_status"]}
        )
        info = os.lstat(self.tools)
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)

    def test_empty_list_stays_empty(self):
        self.write_options({"expose_tools": []})
        self.extract()
        self.assertEqual(self.read_tools(), {"expose_tools": []})

    def test_missing_setting_marks_default(self):
        self.write_options({"allowed_ha_users": ["carlj"]})
        self.extract()
        self.assertEqual(self.read_tools(), {"expose_tools": None})
        self.assertEqual(
            bridge.load_exposed_tools(self.data_dir),
            ("android_screenshot", "android_status"),
        )

    def test_wrong_type_marks_default(self):
        self.write_options({"expose_tools": "android_tap"})
        self.extract()
        self.assertEqual(self.read_tools(), {"expose_tools": None})

    def test_server_reads_a_tools_handoff(self):
        self.write_options({"expose_tools": ["android_status"]})
        self.extract()
        self.assertEqual(bridge.load_exposed_tools(self.data_dir), ("android_status",))

    def test_loose_tools_handoff_is_rejected(self):
        self.write_options({"expose_tools": ["android_tap"]})
        self.extract()
        os.chmod(self.tools, 0o644)
        self.assertEqual(
            bridge.load_exposed_tools(self.data_dir),
            ("android_screenshot", "android_status"),
        )


class AllowlistSignInTests(unittest.TestCase):
    """End-to-end: carlj from the handoff can sign in; others cannot."""

    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="bridge-allow-")
        os.makedirs(bridge.private_dir(cls.data_dir), mode=0o700)
        options = os.path.join(cls.data_dir, "options.json")
        with open(options, "w", encoding="utf-8") as handle:
            json.dump({"allowed_ha_users": ["carlj"], "access_token": "x"}, handle)
        os.chmod(options, 0o600)
        options_bridge.extract(
            options,
            os.path.join(bridge.private_dir(cls.data_dir), "allowed_users.json"),
            os.geteuid(),
            os.getegid(),
        )
        cls.server = bridge.create_server("127.0.0.1", 0, data_dir=cls.data_dir)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls._orig_peer = bridge.Handler._peer
        bridge.Handler._peer = lambda handler: "172.30.32.2"

    @classmethod
    def tearDownClass(cls):
        bridge.Handler._peer = cls._orig_peer
        cls.server.shutdown()
        cls.server.server_close()

    def sign_in(self, user, nonce=None, cookie=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            if nonce is None:
                conn.request("GET", "/control")
                response = conn.getresponse()
                page = response.read()
                nonce = re.search(rb"name='nonce' value='([0-9a-f]+)'", page).group(1).decode()
                cookie = response.getheader("Set-Cookie").split(";", 1)[0]
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": cookie,
                "X-Ingress-Path": "/api/hassio_ingress/TESTTOKEN",
            }
            if user is not None:
                headers["X-Remote-User-Name"] = user
            conn.request("POST", "/control",
                         urllib.parse.urlencode({"nonce": nonce}), headers)
            response = conn.getresponse()
            response.read()
            return response.status, response.getheader("Set-Cookie")
        finally:
            conn.close()

    def test_loaded_allowlist_contains_carlj(self):
        self.assertEqual(self.server.allowed_users, frozenset({"carlj"}))

    def test_carlj_can_sign_in(self):
        status, cookie = self.sign_in("carlj")
        self.assertEqual(status, 200)
        self.assertIsNotNone(cookie)

    def test_unknown_user_is_rejected(self):
        status, cookie = self.sign_in("mallory")
        self.assertEqual(status, 403)
        self.assertIsNone(cookie)


if __name__ == "__main__":
    unittest.main()
