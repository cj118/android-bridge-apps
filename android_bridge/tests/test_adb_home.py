"""Startup repair of adb key ownership and mode."""

import contextlib
import io
import os
import stat
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(os.path.dirname(HERE), "app")
sys.path.insert(0, APP_DIR)

import adb_home  # noqa: E402
import server as bridge  # noqa: E402


class AdbHomeTests(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="bridge-adbhome-")
        self.android = os.path.join(self.data_dir, ".android")
        os.makedirs(self.android, mode=0o700)
        self.files = {
            "adbkey": (b"-----BEGIN PRIVATE KEY-----\nsecret\n", 0o600),
            "adbkey.pub": (b"ssh-rsa AAAA test\n", 0o644),
            "adb_known_hosts.pb": (b"hosts", 0o600),
            "adb.5037": (b"", 0o644),
        }
        for name, (content, mode) in self.files.items():
            path = os.path.join(self.android, name)
            with open(path, "wb") as handle:
                handle.write(content)
            os.chmod(path, mode)

    @unittest.skipUnless(os.geteuid() == 0, "requires root to simulate root-owned keys")
    def test_repairs_ownership_and_modes_without_touching_content(self):
        for name in self.files:
            os.chown(os.path.join(self.android, name), 12345, 12345)
        os.chown(self.android, 12345, 12345)

        count = adb_home.fix(self.android, os.geteuid(), os.getegid())
        self.assertEqual(count, 4)

        info = os.lstat(self.android)
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
        self.assertEqual(info.st_uid, os.geteuid())

        for name, (content, _mode) in self.files.items():
            path = os.path.join(self.android, name)
            info = os.lstat(path)
            self.assertEqual(info.st_uid, os.geteuid(), name)
            expected = 0o644 if name == "adbkey.pub" else 0o600
            self.assertEqual(stat.S_IMODE(info.st_mode), expected, name)
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), content, name)

    def test_symlinks_are_not_followed(self):
        outside = os.path.join(self.data_dir, "outside")
        with open(outside, "wb") as handle:
            handle.write(b"keep")
        os.chmod(outside, 0o644)
        before = os.lstat(outside)
        os.symlink(outside, os.path.join(self.android, "adbkey.link"))
        adb_home.fix(self.android, os.geteuid(), os.getegid())
        after = os.lstat(outside)
        self.assertEqual(before.st_mode, after.st_mode)
        self.assertEqual(before.st_uid, after.st_uid)


class KeyStateLoggingTests(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="bridge-keystate-")
        self.android = os.path.join(self.data_dir, ".android")
        os.makedirs(self.android, mode=0o700)
        self.key = os.path.join(self.android, "adbkey")

    def log_line(self):
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            bridge._log_adb_key_state(self.data_dir)
        return capture.getvalue().strip()

    def test_missing_key(self):
        self.assertEqual(self.log_line(), "adb key missing")

    def test_readable_key(self):
        with open(self.key, "wb") as handle:
            handle.write(b"key")
        os.chmod(self.key, 0o600)
        os.chown(self.key, os.geteuid(), os.getegid())
        self.assertEqual(self.log_line(), "adb key ok")

    def test_loose_mode_is_unreadable(self):
        with open(self.key, "wb") as handle:
            handle.write(b"key")
        os.chmod(self.key, 0o644)
        os.chown(self.key, os.geteuid(), os.getegid())
        self.assertEqual(self.log_line(), "adb key unreadable")

    @unittest.skipUnless(os.geteuid() == 0, "requires root to simulate foreign owner")
    def test_foreign_owner_is_unreadable(self):
        with open(self.key, "wb") as handle:
            handle.write(b"key")
        os.chmod(self.key, 0o600)
        os.chown(self.key, 12345, 12345)
        self.assertEqual(self.log_line(), "adb key unreadable")


if __name__ == "__main__":
    unittest.main()
