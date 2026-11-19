"""Bounded ADB reconnect: startup, lazy, identity, concurrency and safety.

Every ADB call goes to a fake binary in a temporary directory. No real device
is contacted and no input is performed.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(os.path.dirname(HERE), "app")
sys.path.insert(0, APP_DIR)

import server as bridge  # noqa: E402
import adbctl  # noqa: E402
import reconnect as reconnect_module  # noqa: E402

FAKE_ADB = r'''#!/usr/bin/env python3
import os, sys, time
args = sys.argv[1:]
log = os.environ.get("FAKE_ADB_LOG")
if log:
    with open(log, "a") as fh:
        fh.write(repr(args) + "\n")
envlog = os.environ.get("FAKE_ADB_ENV_LOG")
if envlog:
    with open(envlog, "a") as fh:
        fh.write("%s|%s\n" % (os.geteuid(), os.environ.get("HOME", "")))
marker = os.environ.get("FAKE_ADB_MARKER", "")
serial = os.environ.get("FAKE_ADB_SERIAL", "")
hw_serial = os.environ.get("FAKE_ADB_HW_SERIAL", "R5CT12345678")
mode = os.environ.get("FAKE_ADB_CONNECT_MODE", "ok")
server = os.environ.get("FAKE_ADB_SERVER", "ok")
if args and args[0] == "start-server":
    if server == "down":
        sys.stderr.write("error: cannot connect to daemon at tcp:localhost:5037: failed to start daemon\n")
        sys.exit(1)
    time.sleep(float(os.environ.get("FAKE_ADB_START_SLEEP", "0")))
    print("* daemon started successfully")
    sys.exit(0)
if server == "down":
    sys.stderr.write("error: cannot connect to daemon at tcp:localhost:5037\n")
    sys.exit(1)
if args and args[0] == "devices":
    print("List of devices attached")
    if serial and (not marker or os.path.exists(marker)):
        print(serial + "\tdevice product:x model:"
              + os.environ.get("FAKE_ADB_MODEL", "SM_X210") + " device:y")
    sys.exit(0)
if args and args[0] == "connect":
    if mode == "slow":
        time.sleep(float(os.environ.get("FAKE_ADB_CONNECT_SLEEP", "0.3")))
    if mode == "fail":
        sys.stderr.write("failed to connect to '%s'\n" % args[1])
        sys.exit(1)
    if marker:
        open(marker, "w").close()
    print("connected to " + args[1])
    sys.exit(0)
if "-s" in args and "get-serialno" in args:
    print(serial or "192.168.1.50:41234")
    sys.exit(0)
if "-s" in args and "shell" in args and "getprop" in args:
    prop = args[-1]
    if prop == "ro.serialno":
        print(hw_serial)
    elif prop == "ro.product.model":
        print(os.environ.get("FAKE_ADB_MODEL", "SM_X210"))
    else:
        sys.exit(2)
    sys.exit(0)
if "-s" in args and "exec-out" in args:
    with open(os.environ["FAKE_ADB_PNG"], "rb") as fh:
        sys.stdout.buffer.write(fh.read())
    sys.exit(0)
sys.exit(2)
'''

ENV_KEYS = (
    "FAKE_ADB_LOG",
    "FAKE_ADB_ENV_LOG",
    "FAKE_ADB_MARKER",
    "FAKE_ADB_SERIAL",
    "FAKE_ADB_HW_SERIAL",
    "FAKE_ADB_CONNECT_MODE",
    "FAKE_ADB_CONNECT_SLEEP",
    "FAKE_ADB_START_SLEEP",
    "FAKE_ADB_SERVER",
    "FAKE_ADB_MODEL",
    "FAKE_ADB_PNG",
)


def make_png():
    return b"\x89PNG\r\n\x1a\n" + b"\x00" * 16


class ReconnectTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bridge-rc-")
        self.data_dir = os.path.join(self.tmp, "data")
        os.makedirs(self.data_dir, mode=0o700)

        self.png_path = os.path.join(self.tmp, "frame.png")
        with open(self.png_path, "wb") as handle:
            handle.write(make_png())

        self.adb = os.path.join(self.tmp, "adb")
        with open(self.adb, "w", encoding="utf-8") as handle:
            handle.write(FAKE_ADB)
        os.chmod(self.adb, 0o755)

        self.log_path = os.path.join(self.tmp, "adb.log")
        open(self.log_path, "w").close()
        self.env_log_path = os.path.join(self.tmp, "adb.env.log")
        open(self.env_log_path, "w").close()
        self.marker_path = os.path.join(self.tmp, "connected")

        self._orig_binary = adbctl.ADB_BINARY
        adbctl.ADB_BINARY = self.adb
        self._saved_env = {key: os.environ.get(key) for key in ENV_KEYS}
        os.environ.update({
            "FAKE_ADB_LOG": self.log_path,
            "FAKE_ADB_ENV_LOG": self.env_log_path,
            "FAKE_ADB_MARKER": self.marker_path,
            "FAKE_ADB_SERIAL": "192.168.1.50:41234",
            "FAKE_ADB_HW_SERIAL": "R5CT12345678",
            "FAKE_ADB_CONNECT_MODE": "ok",
            "FAKE_ADB_CONNECT_SLEEP": "0.3",
            "FAKE_ADB_START_SLEEP": "0",
            "FAKE_ADB_SERVER": "ok",
            "FAKE_ADB_MODEL": "SM_X210",
            "FAKE_ADB_PNG": self.png_path,
        })
        adbctl.reset_server_state()
        self.servers = []

    def tearDown(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        adbctl.ADB_BINARY = self._orig_binary
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    # ---------- helpers ----------

    def server(self, lazy_sleep=None):
        server = bridge.create_server("127.0.0.1", 0, data_dir=self.data_dir)
        if lazy_sleep is not None:
            server.reconnector = reconnect_module.Reconnector(sleep=lazy_sleep)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.servers.append(server)
        return server

    def save(self, host="192.168.1.50", port="41234"):
        bridge.save_device(self.data_dir, host, port)

    def calls(self):
        if not os.path.exists(self.log_path):
            return []
        with open(self.log_path, encoding="utf-8") as handle:
            return [line.rstrip("\n") for line in handle if line.strip()]

    def connects(self):
        return [line for line in self.calls() if line.startswith("['connect'")]

    def request(self, server, path, headers=None):
        connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=20)
        try:
            connection.request("GET", path, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def token_of(self):
        with open(bridge.token_path(self.data_dir), "rb") as handle:
            return handle.read().strip().decode("ascii")

    # ---------- 1-6: startup ----------

    def test_01_startup_with_saved_device_connects_as_app_user(self):
        self.save()
        server = self.server()
        capture = io.StringIO()
        before_uid = os.geteuid()
        with contextlib.redirect_stderr(capture):
            ok = bridge.startup_reconnect(server)
        self.assertTrue(ok)
        self.assertEqual(os.geteuid(), before_uid)
        calls = self.calls()
        self.assertEqual(calls[0], "['start-server']")
        self.assertIn("['connect', '192.168.1.50:41234']", calls)
        joined = "\n".join(calls)
        self.assertNotIn("'pair'", joined)
        self.assertNotIn("'get-serialno'", joined)
        for wrapper in ("'su'", "'sudo'", "'su-exec'", "root"):
            self.assertNotIn(wrapper, joined)
        with open(self.env_log_path, encoding="utf-8") as handle:
            environments = [line.rstrip("\n") for line in handle]
        self.assertTrue(environments)
        for entry in environments:
            uid, _, home = entry.partition("|")
            self.assertEqual(int(uid), os.geteuid())
            self.assertEqual(home, os.environ.get("HOME", ""))
        output = capture.getvalue()
        self.assertIn("adb reconnect ok", output)
        self.assertNotIn("192.168.1.50", output)

    def test_02_startup_without_device_file_makes_no_attempt(self):
        server = self.server()
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.assertFalse(bridge.startup_reconnect(server))
        self.assertEqual(self.calls(), [])
        self.assertEqual(capture.getvalue(), "")

    def test_03_failed_startup_reconnect_stops_after_three_attempts(self):
        self.save()
        os.environ["FAKE_ADB_CONNECT_MODE"] = "fail"
        server = self.server(lazy_sleep=lambda _seconds: None)
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.assertFalse(bridge.startup_reconnect(server))
        self.assertEqual(len(self.connects()), 3)
        lines = [line for line in capture.getvalue().splitlines() if line]
        self.assertEqual(lines, ["adb reconnect failed reason=connection_refused"])

    def test_04_attempts_obey_timeouts_and_backoff(self):
        self.assertLessEqual(reconnect_module.STARTUP_ATTEMPTS, 3)
        self.assertLessEqual(reconnect_module.COMMAND_TIMEOUT_SECONDS, 15.0)
        for delay in reconnect_module.STARTUP_BACKOFF_SECONDS:
            self.assertLessEqual(delay, 2.0)

        sleeps = []
        reconnector = reconnect_module.Reconnector(
            attempts=3,
            backoff=(0.05, 0.1),
            timeout=2.5,
            sleep=sleeps.append,
            log=io.StringIO().write,
        )
        with mock.patch.object(adbctl, "connect") as connect_mock:
            connect_mock.side_effect = adbctl.AdbError("timeout")
            ok = reconnector.startup(
                {"host": "192.168.1.50", "connect_port": "41234"}
            )
        self.assertFalse(ok)
        self.assertEqual(connect_mock.call_count, 3)
        self.assertEqual(sleeps, [0.05, 0.1])
        for call in connect_mock.call_args_list:
            self.assertEqual(call.kwargs.get("timeout"), 2.5)

    def test_05_invalid_saved_host_or_port_cannot_trigger_adb(self):
        cases = [
            ("example.com", "41234"),
            ("192.168.1.50", "99999"),
            ("192.168.1.50", "abc"),
            ("8.8.8.8", "41234"),
        ]
        server = self.server(lazy_sleep=lambda _seconds: None)
        for host, port in cases:
            with self.subTest(host=host, port=port):
                self.save(host, port)
                capture = io.StringIO()
                with contextlib.redirect_stderr(capture):
                    self.assertFalse(bridge.startup_reconnect(server))
                self.assertEqual(self.calls(), [])
                self.assertIn(
                    "adb reconnect failed reason=invalid_target",
                    capture.getvalue(),
                )

    def test_06_reconnect_verifies_the_saved_identity(self):
        self.save()
        os.environ["FAKE_ADB_SERIAL"] = "192.168.1.99:41234"
        server = self.server(lazy_sleep=lambda _seconds: None)
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.assertFalse(bridge.startup_reconnect(server))
        output = capture.getvalue()
        self.assertIn("adb reconnect failed reason=identity_mismatch", output)
        self.assertNotIn("adb reconnect ok", output)
        self.assertEqual(len(self.connects()), 3)

    def test_06b_legacy_record_accepts_only_the_known_model(self):
        self.save()
        server = self.server(lazy_sleep=lambda _seconds: None)
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.assertTrue(bridge.startup_reconnect(server))
        output = capture.getvalue()
        self.assertIn("adb reconnect ok", output)
        self.assertIn("adb reconnect identity unverified", output)

    def test_06c_legacy_record_rejects_an_unknown_model(self):
        self.save()
        os.environ["FAKE_ADB_MODEL"] = "Pixel_9"
        server = self.server(lazy_sleep=lambda _seconds: None)
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.assertFalse(bridge.startup_reconnect(server))
        self.assertIn(
            "adb reconnect failed reason=identity_mismatch", capture.getvalue()
        )

    def test_06d_saved_identity_is_verified_without_weak_fallback(self):
        bridge.save_device(
            self.data_dir,
            "192.168.1.50",
            "41234",
            {"serial": "R5CT12345678", "model": "SM_X210"},
        )
        server = self.server(lazy_sleep=lambda _seconds: None)
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.assertTrue(bridge.startup_reconnect(server))
        output = capture.getvalue()
        self.assertIn("adb reconnect ok", output)
        self.assertNotIn("identity unverified", output)

    def test_06e_saved_serial_mismatch_is_rejected(self):
        bridge.save_device(
            self.data_dir,
            "192.168.1.50",
            "41234",
            {"serial": "R5CT00000000", "model": "SM_X210"},
        )
        server = self.server(lazy_sleep=lambda _seconds: None)
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.assertFalse(bridge.startup_reconnect(server))
        self.assertIn(
            "adb reconnect failed reason=identity_mismatch", capture.getvalue()
        )

    def test_06f_saved_model_mismatch_is_rejected(self):
        bridge.save_device(
            self.data_dir,
            "192.168.1.50",
            "41234",
            {"serial": "192.168.1.50:41234", "model": "SM_X210"},
        )
        os.environ["FAKE_ADB_MODEL"] = "Pixel_9"
        server = self.server(lazy_sleep=lambda _seconds: None)
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.assertFalse(bridge.startup_reconnect(server))
        self.assertIn(
            "adb reconnect failed reason=identity_mismatch", capture.getvalue()
        )

    def test_06g_reconnect_never_writes_device_state(self):
        self.save()
        before = open(bridge.device_path(self.data_dir), "rb").read()
        server = self.server(lazy_sleep=lambda _seconds: None)
        with mock.patch.object(bridge, "save_device") as save_mock:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertTrue(bridge.startup_reconnect(server))
        self.assertFalse(save_mock.called)
        after = open(bridge.device_path(self.data_dir), "rb").read()
        self.assertEqual(before, after)

    def test_06h_identity_round_trips_through_device_json(self):
        bridge.save_device(
            self.data_dir,
            "192.168.1.50",
            "41234",
            {"serial": "R5CT12345678", "model": "SM_X210"},
        )
        info = bridge.load_device(self.data_dir)
        self.assertEqual(info["serial"], "R5CT12345678")
        self.assertEqual(info["model"], "SM_X210")

    # ---------- 7-9: lazy reconnect ----------

    def test_07_disconnected_status_triggers_one_lazy_reconnect(self):
        self.save()
        server = self.server()
        status, body = self.request(
            server, "/status", {"Authorization": "Bearer " + self.token_of()}
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["connected"])
        self.assertEqual(len(self.connects()), 1)

    def test_08_disconnected_screenshot_triggers_one_lazy_reconnect(self):
        self.save()
        os.environ["FAKE_ADB_CONNECT_MODE"] = "fail"
        server = self.server()
        server.viewing_active = True
        server.viewing_expires = time.monotonic() + 3600
        status, body = self.request(
            server, "/screenshot", {"Authorization": "Bearer " + self.token_of()}
        )
        self.assertEqual(status, 409)
        self.assertIn(b"device_not_connected", body)
        self.assertEqual(len(self.connects()), 1)

    def test_09_concurrent_calls_cannot_cause_repeated_reconnects(self):
        self.save()
        os.environ["FAKE_ADB_CONNECT_MODE"] = "fail"
        server = self.server()
        token = self.token_of()
        results = []

        def worker():
            results.append(
                self.request(server, "/status", {"Authorization": "Bearer " + token})[0]
            )

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(results, [200] * 8)
        self.assertEqual(len(self.connects()), 1)

    def test_10_reconnect_failure_does_not_stop_startup(self):
        self.save()
        server = self.server()
        capture = io.StringIO()

        def explode(*args, **kwargs):
            raise RuntimeError("simulated adapter failure")

        with mock.patch.object(adbctl, "connect", side_effect=explode):
            with contextlib.redirect_stderr(capture):
                bridge._schedule_startup_reconnect(server)
                deadline = time.monotonic() + 10.0
                while time.monotonic() < deadline:
                    if "adb reconnect failed reason=unknown" in capture.getvalue():
                        break
                    time.sleep(0.05)
        self.assertIn("adb reconnect failed reason=unknown", capture.getvalue())
        status, body = self.request(server, "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"status":"ok"}')


    # ---------- ADB server ----------

    def test_10_start_server_runs_before_the_first_connection(self):
        self.save()
        server = self.server(lazy_sleep=lambda _seconds: None)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertTrue(bridge.startup_reconnect(server))
        calls = self.calls()
        self.assertEqual(calls[0], "['start-server']")
        self.assertIn("['connect', '192.168.1.50:41234']", calls)
        self.assertEqual(calls.count("['start-server']"), 1)

    def test_11_daemon_unavailable_is_not_a_tablet_connection_failure(self):
        self.save()
        os.environ["FAKE_ADB_SERVER"] = "down"
        server = self.server(lazy_sleep=lambda _seconds: None)
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.assertFalse(bridge.startup_reconnect(server))
        output = capture.getvalue()
        self.assertIn("adb reconnect failed reason=adb_server_unavailable", output)
        self.assertNotIn("connection_refused", output)
        self.assertEqual(self.connects(), [])
        status, body = self.request(server, "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"status":"ok"}')

    def test_12_concurrent_requests_start_one_server(self):
        os.environ["FAKE_ADB_START_SLEEP"] = "0.2"
        open(self.marker_path, "w").close()
        adbctl.reset_server_state()
        results = []

        def worker():
            results.append(len(adbctl.list_devices()))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(results, [1] * 8)
        self.assertEqual(self.calls().count("['start-server']"), 1)

    def test_13_adb_uses_the_current_environment_and_no_escalation(self):
        adbctl.ensure_server()
        adbctl.list_devices()
        joined = "\n".join(self.calls())
        for wrapper in ("'su'", "'sudo'", "'su-exec'", "root"):
            self.assertNotIn(wrapper, joined)
        with open(self.env_log_path, encoding="utf-8") as handle:
            entries = [line.rstrip("\n") for line in handle if line.strip()]
        self.assertTrue(entries)
        for entry in entries:
            uid, _, home = entry.partition("|")
            self.assertEqual(int(uid), os.geteuid())
            self.assertEqual(home, os.environ.get("HOME", ""))

    # ---------- physical identity ----------

    def test_14_get_serialno_transport_is_never_the_hardware_identity(self):
        identity = bridge.capture_identity(
            {"serial": "192.168.18.34:46337", "model": "SM-X210"}
        )
        self.assertEqual(identity["serial"], "R5CT12345678")
        self.assertNotEqual(identity["serial"], "192.168.18.34:46337")
        joined = "\n".join(self.calls())
        self.assertNotIn("'get-serialno'", joined)
        self.assertIn("'ro.serialno'", joined)

    def test_15_empty_or_address_like_ro_serialno_is_refused(self):
        for value in ("", "192.168.18.34:46337", "192.168.18.34", "unknown"):
            with self.subTest(value=value):
                os.environ["FAKE_ADB_HW_SERIAL"] = value
                adbctl.reset_server_state()
                with self.assertRaises(adbctl.AdbError):
                    adbctl.get_hardware_serial("192.168.1.50:41234")
        os.environ["FAKE_ADB_HW_SERIAL"] = "R5CT12345678"

    def test_16_model_normalisation_treats_hyphen_and_underscore_as_equal(self):
        self.assertTrue(bridge.same_model("SM-X210", "SM_X210"))
        self.assertTrue(bridge.same_model(" sm-x210 ", "SM_X210"))
        self.assertFalse(bridge.same_model("SM-X999", "SM-X210"))
        self.assertEqual(
            reconnect_module._normalise_model("SM-X210"),
            reconnect_module._normalise_model("SM_X210"),
        )

    def test_17_startup_and_lazy_reconnect_share_identity_rules(self):
        bridge.save_device(
            self.data_dir, "192.168.1.50", "41234",
            {"serial": "R5CT00000000", "model": "SM_X210"},
        )
        startup = self.server(lazy_sleep=lambda _seconds: None)
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.assertFalse(bridge.startup_reconnect(startup))
        self.assertIn("identity_mismatch", capture.getvalue())
        lazy = self.server(lazy_sleep=lambda _seconds: None)
        with contextlib.redirect_stderr(capture):
            self.assertFalse(
                lazy.reconnector.lazy(bridge.load_device(self.data_dir))
            )
        self.assertIn("identity_mismatch", capture.getvalue())

    def test_18_transport_serial_record_is_legacy_and_unverified(self):
        bridge.save_device(
            self.data_dir, "192.168.1.50", "41234",
            {"serial": "192.168.1.50:41234", "model": "SM_X210"},
        )
        server = self.server(lazy_sleep=lambda _seconds: None)
        capture = io.StringIO()
        with contextlib.redirect_stderr(capture):
            self.assertTrue(bridge.startup_reconnect(server))
        self.assertIn("adb reconnect identity unverified", capture.getvalue())



if __name__ == "__main__":
    unittest.main()
