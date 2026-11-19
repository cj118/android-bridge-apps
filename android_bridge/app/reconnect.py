"""Bounded reconnection to the saved wireless-ADB tablet.

Only fixed ADB operations are used: `connect` to the saved target, a read-only
device listing, and the two read-only identity reads (`getprop ro.serialno` and
`getprop ro.product.model`). Every value comes from /data/private/device.json
and is validated before adb runs, so a corrupt file cannot reach the adb binary.
The caller is already the unprivileged application user; this module never
escalates privileges and never pairs.

Log output is limited to these fixed lines:

    adb reconnect ok
    adb reconnect identity unverified
    adb reconnect failed reason=<category>
"""

from __future__ import annotations

import sys
import threading
import time

import adbctl

STARTUP_ATTEMPTS = 3
STARTUP_BACKOFF_SECONDS = (0.5, 1.0)
COMMAND_TIMEOUT_SECONDS = 8.0
LAZY_COOLDOWN_SECONDS = 30.0

# A saved record from before identities were stored has no serial/model. The
# only tablet this bridge was built for is the SM-X210, so that model is the
# single weak check allowed until a human connect from the panel saves a real
# identity.
LEGACY_UNVERIFIED_MODEL = "SM-X210"


def _normalise_model(value):
    value = (value or "").strip().lower()
    value = value.replace("-", " ").replace("_", " ")
    return " ".join(value.split())


class Reconnector:
    """One reconnect at a time, bounded attempts, bounded command timeouts."""

    def __init__(
        self,
        attempts=STARTUP_ATTEMPTS,
        backoff=STARTUP_BACKOFF_SECONDS,
        timeout=COMMAND_TIMEOUT_SECONDS,
        cooldown=LAZY_COOLDOWN_SECONDS,
        sleep=time.sleep,
        log=None,
    ):
        self.attempts = max(1, int(attempts))
        self.backoff = tuple(float(value) for value in backoff)
        self.timeout = float(timeout)
        self.cooldown = float(cooldown)
        self._sleep = sleep
        self._log = log or (lambda line: sys.stderr.write(line))
        self._lock = threading.Lock()
        self._last_attempt = None

    def _emit(self, reason, unverified=False):
        if reason is None:
            self._log("adb reconnect ok\n")
            if unverified:
                self._log("adb reconnect identity unverified\n")
        else:
            self._log("adb reconnect failed reason=%s\n" % reason)

    def _backoff_for(self, index):
        if not self.backoff:
            return 0.0
        return self.backoff[min(index, len(self.backoff) - 1)]

    def _verify(self, info, device):
        """Return (reason, unverified). reason None means the device is trusted.

        A saved value is a hardware identity only when it is a plausible
        physical serial. A missing serial, or a legacy host:port transport
        address, is unverified data and must be re-enrolled by a human panel
        connection.
        """
        saved_serial = (info.get("serial") or "").strip()
        if adbctl.is_hardware_serial(saved_serial):
            try:
                actual_serial = adbctl.get_hardware_serial(
                    device["serial"], timeout=adbctl.IDENTITY_TIMEOUT
                )
                actual_model = adbctl.get_model(
                    device["serial"], timeout=adbctl.IDENTITY_TIMEOUT
                )
            except adbctl.AdbError:
                return "identity_mismatch", False
            if actual_serial != saved_serial:
                return "identity_mismatch", False
            saved_model = info.get("model")
            if saved_model and (
                _normalise_model(actual_model) != _normalise_model(saved_model)
            ):
                return "identity_mismatch", False
            return None, False
        # Legacy record: no hardware serial, or a transport address saved by an
        # older build. Only the known tablet model is accepted, and the caller
        # is told the check was weak.
        if (
            _normalise_model(device.get("model"))
            != _normalise_model(LEGACY_UNVERIFIED_MODEL)
        ):
            return "identity_mismatch", False
        return None, True

    def _attempt(self, info):
        """One connect plus identity check. Returns (reason, unverified)."""
        try:
            adbctl.validate_target(info["host"], info["connect_port"])
        except (KeyError, TypeError, adbctl.AdbError):
            return "invalid_target", False
        try:
            adbctl.connect(info["host"], info["connect_port"], timeout=self.timeout)
        except adbctl.AdbError as exc:
            if exc.reason:
                return exc.reason, False
            return ("timeout" if str(exc) == "timeout" else "connection_refused"), False
        try:
            devices = adbctl.list_devices(timeout=self.timeout)
        except adbctl.AdbError:
            return "device_list_failed", False
        target = "%s:%s" % (info["host"], info["connect_port"])
        matches = [entry for entry in devices if entry.get("serial") == target]
        if len(matches) != 1:
            return "identity_mismatch", False
        return self._verify(info, matches[0])

    def startup(self, info):
        """Bounded startup reconnect. Returns True only on a verified device."""
        if not info:
            return False
        with self._lock:
            self._last_attempt = time.monotonic()
            reason, unverified = "unknown", False
            for index in range(self.attempts):
                reason, unverified = self._attempt(info)
                if reason is None:
                    self._emit(None, unverified)
                    return True
                if index + 1 < self.attempts:
                    self._sleep(self._backoff_for(index))
            self._emit(reason)
            return False

    def lazy(self, info):
        """At most one reconnect per cooldown, for a request-time failure."""
        if not info:
            return False
        with self._lock:
            now = time.monotonic()
            if self._last_attempt is not None and now - self._last_attempt < self.cooldown:
                return False
            self._last_attempt = now
            reason, unverified = self._attempt(info)
            self._emit(reason, unverified)
            return reason is None
