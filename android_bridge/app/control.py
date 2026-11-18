"""Approval-gated Android input actions.

Nothing here executes without a human approval recorded through the bridge UI.
Actions are validated, fingerprinted and bound to one device and one screenshot.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time

MAX_COORD = 4095
MAX_SWIPE_MS = 5000
MIN_SWIPE_MS = 50
MAX_TEXT_LEN = 200
APPROVAL_TTL_SECONDS = 120.0
MAX_PENDING = 3
_TEXT_RE = re.compile(r"\A[A-Za-z0-9 .,!?@#_+:\-]{1,%d}\Z" % MAX_TEXT_LEN)


class ActionError(ValueError):
    """The requested action is malformed or not permitted."""


def _coord(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ActionError("invalid coordinate") from None
    if not 0 <= number <= MAX_COORD:
        raise ActionError("coordinate out of range")
    return number


def validate_tap(x, y):
    return {"type": "tap", "x": _coord(x), "y": _coord(y)}


def validate_swipe(x1, y1, x2, y2, duration_ms=300):
    try:
        duration = int(duration_ms)
    except (TypeError, ValueError):
        raise ActionError("invalid duration") from None
    if not MIN_SWIPE_MS <= duration <= MAX_SWIPE_MS:
        raise ActionError("duration out of range")
    return {
        "type": "swipe",
        "x1": _coord(x1),
        "y1": _coord(y1),
        "x2": _coord(x2),
        "y2": _coord(y2),
        "duration_ms": duration,
    }


def validate_text(text):
    text = (text or "").strip()
    if not _TEXT_RE.match(text):
        raise ActionError("text contains unsupported characters")
    return {"type": "text", "text": text}


def describe(action):
    kind = action.get("type")
    if kind == "tap":
        return "Tap (%d, %d)" % (action["x"], action["y"])
    if kind == "swipe":
        return "Swipe (%d, %d) to (%d, %d) over %d ms" % (
            action["x1"], action["y1"], action["x2"], action["y2"],
            action["duration_ms"],
        )
    if kind == "text":
        return "Type text: %r" % action["text"]
    return "Unknown action"


def fingerprint(action, device, preshot):
    payload = json.dumps(
        {
            "action": action,
            "device": device,
            "shot": hashlib.sha256(preshot).hexdigest(),
        },
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def adb_args(action, serial):
    """Fixed input command. The caller never supplies free-form arguments."""
    kind = action["type"]
    if kind == "tap":
        return ["-s", serial, "shell", "input", "tap",
                str(action["x"]), str(action["y"])]
    if kind == "swipe":
        return ["-s", serial, "shell", "input", "swipe",
                str(action["x1"]), str(action["y1"]),
                str(action["x2"]), str(action["y2"]),
                str(action["duration_ms"])]
    if kind == "text":
        return ["-s", serial, "shell", "input", "text",
                action["text"].replace(" ", "%s")]
    raise ActionError("unsupported action")


class Approvals:
    """In-memory, single-use approval records. Cleared on restart or STOP."""

    def __init__(self, ttl=APPROVAL_TTL_SECONDS, max_pending=MAX_PENDING):
        self.ttl = ttl
        self.max_pending = max_pending
        self.records = {}
        self.order = []
        self._lock = threading.Lock()

    def _sweep(self):
        now = time.monotonic()
        for record in self.records.values():
            if record["state"] in ("pending", "approved") and record["expires"] <= now:
                record["state"] = "expired"
        while len(self.order) > 20:
            oldest = self.order.pop(0)
            record = self.records.get(oldest)
            if record is not None and record["state"] not in ("pending", "approved"):
                self.records.pop(oldest, None)

    def pending_count(self):
        self._sweep()
        return sum(1 for r in self.records.values() if r["state"] == "pending")

    def create(self, action, device, preshot):
        with self._lock:
            return self._create(action, device, preshot)

    def _create(self, action, device, preshot):
        self._sweep()
        if self.pending_count() >= self.max_pending:
            raise ActionError("too many pending approvals")
        key = secrets.token_hex(4)
        record = {
            "id": key,
            "action": action,
            "device": device,
            "preshot": preshot,
            "postshot": None,
            "fingerprint": fingerprint(action, device, preshot),
            "created": time.monotonic(),
            "expires": time.monotonic() + self.ttl,
            "state": "pending",
            "detail": "",
        }
        self.records[key] = record
        self.order.append(key)
        return record

    def get(self, key):
        with self._lock:
            return self._get(key)

    def _get(self, key):
        self._sweep()
        return self.records.get(key)

    def pending(self):
        self._sweep()
        return [r for r in self.records.values() if r["state"] == "pending"]

    def approve(self, key):
        with self._lock:
            return self._approve(key)

    def _approve(self, key):
        record = self._get(key)
        if record is None:
            raise ActionError("unknown approval")
        if record["state"] != "pending":
            raise ActionError("approval is not pending")
        if record["expires"] <= time.monotonic():
            raise ActionError("approval expired")
        if fingerprint(record["action"], record["device"], record["preshot"]) != record["fingerprint"]:
            raise ActionError("approval binding mismatch")
        record["state"] = "approved"
        return record

    def complete(self, key, postshot, detail=""):
        record = self.records.get(key)
        if record is not None:
            record.update(state="executed", postshot=postshot, detail=detail)

    def fail(self, key, detail):
        record = self.records.get(key)
        if record is not None:
            record.update(state="failed", detail=detail)

    def reject(self, key):
        with self._lock:
            return self._reject(key)

    def _reject(self, key):
        record = self._get(key)
        if record is None:
            raise ActionError("unknown approval")
        if record["state"] != "pending":
            raise ActionError("approval is not pending")
        record["state"] = "rejected"
        return record

    def clear(self):
        with self._lock:
            for record in self.records.values():
                if record["state"] in ("pending", "approved"):
                    record["state"] = "cancelled"
            self.records.clear()
            self.order.clear()
