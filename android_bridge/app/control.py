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
import xml.etree.ElementTree as ElementTree

MAX_COORD = 4095
MAX_SWIPE_MS = 5000
MIN_SWIPE_MS = 50
MAX_TEXT_LEN = 200
MAX_REASON_LEN = 200
# 10 minutes: long enough to read the screenshot calmly without leaving an
# approval usable for an unbounded time.
APPROVAL_TTL_SECONDS = 600.0
MAX_PENDING = 3
_TEXT_RE = re.compile(r"\A[A-Za-z0-9 .,!?@#_+:\-]{1,%d}\Z" % MAX_TEXT_LEN)

# Screen-element descriptions (0.3.21). The label is what the approval card
# shows so a human can recognise the target without reading coordinates.
UI_LABEL_MAX = 80
MAX_UI_ELEMENTS = 200
EMPTY_TARGET = "No clickable element detected — verify visually."
UNKNOWN_TARGET = "Unknown — could not check."
_BOUNDS_RE = re.compile(
    r"\A\[\s*(-?\d{1,5})\s*,\s*(-?\d{1,5})\s*\]"
    r"\[\s*(-?\d{1,5})\s*,\s*(-?\d{1,5})\s*\]\Z"
)


def format_remaining(seconds):
    """Format a TTL as minutes and seconds, never negative."""
    total = max(0, int(seconds))
    return "%dm %02ds" % (total // 60, total % 60)


class ActionError(ValueError):
    """The requested action is malformed or not permitted."""


def _coord(value, limit=MAX_COORD):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ActionError("invalid coordinate")
    if not 0 <= value < limit:
        raise ActionError("coordinate out of range")
    return value


def validate_reason(reason):
    """Accept a non-empty human-readable explanation, at most 200 chars."""
    if not isinstance(reason, str):
        raise ActionError("reason is required")
    if not reason.strip():
        raise ActionError("reason is required")
    if len(reason) > MAX_REASON_LEN:
        raise ActionError("reason is too long")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in reason):
        raise ActionError("reason contains unsupported characters")
    return reason


def validate_tap(x, y, width, height, reason):
    if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
        raise ActionError("invalid screen width")
    if isinstance(height, bool) or not isinstance(height, int) or height <= 0:
        raise ActionError("invalid screen height")
    return {
        "type": "tap",
        "x": _coord(x, width),
        "y": _coord(y, height),
        "reason": validate_reason(reason),
    }


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


def _clean_label(value):
    """Safe display label: printable, single-spaced, at most 80 characters."""
    if not isinstance(value, str):
        return ""
    text = "".join(
        char if char.isprintable() else " " for char in value
    )
    text = " ".join(text.split())
    return text[:UI_LABEL_MAX]


_SENSITIVE_CLASS_MARKERS = ("edittext", "password", "autofill")


def _node_sensitive(node):
    """True for text and password fields: never expose their contents."""
    password = (node.get("password", "false") or "false").strip().lower()
    if password == "true":
        return True
    class_name = (node.get("class", "") or "").lower()
    return any(marker in class_name for marker in _SENSITIVE_CLASS_MARKERS)


def _element_label(node, sensitive=None):
    """First useful of text, content-desc and resource-id, bounded and cleaned.

    A sensitive field - and anything inside one - contributes only its
    resource-id: typed or stored values from EditText and password fields
    never reach a model, card or log.
    """
    if sensitive is None:
        sensitive = _node_sensitive(node)
    if sensitive:
        attributes = ("resource-id",)
    else:
        attributes = ("text", "content-desc", "resource-id")
    for attribute in attributes:
        label = _clean_label(node.get(attribute, ""))
        if label:
            return label
    return ""


def _parse_bounds(value):
    if not isinstance(value, str):
        return None
    match = _BOUNDS_RE.match(value.strip())
    if match is None:
        return None
    x1, y1, x2, y2 = (int(group) for group in match.groups())
    if x1 < 0 or y1 < 0 or x2 < x1 or y2 < y1:
        return None
    return (x1, y1, x2, y2)


def _nodes(xml_text):
    """Parse a dump into (node, sensitive) pairs; unreadable yields nothing.

    A node is sensitive when it is a text or password field, or when it sits
    inside one, so nested value labels are suppressed too.
    """
    if isinstance(xml_text, bytes):
        try:
            xml_text = xml_text.decode("utf-8", "replace")
        except Exception:
            return []
    if not isinstance(xml_text, str) or not xml_text.strip():
        return []
    try:
        root = ElementTree.fromstring(xml_text)
    except (ElementTree.ParseError, ValueError):
        return []

    found = []

    def walk(element, sensitive):
        for child in element:
            if child.tag != "node":
                continue
            child_sensitive = sensitive or _node_sensitive(child)
            found.append((child, child_sensitive))
            walk(child, child_sensitive)

    walk(root, False)
    return found


def _node_visible(node):
    value = (node.get("visible-to-user", "true") or "true").strip().lower()
    return value != "false"


def _node_clickable(node):
    value = (node.get("clickable", "false") or "false").strip().lower()
    return value == "true"


def _contains(bounds, x, y):
    x1, y1, x2, y2 = bounds
    return x1 <= x <= x2 and y1 <= y <= y2


def unknown_target():
    """Inspection failed. The area is not known to be empty."""
    return {
        "identified": False,
        "label": "",
        "bounds": [],
        "description": UNKNOWN_TARGET,
        "clickable": False,
    }


def unidentified_target():
    """Inspection worked, but nothing clickable covers the point."""
    return {
        "identified": False,
        "label": "",
        "bounds": [],
        "description": EMPTY_TARGET,
        "clickable": False,
    }


def _target_result(label, bounds):
    if label:
        description = 'button "%s" at [%d,%d][%d,%d]' % (
            label, bounds[0], bounds[1], bounds[2], bounds[3]
        )
    else:
        description = "tappable area at [%d,%d][%d,%d]" % bounds
    return {
        "identified": True,
        "label": label,
        "bounds": [bounds[0], bounds[1], bounds[2], bounds[3]],
        "description": description,
        "clickable": True,
    }


def describe_target(xml_text, x, y):
    """Describe the clickable element at (x, y) from a UI dump.

    The smallest *clickable* element containing the point wins, so text drawn
    inside a card or button reports the control that would actually be pressed
    and never merely the smallest non-clickable label. Text alone is not a
    target: with no clickable element the point is reported as unidentified.
    """
    nodes = _nodes(xml_text)
    if not nodes:
        return unknown_target()

    candidates = []
    for node, sensitive in nodes:
        if not _node_visible(node) or not _node_clickable(node):
            continue
        bounds = _parse_bounds(node.get("bounds"))
        if bounds is None or not _contains(bounds, x, y):
            continue
        candidates.append((bounds, _element_label(node, sensitive)))
    if not candidates:
        return unidentified_target()

    def area(entry):
        bounds = entry[0]
        return (bounds[2] - bounds[0]) * (bounds[3] - bounds[1])

    bounds, label = min(candidates, key=area)
    return _target_result(label, bounds)


def targets_match(proposed, current):
    """True only when the approval-time recheck still agrees with the proposal.

    Fails closed when either inspection failed: an unreadable dump is never
    evidence that the point is safe. A target that vanished, changed label or
    bounds, or a new clickable element covering the point is a mismatch.
    """
    if not isinstance(proposed, dict) or not isinstance(current, dict):
        return False
    for record in (proposed, current):
        description = record.get("description")
        if not isinstance(description, str) or not description:
            return False
    if (
        proposed.get("description") == UNKNOWN_TARGET
        or current.get("description") == UNKNOWN_TARGET
    ):
        return False
    proposed_identified = bool(proposed.get("identified"))
    current_identified = bool(current.get("identified"))
    if proposed_identified != current_identified:
        return False
    if not proposed_identified:
        return True
    return (
        proposed.get("label") == current.get("label")
        and proposed.get("bounds") == current.get("bounds")
    )


def list_clickable(xml_text, limit=MAX_UI_ELEMENTS):
    """Visible clickable elements for target selection. Bounded and safe."""
    elements = []
    truncated = False
    for node, sensitive in _nodes(xml_text):
        if not _node_visible(node) or not _node_clickable(node):
            continue
        bounds = _parse_bounds(node.get("bounds"))
        if bounds is None:
            continue
        if len(elements) >= limit:
            truncated = True
            break
        label = _element_label(node, sensitive) or "unlabelled"
        elements.append(
            {"name": label, "bounds": [bounds[0], bounds[1], bounds[2], bounds[3]]}
        )
    return {
        "elements": elements,
        "count": len(elements),
        "truncated": truncated,
    }


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
        self._lock = threading.RLock()

    def _sweep(self):
        now = time.monotonic()
        for record in self.records.values():
            if record["state"] in ("pending", "approved") and record["expires"] <= now:
                record["state"] = "expired"
                if record.get("finished") is None:
                    record["finished"] = now
        while len(self.order) > 20:
            oldest = self.order.pop(0)
            record = self.records.get(oldest)
            if record is not None and record["state"] not in ("pending", "approved"):
                self.records.pop(oldest, None)

    def pending_count(self):
        with self._lock:
            self._sweep()
            return sum(
                1 for r in self.records.values() if r["state"] == "pending"
            )

    def in_flight_count(self):
        """Pending plus approved-but-not-yet-completed records."""
        with self._lock:
            self._sweep()
            return sum(
                1 for r in self.records.values()
                if r["state"] in ("pending", "approved")
            )

    def create(self, action, device, preshot, width, height, orientation,
               hardware_serial, safety_epoch=0):
        with self._lock:
            return self._create(
                action, device, preshot, width, height, orientation,
                hardware_serial, safety_epoch,
            )

    def _create(self, action, device, preshot, width, height, orientation,
                hardware_serial, safety_epoch):
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
            "width": width,
            "height": height,
            "orientation": orientation,
            "hardware_serial": hardware_serial,
            "safety_epoch": safety_epoch,
            "fingerprint": fingerprint(action, device, preshot),
            "created": time.monotonic(),
            "expires": time.monotonic() + self.ttl,
            "state": "pending",
            "detail": "",
            "finished": None,
        }
        self.records[key] = record
        self.order.append(key)
        self._sweep()
        return record

    def get(self, key):
        with self._lock:
            return self._get(key)

    def _get(self, key):
        self._sweep()
        return self.records.get(key)

    def pending(self):
        with self._lock:
            self._sweep()
            return [
                r for r in self.records.values() if r["state"] == "pending"
            ]

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
        with self._lock:
            record = self.records.get(key)
            if record is not None:
                record.update(
                    state="executed", postshot=postshot, detail=detail,
                    finished=time.monotonic(),
                )

    def fail(self, key, detail):
        with self._lock:
            record = self.records.get(key)
            if record is not None:
                record.update(
                    state="failed", detail=detail, finished=time.monotonic()
                )

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
        record["finished"] = time.monotonic()
        return record

    def recent(self, limit=5):
        """Completed results, newest first, bounded by the order list."""
        with self._lock:
            self._sweep()
            rows = [
                record for record in self.records.values()
                if record["state"] not in ("pending", "approved")
            ]
            rows.sort(key=lambda record: record["created"], reverse=True)
            return rows[:max(1, int(limit))]

    def clear(self):
        """Cancel pending/approved work and keep bounded completed history."""
        with self._lock:
            for key in list(self.records):
                record = self.records[key]
                if record["state"] in ("pending", "approved"):
                    record["state"] = "cancelled"
                    record["finished"] = time.monotonic()
                    self.records.pop(key, None)
            self.order = [key for key in self.order if key in self.records]
            while len(self.order) > 20:
                oldest = self.order.pop(0)
                record = self.records.get(oldest)
                if record is not None and record["state"] not in ("pending", "approved"):
                    self.records.pop(oldest, None)
