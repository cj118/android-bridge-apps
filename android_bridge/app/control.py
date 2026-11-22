"""Approval-gated Android input actions.

Nothing here executes without a human approval recorded through the bridge UI.
Actions are validated, fingerprinted and bound to one device and one screenshot.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import threading
import time
import xml.etree.ElementTree as ElementTree

MAX_COORD = 4095
MAX_TEXT_LEN = 200
MAX_REASON_LEN = 200
MAX_PURPOSE_LEN = 200

# Swipe limits (0.3.22). Edge gestures belong to the system (back, home, the
# notification shade), so both points stay clear of every edge; the gesture
# must be long enough to register, short enough to stay deliberate, and close
# enough to one axis to mean what its direction says.
MIN_SWIPE_MS = 300
MAX_SWIPE_MS = 1500
SWIPE_EDGE_ZONE = 80
SWIPE_MIN_DISTANCE = 100
SWIPE_MAX_DISTANCE_FRACTION = 0.70
SWIPE_MAX_ANGLE_DEGREES = 20
# 10 minutes: long enough to read the screenshot calmly without leaving an
# approval usable for an unbounded time.
APPROVAL_TTL_SECONDS = 600.0
MAX_PENDING = 3
# `adb shell` still hands the command to the device shell, so the set stays
# deliberately narrow: no quotes, #, ?, *, ;, |, &, $, backticks, parentheses,
# backslashes, newlines or non-ASCII.
_TEXT_RE = re.compile(r"\A[A-Za-z0-9 .,!@_+:\-]{1,%d}\Z" % MAX_TEXT_LEN)

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

# Typing (0.3.23). A text proposal is only made for one clearly focused,
# ordinary text field. The label shown on the card is the field's content-desc
# or resource-id, never its contents, so text already in the field cannot leak.
_NOTE_NO_FIELD = "no_focused_text_field"
_NOTE_SENSITIVE = "sensitive_field_refused"
_NOTE_AMBIGUOUS = "ambiguous_text_field"
NOTE_NO_FIELD = "No focused text field detected."
NOTE_SENSITIVE = "Sensitive text field - typing refused."
NOTE_AMBIGUOUS = "More than one focused text field - typing refused."
_EDITABLE_CLASS_MARKERS = ("edittext", "textfield", "autocompletetextview")
# Words that mark a field as carrying a secret: password, PIN, one-time code,
# payment card data or an account/API secret. Matched on whole words inside
# resource-id, content-desc and hint so "spinner" is not a PIN.
_SENSITIVE_WORD_RE = re.compile(
    r"(?:^|[^a-z0-9])(?:"
    r"pass(?:word|wd|phrase|code)?|pwd|pin|otp|one[ _-]?time(?:[ _-]?code)?|"
    r"cvv|cvc|ccv|card[ _-]?(?:number|no)|credit[ _-]?card|"
    r"iban|ssn|security[ _-]?code|secret|api[ _-]?key|token|"
    r"account[ _-]?(?:number|no)|routing[ _-]?number|sort[ _-]?code"
    r")(?:$|[^a-z0-9])"
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


def validate_purpose(purpose):
    """Accept a non-empty plain-English account of what the gesture does."""
    if not isinstance(purpose, str):
        raise ActionError("purpose is required")
    if not purpose.strip():
        raise ActionError("purpose is required")
    if len(purpose) > MAX_PURPOSE_LEN:
        raise ActionError("purpose is too long")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in purpose):
        raise ActionError("purpose contains unsupported characters")
    return purpose


def swipe_direction(x1, y1, x2, y2):
    """The plain-English effect of the gesture on the screen.

    A finger moving up scrolls the content down, and vice versa; a finger
    moving left is a swipe left. Vertical wins when the gesture is closer to
    vertical than horizontal.
    """
    dx = x2 - x1
    dy = y2 - y1
    if abs(dy) >= abs(dx):
        if dy < 0:
            return "scroll down (swipe upwards)"
        if dy > 0:
            return "scroll up (swipe downwards)"
    else:
        if dx < 0:
            return "swipe left"
        if dx > 0:
            return "swipe right"
    raise ActionError("distance: a swipe must move")


def _near_edge(value, limit):
    return value < SWIPE_EDGE_ZONE or value > limit - 1 - SWIPE_EDGE_ZONE


def _swipe_distance(x1, y1, x2, y2, width, height):
    """Distance and axis rules: 100 px to 70% of the relevant dimension."""
    dx = x2 - x1
    dy = y2 - y1
    distance = math.hypot(dx, dy)
    if distance < SWIPE_MIN_DISTANCE:
        raise ActionError("distance: a swipe must travel at least 100 px")
    if abs(dx) >= abs(dy):
        limit = width * SWIPE_MAX_DISTANCE_FRACTION
        off_axis = abs(dy)
        axis = abs(dx)
    else:
        limit = height * SWIPE_MAX_DISTANCE_FRACTION
        off_axis = abs(dx)
        axis = abs(dy)
    if distance > limit:
        raise ActionError("distance: a swipe may not exceed 70% of the screen")
    angle = math.degrees(math.atan2(off_axis, axis)) if axis > 0 else 90.0
    if angle > SWIPE_MAX_ANGLE_DEGREES:
        raise ActionError(
            "diagonal: a swipe must stay within 20 degrees of an axis"
        )
    return distance


def validate_swipe(x1, y1, x2, y2, duration_ms, width, height, reason, purpose):
    """Validate a swipe against the screen it was captured from.

    Every rule is checked here, before any approval exists: points inside the
    screen and clear of the edge band, a whole-number duration in range, a
    distance between 100 px and 70% of the axis dimension, and at most 20
    degrees off that axis. The direction is derived, never supplied.
    """
    if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
        raise ActionError("invalid screen width")
    if isinstance(height, bool) or not isinstance(height, int) or height <= 0:
        raise ActionError("invalid screen height")
    x1 = _coord(x1, width)
    y1 = _coord(y1, height)
    x2 = _coord(x2, width)
    y2 = _coord(y2, height)
    if isinstance(duration_ms, bool):
        raise ActionError("duration: a swipe must last 300 to 1500 ms")
    try:
        duration = int(duration_ms)
    except (TypeError, ValueError):
        raise ActionError(
            "duration: a swipe must last 300 to 1500 ms"
        ) from None
    if not MIN_SWIPE_MS <= duration <= MAX_SWIPE_MS:
        raise ActionError("duration: a swipe must last 300 to 1500 ms")
    if (
        _near_edge(x1, width) or _near_edge(x2, width)
        or _near_edge(y1, height) or _near_edge(y2, height)
    ):
        raise ActionError(
            "edge_zone: keep both points at least 80 px from every screen edge"
        )
    distance = _swipe_distance(x1, y1, x2, y2, width, height)
    return {
        "type": "swipe",
        "x1": x1,
        "y1": y1,
        "x2": x2,
        "y2": y2,
        "duration_ms": duration,
        "distance": int(round(distance)),
        "direction": swipe_direction(x1, y1, x2, y2),
        "reason": validate_reason(reason),
        "purpose": validate_purpose(purpose),
    }


# Friendly names for packages the tablet is likely to show. Anything else
# falls back to a readable form of the package's last segment, so the card
# never invents a product name it does not know.
APP_LABELS = {
    "com.android.settings": "Settings",
    "com.android.systemui": "System UI",
    "com.android.chrome": "Chrome",
    "com.android.vending": "Play Store",
    "com.google.android.youtube": "YouTube",
    "com.google.android.gm": "Gmail",
    "com.google.android.apps.maps": "Maps",
    "com.google.android.apps.photos": "Photos",
    "com.google.android.camera": "Camera",
    "com.android.camera": "Camera",
    "com.google.android.dialer": "Phone",
    "com.android.dialer": "Phone",
    "com.google.android.apps.messaging": "Messages",
    "com.android.messaging": "Messages",
    "com.google.android.calendar": "Calendar",
    "com.android.deskclock": "Clock",
    "com.android.documentsui": "Files",
}
_APP_FALLBACK_MAX = 40


def app_label(package):
    """Friendly app name from a package id (com.android.settings -> Settings)."""
    if not isinstance(package, str):
        return ""
    value = package.strip()
    if not value:
        return ""
    known = APP_LABELS.get(value)
    if known:
        return known
    segment = value.rsplit(".", 1)[-1]
    words = re.sub(r"[^A-Za-z0-9]+", " ", segment).split()
    if not words:
        return ""
    label = " ".join(word[:1].upper() + word[1:] for word in words)
    return label[:_APP_FALLBACK_MAX]


def swipe_headline(action):
    """The exact approval-card sentence for a swipe proposal."""
    direction = action.get("direction") or "swipe"
    app = action.get("app") or "the current app"
    return "DeepSeek wants to %s in %s." % (direction, app)


def text_headline(action):
    """The exact approval-card sentence for a text proposal."""
    app = action.get("app") or "the current app"
    return "DeepSeek wants to type in %s" % app


def approval_headline(action):
    """The approval card's headline, safe for a read-only summary.

    The tap card names the element together with its bounds; the summary drops
    the bounds because it must never carry coordinates. Typed text, screenshots
    and device identifiers are not part of any headline.
    """
    kind = action.get("type")
    if kind == "swipe":
        return swipe_headline(action)
    if kind == "text":
        return text_headline(action) + "."
    if kind == "tap":
        target = action.get("target") or {}
        if target.get("identified"):
            label = target.get("label") or ""
            detail = 'button "%s"' % label if label else "tappable area"
        else:
            detail = target.get("description") or UNKNOWN_TARGET
        return "This will tap: %s" % detail
    return "An approval is waiting."


def validate_text(text, purpose=None, reason=None):
    """Restricted ordinary text, at most 200 characters.

    Leading and trailing whitespace is trimmed before approval, so the card,
    the stored action and the input command always agree. Purpose and reason
    are optional here so the charset can be checked on its own; a proposal
    must supply both.
    """
    if not isinstance(text, str):
        raise ActionError("text is required")
    cleaned = text.strip()
    if not cleaned:
        raise ActionError("text is required")
    if not _TEXT_RE.match(cleaned):
        raise ActionError(
            "text contains unsupported characters (letters, digits, spaces "
            "and .,!@_+:- only)"
        )
    action = {"type": "text", "text": cleaned}
    if purpose is not None:
        action["purpose"] = validate_purpose(purpose)
    if reason is not None:
        action["reason"] = validate_reason(reason)
    return action


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


def _node_focused(node):
    value = (node.get("focused", "false") or "false").strip().lower()
    return value == "true"


def _node_editable(node):
    """An actual text input, identified by class or an editable attribute."""
    value = (node.get("editable", "") or "").strip().lower()
    if value == "true":
        return True
    class_name = (node.get("class", "") or "").lower()
    return any(marker in class_name for marker in _EDITABLE_CLASS_MARKERS)


def _field_is_secret(node):
    """True for password, PIN, one-time-code, payment and secret fields.

    Only metadata is inspected - never the field's text - so a refusal cannot
    echo what the field already contains.
    """
    if (node.get("password", "false") or "false").strip().lower() == "true":
        return True
    class_name = (node.get("class", "") or "").lower()
    if "password" in class_name:
        return True
    for attribute in ("resource-id", "content-desc", "hint"):
        value = (node.get(attribute, "") or "").lower()
        if value and _SENSITIVE_WORD_RE.search(value):
            return True
    return False


def _field_label(node):
    """A safe name for a text field: content-desc, then resource-id.

    The field's own text is never used: it may hold a previous query, an
    address or a name that the approval card has no need to reveal.
    """
    for attribute in ("content-desc", "resource-id"):
        label = _clean_label(node.get(attribute, ""))
        if label:
            return label
    return ""


def _unidentified_field(description, reason, sensitive=False):
    return {
        "identified": False,
        "reason": reason,
        "sensitive": bool(sensitive),
        "label": "",
        "bounds": [],
        "description": description,
        "clickable": False,
    }


def focused_text_field(xml_text):
    """Describe the one focused, visible, editable text field, or refuse.

    Refuses when the dump cannot be read, when nothing editable is focused,
    when several fields are focused at once, and for any password, PIN,
    payment or other secret field. The refusal carries a fixed reason token;
    no field contents are included.
    """
    nodes = _nodes(xml_text)
    if not nodes:
        return _unidentified_field(UNKNOWN_TARGET, "target_unverified")

    focused = []
    for node, _sensitive in nodes:
        if not _node_visible(node) or not _node_focused(node):
            continue
        if not _node_editable(node):
            continue
        bounds = _parse_bounds(node.get("bounds"))
        if bounds is None:
            continue
        focused.append((node, bounds))

    if not focused:
        return _unidentified_field(NOTE_NO_FIELD, _NOTE_NO_FIELD)
    if len(focused) > 1:
        return _unidentified_field(NOTE_AMBIGUOUS, _NOTE_AMBIGUOUS)

    node, bounds = focused[0]
    if _field_is_secret(node):
        return _unidentified_field(
            NOTE_SENSITIVE, _NOTE_SENSITIVE, sensitive=True
        )

    label = _field_label(node)
    if label:
        description = 'text field "%s" at [%d,%d][%d,%d]' % (
            label, bounds[0], bounds[1], bounds[2], bounds[3]
        )
    else:
        description = "focused text field at [%d,%d][%d,%d]" % bounds
    return {
        "identified": True,
        "reason": "",
        "sensitive": False,
        "label": label,
        "bounds": [bounds[0], bounds[1], bounds[2], bounds[3]],
        "description": description,
        "clickable": True,
    }


def text_targets_match(proposed, current):
    """True only when the approval-time recheck names the same focused field.

    Fails closed: an unreadable dump, a missing field or a field that changed
    size, position or identity is a mismatch, and nothing is typed.
    """
    if not isinstance(proposed, dict) or not isinstance(current, dict):
        return False
    for record in (proposed, current):
        if not record.get("identified"):
            return False
        bounds = record.get("bounds")
        if not isinstance(bounds, list) or len(bounds) != 4:
            return False
    return (
        proposed.get("label") == current.get("label")
        and proposed.get("bounds") == current.get("bounds")
    )


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
        # Never echo the contents in a description: it lands in panel history
        # and logs. The approval card shows the text from the action itself.
        return "Type %d characters" % len(action.get("text", ""))
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
        # Re-validated here so nothing but restricted ordinary text can reach
        # the fixed argv. The text is one argv element, never a shell string:
        # a space becomes %s for `input text` and no other metacharacter is
        # permitted by _TEXT_RE.
        text = action.get("text")
        if not isinstance(text, str) or not _TEXT_RE.match(text):
            raise ActionError("unsupported text")
        return ["-s", serial, "shell", "input", "text",
                text.replace(" ", "%s")]
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
