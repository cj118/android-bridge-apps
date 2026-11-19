"""Root-only startup bridge for the Home Assistant user allowlist.

/data/options.json is Supervisor-managed and is normally readable only by root.
The application runs as uid 10001 and must not be given that file. This script
runs once during container start, extracts ONLY `allowed_ha_users` and
`expose_tools`, and writes them atomically into /data/private with mode 0600
owned by the application user. No other option, credential or token is copied.
"""

from __future__ import annotations

import json
import os
import sys

MAX_OPTIONS_BYTES = 64 * 1024
TOOLS_FILENAME = "expose_tools.json"


def _read_options(options_path: str):
    try:
        with open(options_path, "rb") as handle:
            data = json.loads(handle.read(MAX_OPTIONS_BYTES))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def extract_users(options_path: str):
    """Return the allowlist as a list of non-empty strings. Fail closed."""
    data = _read_options(options_path)
    if data is None:
        return []
    values = data.get("allowed_ha_users")
    if not isinstance(values, list):
        return []
    return [value.strip() for value in values if isinstance(value, str) and value.strip()]


def extract_tools(options_path: str):
    """Return the configured tool list, or None when it is not configured.

    None means "use the server's read-only default". An explicit empty list is
    returned unchanged so the operator can expose nothing at all.
    """
    data = _read_options(options_path)
    if data is None:
        return None
    values = data.get("expose_tools")
    if not isinstance(values, list):
        return None
    return values


def _write_private(target_path: str, payload: bytes, uid: int, gid: int) -> None:
    temporary = target_path + ".tmp"
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chown(temporary, uid, gid)
    os.chmod(temporary, 0o600)
    os.replace(temporary, target_path)


def write_handoff(target_path: str, users, uid: int, gid: int) -> None:
    payload = json.dumps({"allowed_ha_users": users}, sort_keys=True).encode("utf-8")
    _write_private(target_path, payload, uid, gid)


def write_tools_handoff(target_path: str, tools, uid: int, gid: int) -> None:
    payload = json.dumps({"expose_tools": tools}, sort_keys=True).encode("utf-8")
    _write_private(target_path, payload, uid, gid)


def extract(options_path: str, target_path: str, uid: int, gid: int) -> int:
    users = extract_users(options_path)
    write_handoff(target_path, users, uid, gid)
    write_tools_handoff(
        os.path.join(os.path.dirname(target_path), TOOLS_FILENAME),
        extract_tools(options_path),
        uid,
        gid,
    )
    return len(users)


def main(argv) -> int:
    if len(argv) != 5:
        sys.stderr.write(
            "options_bridge: usage: options_bridge.py OPTIONS TARGET UID GID\n"
        )
        return 2
    options_path, target_path = argv[1], argv[2]
    try:
        uid, gid = int(argv[3]), int(argv[4])
    except ValueError:
        sys.stderr.write("options_bridge: invalid uid/gid\n")
        return 2
    count = extract(options_path, target_path, uid, gid)
    sys.stderr.write("options_bridge: allowlist entries=%d\n" % count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
