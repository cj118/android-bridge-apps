"""Root-only startup: make the adb home usable by the application user.

An earlier adb run as root left /data/.android key material owned by root, so
the unprivileged adb server could not read its own key. This repairs ownership
and modes in place. The key content is never read, printed or regenerated.
"""

from __future__ import annotations

import os
import stat
import sys


def fix(android_dir: str, uid: int, gid: int) -> int:
    if os.path.islink(android_dir):
        raise OSError("adb home is a symlink")
    os.makedirs(android_dir, mode=0o700, exist_ok=True)
    os.chown(android_dir, uid, gid)
    os.chmod(android_dir, 0o700)

    changed = 0
    for name in sorted(os.listdir(android_dir)):
        path = os.path.join(android_dir, name)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            continue  # never follow or touch symlinks, sockets or devices
        os.chown(path, uid, gid)
        if name == "adbkey.pub":
            os.chmod(path, 0o644)
        else:
            os.chmod(path, 0o600)
        changed += 1
    return changed


def main(argv) -> int:
    if len(argv) != 4:
        sys.stderr.write("adb_home: usage: adb_home.py DIR UID GID\n")
        return 2
    try:
        uid, gid = int(argv[2]), int(argv[3])
    except ValueError:
        sys.stderr.write("adb_home: invalid uid/gid\n")
        return 2
    count = fix(argv[1], uid, gid)
    sys.stderr.write("adb_home: files=%d uid=%d\n" % (count, uid))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
