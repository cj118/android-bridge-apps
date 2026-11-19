#!/bin/sh
set -eu

APP_UID=10001
APP_GID=10001
DATA_DIR="${BRIDGE_DATA_DIR:-/data}"
PRIVATE_DIR="$DATA_DIR/private"
ANDROID_DIR="$DATA_DIR/.android"

if [ -L "$DATA_DIR" ] || [ ! -d "$DATA_DIR" ]; then
    echo "android-bridge: fatal: data directory is missing or a symlink" >&2
    exit 1
fi

chown "$APP_UID:$APP_GID" "$DATA_DIR" 2>/dev/null || true

if [ -L "$PRIVATE_DIR" ]; then
    echo "android-bridge: fatal: private directory is a symlink" >&2
    exit 1
fi
if [ ! -d "$PRIVATE_DIR" ]; then
    mkdir -p "$PRIVATE_DIR"
fi
chown "$APP_UID:$APP_GID" "$PRIVATE_DIR" 2>/dev/null || true
chmod 0700 "$PRIVATE_DIR" 2>/dev/null || true

# ADB private key home. Created as a plain directory, never a symlink.
if [ -L "$ANDROID_DIR" ]; then
    echo "android-bridge: fatal: adb home is a symlink" >&2
    exit 1
fi
if [ ! -d "$ANDROID_DIR" ]; then
    mkdir -p "$ANDROID_DIR"
fi
chown "$APP_UID:$APP_GID" "$ANDROID_DIR" 2>/dev/null || true
chmod 0700 "$ANDROID_DIR" 2>/dev/null || true

# Root-only handoff: copy ONLY allowed_ha_users out of the Supervisor-managed
# options file. That file stays root-readable; the app user never sees it.
python3 /app/options_bridge.py \
    "$DATA_DIR/options.json" \
    "$PRIVATE_DIR/allowed_users.json" \
    "$APP_UID" "$APP_GID" || true

# The token and adbkey files are never touched here: chown follows symlinks.
exec su-exec "$APP_UID:$APP_GID" python3 -u /app/server.py
