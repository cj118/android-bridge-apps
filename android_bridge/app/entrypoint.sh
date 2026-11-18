#!/bin/sh
set -eu

APP_UID=10001
APP_GID=10001
DATA_DIR="${BRIDGE_DATA_DIR:-/data}"
PRIVATE_DIR="$DATA_DIR/private"

if [ -L "$DATA_DIR" ] || [ ! -d "$DATA_DIR" ]; then
    echo "android-bridge: fatal: data directory is missing or a symlink" >&2
    exit 1
fi

# /data is created by the Supervisor owned by root; the service runs as uid 10001.
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

# The token file is deliberately NOT touched here.
# The application verifies its type, owner and permissions.
exec su-exec "$APP_UID:$APP_GID" python3 -u /app/server.py
