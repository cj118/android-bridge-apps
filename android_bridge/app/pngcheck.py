"""PNG validation for captured frames. No decoding, no trust in the device."""

from __future__ import annotations

import struct

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_DIMENSION = 4096
MAX_IMAGE_BYTES = 12 * 1024 * 1024


class PngError(ValueError):
    """The captured bytes are not an acceptable PNG."""


def validate(data: bytes, max_bytes: int = MAX_IMAGE_BYTES):
    """Return (width, height) or raise PngError."""
    if not data:
        raise PngError("empty image")
    if len(data) > max_bytes:
        raise PngError("image too large")
    if not data.startswith(PNG_SIGNATURE):
        raise PngError("not a png")
    if len(data) < 24:
        raise PngError("truncated png")
    if data[12:16] != b"IHDR":
        raise PngError("missing ihdr")
    width, height = struct.unpack(">II", data[16:24])
    if not 0 < width <= MAX_DIMENSION:
        raise PngError("bad width")
    if not 0 < height <= MAX_DIMENSION:
        raise PngError("bad height")
    return width, height
