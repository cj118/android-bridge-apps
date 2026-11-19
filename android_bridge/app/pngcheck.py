"""PNG validation, bounded decoding, and tap-region comparison.

The bridge only accepts non-interlaced 8-bit PNGs up to the capture limit.
Decoding is deliberately small and dependency-free: zlib plus the five PNG
row filters. Any image outside that shape fails closed.
"""

from __future__ import annotations

import binascii
import struct
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_DIMENSION = 4096
MAX_IMAGE_BYTES = 12 * 1024 * 1024
MAX_DECODED_BYTES = 64 * 1024 * 1024

# Deterministic tap comparison tolerances. A pixel differs when any RGB
# channel differs by more than PIXEL_DIFF_THRESHOLD (0-255). The target area
# counts as changed when more than CHANGED_PIXEL_FRACTION (0.5%) of
# its pixels differ.
TAP_REGION_RADIUS = 48
PIXEL_DIFF_THRESHOLD = 24
CHANGED_PIXEL_FRACTION = 0.005

_CHANNELS = {0: 1, 2: 3, 4: 2, 6: 4}


class PngError(ValueError):
    """The captured bytes are not an acceptable PNG."""


class Image:
    """Decoded image rows without the per-row filter byte."""

    __slots__ = ("width", "height", "channels", "rows")

    def __init__(self, width, height, channels, rows):
        self.width = width
        self.height = height
        self.channels = channels
        self.rows = rows


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


def _chunks(data):
    if not data.startswith(PNG_SIGNATURE):
        raise PngError("not a png")
    position = len(PNG_SIGNATURE)
    while position + 12 <= len(data):
        length = struct.unpack(">I", data[position:position + 4])[0]
        chunk_type = data[position + 4:position + 8]
        end = position + 8 + length
        if end + 4 > len(data):
            raise PngError("truncated chunk")
        payload = data[position + 8:end]
        expected = struct.unpack(">I", data[end:end + 4])[0]
        if binascii.crc32(chunk_type + payload) & 0xFFFFFFFF != expected:
            raise PngError("bad chunk checksum")
        yield chunk_type, payload
        position = end + 4
    if position != len(data):
        raise PngError("trailing bytes")


def _paeth(left, up, upper_left):
    estimate = left + up - upper_left
    distance_left = abs(estimate - left)
    distance_up = abs(estimate - up)
    distance_upper_left = abs(estimate - upper_left)
    if distance_left <= distance_up and distance_left <= distance_upper_left:
        return left
    if distance_up <= distance_upper_left:
        return up
    return upper_left


def decode(data: bytes, max_bytes: int = MAX_IMAGE_BYTES) -> Image:
    """Decode a PNG accepted by validate() into raw rows.

    Supported: bit depth 8, colour types 0/2/4/6, no interlacing. Everything
    else raises PngError so callers fail closed rather than guess.
    """
    width, height = validate(data, max_bytes=max_bytes)
    header = None
    compressed = []
    saw_end = False
    for chunk_type, payload in _chunks(data):
        if header is None:
            if chunk_type != b"IHDR" or len(payload) != 13:
                raise PngError("missing ihdr")
            header = payload
            continue
        if chunk_type == b"IDAT":
            compressed.append(payload)
        elif chunk_type == b"IEND":
            saw_end = True
            break
    if header is None or not saw_end or not compressed:
        raise PngError("incomplete png")

    bit_depth = header[8]
    colour_type = header[9]
    compression = header[10]
    filter_method = header[11]
    interlace = header[12]
    if bit_depth != 8:
        raise PngError("unsupported bit depth")
    if compression != 0 or filter_method != 0 or interlace != 0:
        raise PngError("unsupported png")
    channels = _CHANNELS.get(colour_type)
    if channels is None:
        raise PngError("unsupported colour type")

    stride = width * channels
    expected = height * (1 + stride)
    if expected > MAX_DECODED_BYTES:
        raise PngError("decoded image too large")
    decompressor = zlib.decompressobj()
    try:
        raw = decompressor.decompress(b"".join(compressed), expected + 1)
    except zlib.error:
        raise PngError("bad image data") from None
    if (
        len(raw) != expected
        or not decompressor.eof
        or decompressor.unconsumed_tail
        or decompressor.unused_data
    ):
        raise PngError("bad image data")

    rows = bytearray(height * stride)
    previous = bytearray(stride)
    position = 0
    for row_index in range(height):
        filter_type = raw[position]
        position += 1
        line = bytearray(raw[position:position + stride])
        position += stride
        if filter_type == 0:
            pass
        elif filter_type == 1:
            for index in range(stride):
                left = line[index - channels] if index >= channels else 0
                line[index] = (line[index] + left) & 0xFF
        elif filter_type == 2:
            for index in range(stride):
                line[index] = (line[index] + previous[index]) & 0xFF
        elif filter_type == 3:
            for index in range(stride):
                left = line[index - channels] if index >= channels else 0
                line[index] = (line[index] + ((left + previous[index]) >> 1)) & 0xFF
        elif filter_type == 4:
            for index in range(stride):
                left = line[index - channels] if index >= channels else 0
                upper_left = (
                    previous[index - channels] if index >= channels else 0
                )
                line[index] = (
                    line[index] + _paeth(left, previous[index], upper_left)
                ) & 0xFF
        else:
            raise PngError("unsupported filter")
        start = row_index * stride
        rows[start:start + stride] = line
        previous = line
    return Image(width, height, channels, rows)


def orientation(width: int, height: int) -> str:
    if width > height:
        return "Landscape"
    if height > width:
        return "Portrait"
    return "Square"


def _rgb(image, index):
    if image.channels >= 3:
        return image.rows[index], image.rows[index + 1], image.rows[index + 2]
    value = image.rows[index]
    return value, value, value


def region_changed(
    before: Image,
    after: Image,
    x: int,
    y: int,
    radius: int = TAP_REGION_RADIUS,
    pixel_threshold: int = PIXEL_DIFF_THRESHOLD,
    changed_fraction: float = CHANGED_PIXEL_FRACTION,
) -> bool:
    """Return True when the tap neighbourhood differs materially.

    Comparing a decoded region avoids treating PNG compression differences as
    screen changes. The region is clipped at the image edges and the result is
    deterministic: changed pixels / total pixels > changed_fraction.
    """
    if before.width != after.width or before.height != after.height:
        return True
    if before.channels != after.channels:
        return True
    left = max(0, x - radius)
    right = min(before.width, x + radius + 1)
    top = max(0, y - radius)
    bottom = min(before.height, y + radius + 1)
    total = (right - left) * (bottom - top)
    if total <= 0:
        return True
    stride = before.width * before.channels
    changed = 0
    for row in range(top, bottom):
        row_start = row * stride
        for column in range(left, right):
            index = row_start + column * before.channels
            red_before, green_before, blue_before = _rgb(before, index)
            red_after, green_after, blue_after = _rgb(after, index)
            if (
                abs(red_before - red_after) > pixel_threshold
                or abs(green_before - green_after) > pixel_threshold
                or abs(blue_before - blue_after) > pixel_threshold
            ):
                changed += 1
    return (changed / total) > changed_fraction
