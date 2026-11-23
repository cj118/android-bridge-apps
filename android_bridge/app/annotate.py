"""Dependency-free PNG annotation: coordinate grid, crop and tap marker.

The bridge image has no font or drawing library. Everything here is plain
Python over pngcheck.Image rows, so the add-on image stays stdlib-only.
"""

from __future__ import annotations

import binascii
import struct
import zlib

import pngcheck

GRID_STEP = 100
GRID_MAJOR = 200
GRID_BAND = (0, 0, 0)
GRID_COLOUR = (255, 214, 0)
LABEL_TEXT = (255, 255, 255)
LABEL_BACK = (0, 0, 0)
MARKER_COLOUR = (255, 40, 40)
MARKER_BACK = (0, 0, 0)

# 5x7 digits. Labels are coordinates, so digits are all the font needs.
_FONT = {
    "0": ("01110", "10001", "10011", "10101", "11001", "10001", "01110"),
    "1": ("00100", "01100", "00100", "00100", "00100", "00100", "01110"),
    "2": ("01110", "10001", "00001", "00010", "00100", "01000", "11111"),
    "3": ("11111", "00010", "00100", "00010", "00001", "10001", "01110"),
    "4": ("00010", "00110", "01010", "10010", "11111", "00010", "00010"),
    "5": ("11111", "10000", "11110", "00001", "00001", "10001", "01110"),
    "6": ("00110", "01000", "10000", "11110", "10001", "10001", "01110"),
    "7": ("11111", "00001", "00010", "00100", "01000", "01000", "01000"),
    "8": ("01110", "10001", "10001", "01110", "10001", "10001", "01110"),
    "9": ("01110", "10001", "10001", "01111", "00001", "00010", "01100"),
}


def _rgba(image):
    """Return (mutable RGBA bytes, width, height)."""
    width, height = image.width, image.height
    if image.channels == 4:
        return bytearray(image.rows), width, height
    source = image.rows
    out = bytearray(width * height * 4)
    if image.channels == 3:
        out[0::4] = source[0::3]
        out[1::4] = source[1::3]
        out[2::4] = source[2::3]
        out[3::4] = b"\xff" * (width * height)
    elif image.channels == 2:
        out[0::4] = source[0::2]
        out[1::4] = source[0::2]
        out[2::4] = source[0::2]
        out[3::4] = source[1::2]
    else:
        out[0::4] = source
        out[1::4] = source
        out[2::4] = source
        out[3::4] = b"\xff" * (width * height)
    return out, width, height


def _set(buffer, width, height, x, y, colour):
    if 0 <= x < width and 0 <= y < height:
        index = (y * width + x) * 4
        buffer[index:index + 3] = bytes(colour)
        buffer[index + 3] = 255


def _fill(buffer, width, height, left, top, right, bottom, colour):
    left = max(0, left)
    top = max(0, top)
    right = min(width, right)
    bottom = min(height, bottom)
    if left >= right or top >= bottom:
        return
    pixel = bytes(colour) + b"\xff"
    for y in range(top, bottom):
        start = (y * width + left) * 4
        buffer[start:start + (right - left) * 4] = pixel * (right - left)


def _line(buffer, width, height, left, top, right, bottom, thickness, colour):
    """Axis-aligned line centred on the coordinate, with the given width."""
    half = thickness // 2
    if left == right:
        _fill(buffer, width, height, left - half, top - half,
              left - half + thickness, bottom + half + 1, colour)
    else:
        _fill(buffer, width, height, left - half, top - half,
              right + half + 1, top - half + thickness, colour)


def _text(buffer, width, height, x, y, text, scale, colour, back):
    glyph_width = 5 * scale
    gap = scale
    text_width = len(text) * (glyph_width + gap) - gap
    _fill(buffer, width, height, x - 2, y - 2,
          x + text_width + 2, y + 7 * scale + 2, back)
    for index, character in enumerate(text):
        pattern = _FONT.get(character)
        if pattern is None:
            continue
        origin = x + index * (glyph_width + gap)
        for row, bits in enumerate(pattern):
            for column, bit in enumerate(bits):
                if bit == "1":
                    _fill(
                        buffer, width, height,
                        origin + column * scale,
                        y + row * scale,
                        origin + (column + 1) * scale,
                        y + (row + 1) * scale,
                        colour,
                    )


def add_grid(image, device_width, device_height, offset_x=0, offset_y=0):
    """Draw a 100 device-px grid with device-coordinate labels."""
    buffer, width, height = _rgba(image)
    lines = []
    for gx in range(0, device_width + 1, GRID_STEP):
        local = gx - offset_x
        if 0 <= local < width:
            major = gx % GRID_MAJOR == 0
            lines.append((local, major, gx, True))
    for gy in range(0, device_height + 1, GRID_STEP):
        local = gy - offset_y
        if 0 <= local < height:
            major = gy % GRID_MAJOR == 0
            lines.append((local, major, gy, False))
    for local, major, _value, vertical in lines:
        thickness = 4 if major else 2
        if vertical:
            _line(buffer, width, height, local, 0, local, height,
                  thickness + 2, GRID_BAND)
            _line(buffer, width, height, local, 0, local, height,
                  thickness, GRID_COLOUR)
        else:
            _line(buffer, width, height, 0, local, width, local,
                  thickness + 2, GRID_BAND)
            _line(buffer, width, height, 0, local, width, local,
                  thickness, GRID_COLOUR)
    for local, major, value, vertical in lines:
        if vertical:
            _text(buffer, width, height, local + 3, 3, str(value),
                  3 if major else 2, LABEL_TEXT, LABEL_BACK)
        elif value != 0:
            _text(buffer, width, height, 3, local + 2, str(value),
                  3 if major else 2, LABEL_TEXT, LABEL_BACK)
    return buffer, width, height


def grid_png(image, device_width, device_height):
    buffer, width, height = add_grid(
        image, device_width, device_height
    )
    return encode(width, height, buffer)


def crop(image, left, top, width, height):
    buffer, source_width, _source_height = _rgba(image)
    row_bytes = width * 4
    out = bytearray(row_bytes * height)
    for row in range(height):
        start = ((top + row) * source_width + left) * 4
        out[row * row_bytes:(row + 1) * row_bytes] = buffer[
            start:start + row_bytes
        ]
    return pngcheck.Image(width, height, 4, out)


def region_png(image, left, top, width, height):
    piece = crop(image, left, top, width, height)
    buffer, out_width, out_height = add_grid(
        piece, image.width, image.height, offset_x=left, offset_y=top
    )
    return encode(out_width, out_height, buffer)


def _circle(buffer, width, height, x, y, radius, thickness, colour):
    outer = radius + thickness // 2 + 1
    inner = radius - thickness // 2
    for dy in range(-outer, outer + 1):
        for dx in range(-outer, outer + 1):
            distance_squared = dx * dx + dy * dy
            if inner * inner <= distance_squared <= outer * outer:
                _set(buffer, width, height, x + dx, y + dy, colour)


def marker_crop(image, x, y, size=320):
    """A full-resolution crop around a point with a crosshair and ring."""
    half = size // 2
    left = min(max(0, x - half), max(0, image.width - size))
    top = min(max(0, y - half), max(0, image.height - size))
    width = min(size, image.width - left)
    height = min(size, image.height - top)
    piece = crop(image, left, top, width, height)
    buffer, out_width, out_height = _rgba(piece)
    mark_x = x - left
    mark_y = y - top
    arm = 24
    for thickness, colour in ((7, MARKER_BACK), (3, MARKER_COLOUR)):
        _line(buffer, out_width, out_height,
              max(0, mark_x - arm), mark_y, min(out_width - 1, mark_x + arm),
              mark_y, thickness, colour)
        _line(buffer, out_width, out_height,
              mark_x, max(0, mark_y - arm), mark_x,
              min(out_height - 1, mark_y + arm), thickness, colour)
        _circle(buffer, out_width, out_height, mark_x, mark_y, 20,
                thickness, colour)
    return encode(out_width, out_height, buffer)


def encode(width, height, buffer):
    stride = width * 4
    raw = bytearray()
    for row in range(height):
        raw.append(0)
        raw += buffer[row * stride:(row + 1) * stride]
    compressed = zlib.compress(bytes(raw), 6)

    def chunk(kind, payload):
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        pngcheck.PNG_SIGNATURE
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", compressed)
        + chunk(b"IEND", b"")
    )
