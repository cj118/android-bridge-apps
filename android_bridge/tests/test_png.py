"""Bounded PNG decoding and deterministic tap-region comparison."""

import binascii
import os
import struct
import sys
import unittest
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(os.path.dirname(HERE), "app")
sys.path.insert(0, APP_DIR)

import pngcheck  # noqa: E402


def chunk(kind, payload):
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)
    )


def make_png(w, h, blocks=(), filter_type=0):
    base = bytes((245, 245, 245, 255)) * w
    raw = bytearray()
    previous = bytes(w * 4)
    for y in range(h):
        line = bytearray(base)
        for x1, y1, x2, y2, red, green, blue, alpha in blocks:
            if y1 <= y < y2:
                line[max(0, x1) * 4:min(w, x2) * 4] = bytes(
                    (red, green, blue, alpha)
                ) * max(0, min(w, x2) - max(0, x1))
        if filter_type == 0:
            filtered = bytes(line)
        elif filter_type == 1:
            filtered = bytearray(len(line))
            for index, value in enumerate(line):
                left = line[index - 4] if index >= 4 else 0
                filtered[index] = (value - left) & 0xFF
            filtered = bytes(filtered)
        elif filter_type == 2:
            filtered = bytes((value - previous[index]) & 0xFF
                             for index, value in enumerate(line))
        else:
            raise AssertionError("filter helper only supports 0-2")
        raw.append(filter_type)
        raw.extend(filtered)
        previous = bytes(line)
    header = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 6))
        + chunk(b"IEND", b"")
    )


class PngTests(unittest.TestCase):
    def test_decode_solid_image(self):
        image = pngcheck.decode(make_png(10, 6))
        self.assertEqual((image.width, image.height, image.channels), (10, 6, 4))
        self.assertEqual(len(image.rows), 10 * 6 * 4)

    def test_decode_sub_and_up_filters(self):
        for filter_type in (0, 1, 2):
            with self.subTest(filter_type=filter_type):
                image = pngcheck.decode(make_png(8, 4, filter_type=filter_type))
                self.assertEqual(image.width, 8)

    def test_orientation_labels(self):
        self.assertEqual(pngcheck.orientation(1920, 1200), "Landscape")
        self.assertEqual(pngcheck.orientation(1200, 1920), "Portrait")
        self.assertEqual(pngcheck.orientation(100, 100), "Square")

    def test_unchanged_region(self):
        before = pngcheck.decode(make_png(100, 100))
        after = pngcheck.decode(make_png(100, 100))
        self.assertFalse(pngcheck.region_changed(before, after, 50, 50))

    def test_changed_region(self):
        before = pngcheck.decode(make_png(100, 100))
        after = pngcheck.decode(
            make_png(100, 100, blocks=[(40, 40, 60, 60, 0, 0, 0, 255)])
        )
        self.assertTrue(pngcheck.region_changed(before, after, 50, 50))

    def test_change_outside_region_is_ignored(self):
        before = pngcheck.decode(make_png(200, 200))
        after = pngcheck.decode(
            make_png(200, 200, blocks=[(10, 10, 20, 20, 0, 0, 0, 255)])
        )
        self.assertFalse(pngcheck.region_changed(before, after, 150, 150))

    def test_dimension_change_is_changed(self):
        before = pngcheck.decode(make_png(100, 100))
        after = pngcheck.decode(make_png(120, 90))
        self.assertTrue(pngcheck.region_changed(before, after, 50, 50))

    def test_invalid_images_fail_closed(self):
        cases = (
            b"",
            b"not-a-png",
            make_png(10, 10)[:-8],
        )
        for data in cases:
            with self.subTest(data=data[:8]):
                with self.assertRaises(pngcheck.PngError):
                    pngcheck.decode(data)

    def test_unsupported_png_shape_fails_closed(self):
        header = struct.pack(">IIBBBBB", 10, 10, 16, 6, 0, 0, 0)
        data = (
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", header)
            + chunk(b"IEND", b"")
        )
        with self.assertRaises(pngcheck.PngError):
            pngcheck.decode(data)


    def test_small_target_change_is_detected(self):
        before = pngcheck.decode(make_png(200, 200))
        after = pngcheck.decode(
            make_png(200, 200, blocks=[(95, 95, 105, 105, 0, 0, 0, 255)])
        )
        self.assertTrue(pngcheck.region_changed(before, after, 100, 100))


if __name__ == "__main__":
    unittest.main()
