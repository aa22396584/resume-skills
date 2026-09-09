#!/usr/bin/env python3
"""Render the Portable Resume brand mark as PNG with the standard library only.

Design (clean-room, geometric, no vendor material):

* rounded square with a diagonal sky-blue to indigo gradient
* white ring (the bounded session context)
* white "resume" triangle inside the ring

``render_raw`` produces the filtered RGBA scanlines deterministically from pure
Python arithmetic; ``encode_png`` wraps them in IHDR/IDAT/IEND chunks through
``zlib`` + ``struct``. The committed ``assets/logo.png`` (512) and
``assets/icon.png`` (256) were written by this script. ``--check`` decodes the
committed files and compares their pixel data with a fresh render; pixel data
is compared rather than compressed bytes because deflate output may differ
between zlib implementations.

Usage:
    python3 scripts/render_brand_assets.py --write   # regenerate both assets
    python3 scripts/render_brand_assets.py --check   # verify committed assets
"""

from __future__ import annotations

import argparse
import struct
import sys
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ASSETS: dict[str, int] = {
    "assets/logo.png": 512,
    "assets/icon.png": 256,
}
GRADIENT_A = (14, 165, 233)  # #0EA5E9 sky-500 (brand colour)
GRADIENT_B = (99, 102, 241)  # #6366F1 indigo-500
WHITE = (255, 255, 255)
SUPERSAMPLE = 4
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def _inside_rounded_rect(x: float, y: float, lo: float, hi: float, radius: float) -> bool:
    if x < lo or x > hi or y < lo or y > hi:
        return False
    cx = min(max(x, lo + radius), hi - radius)
    cy = min(max(y, lo + radius), hi - radius)
    return (x - cx) ** 2 + (y - cy) ** 2 <= radius**2


def _inside_ring(x: float, y: float, cx: float, cy: float, r_outer: float, r_inner: float) -> bool:
    d2 = (x - cx) ** 2 + (y - cy) ** 2
    return r_inner**2 <= d2 <= r_outer**2


def _inside_triangle(x: float, y: float, pts: tuple[tuple[float, float], ...]) -> bool:
    (x1, y1), (x2, y2), (x3, y3) = pts

    def edge(ax: float, ay: float, bx: float, by: float) -> float:
        return (bx - ax) * (y - ay) - (by - ay) * (x - ax)

    e1 = edge(x1, y1, x2, y2)
    e2 = edge(x2, y2, x3, y3)
    e3 = edge(x3, y3, x1, y1)
    return (e1 >= 0 and e2 >= 0 and e3 >= 0) or (e1 <= 0 and e2 <= 0 and e3 <= 0)


def render_raw(size: int) -> bytes:
    """Return filter-type-0 RGBA scanlines (``size * (1 + size * 4)`` bytes)."""

    scale = size / 512.0
    pad = 32 * scale
    radius = 112 * scale
    cx = cy = size / 2.0
    ring_outer = 168 * scale
    ring_inner = 132 * scale
    # Resume triangle, optically centred inside the ring.
    tri = (
        (cx - 46 * scale, cy - 66 * scale),
        (cx - 46 * scale, cy + 66 * scale),
        (cx + 70 * scale, cy),
    )
    rows: list[bytes] = []
    ss = SUPERSAMPLE
    inv = 1.0 / (ss * ss)
    for py in range(size):
        row = bytearray()
        for px in range(size):
            acc_r = acc_g = acc_b = acc_a = 0.0
            for sy in range(ss):
                y = py + (sy + 0.5) / ss
                for sx in range(ss):
                    x = px + (sx + 0.5) / ss
                    if not _inside_rounded_rect(x, y, pad, size - pad, radius):
                        continue
                    t = (x + y) / (2.0 * size)
                    r = _lerp(GRADIENT_A[0], GRADIENT_B[0], t)
                    g = _lerp(GRADIENT_A[1], GRADIENT_B[1], t)
                    b = _lerp(GRADIENT_A[2], GRADIENT_B[2], t)
                    if _inside_ring(x, y, cx, cy, ring_outer, ring_inner) or _inside_triangle(
                        x, y, tri
                    ):
                        r, g, b = WHITE
                    acc_r += r
                    acc_g += g
                    acc_b += b
                    acc_a += 255.0
            a = acc_a * inv
            if a <= 0.0:
                row += b"\x00\x00\x00\x00"
                continue
            # Un-premultiply colour over the covered fraction.
            cov = a / 255.0
            row += bytes(
                (
                    int(round(acc_r * inv / cov)),
                    int(round(acc_g * inv / cov)),
                    int(round(acc_b * inv / cov)),
                    int(round(a)),
                )
            )
        rows.append(b"\x00" + bytes(row))
    return b"".join(rows)


def _chunk(kind: bytes, payload: bytes) -> bytes:
    body = kind + payload
    return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


def encode_png(size: int, raw: bytes) -> bytes:
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    idat = zlib.compress(raw, 9)
    return _PNG_SIGNATURE + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def render(size: int) -> bytes:
    return encode_png(size, render_raw(size))


def decode_png(data: bytes) -> tuple[int, int, bytes]:
    """Return (width, height, raw scanlines) of an 8-bit RGBA non-interlaced PNG."""

    if data[:8] != _PNG_SIGNATURE:
        raise ValueError("not a PNG")
    offset = 8
    ihdr: bytes | None = None
    idat: list[bytes] = []
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        body = data[offset + 8 : offset + 8 + length]
        crc = struct.unpack(">I", data[offset + 8 + length : offset + 12 + length])[0]
        if crc != (zlib.crc32(kind + body) & 0xFFFFFFFF):
            raise ValueError(f"bad CRC in {kind!r}")
        if kind == b"IHDR":
            ihdr = body
        elif kind == b"IDAT":
            idat.append(body)
        elif kind == b"IEND":
            break
        offset += 12 + length
    if ihdr is None or len(ihdr) != 13:
        raise ValueError("missing IHDR")
    width, height, depth, color_type, _, _, interlace = struct.unpack(">IIBBBBB", ihdr)
    if (depth, color_type, interlace) != (8, 6, 0):
        raise ValueError("unsupported PNG layout")
    return int(width), int(height), zlib.decompress(b"".join(idat))


def check() -> list[str]:
    """Return mismatch descriptions for committed assets (empty when they match)."""

    problems: list[str] = []
    for relative, size in ASSETS.items():
        path = REPO / relative
        if not path.is_file():
            problems.append(f"{relative}: missing")
            continue
        try:
            width, height, raw = decode_png(path.read_bytes())
        except (ValueError, zlib.error, struct.error) as error:
            problems.append(f"{relative}: undecodable ({error})")
            continue
        if (width, height) != (size, size):
            problems.append(f"{relative}: expected {size}x{size}, got {width}x{height}")
            continue
        if raw != render_raw(size):
            problems.append(f"{relative}: pixel data differs from a fresh render")
    return problems


def write() -> None:
    for relative, size in ASSETS.items():
        (REPO / relative).write_bytes(render(size))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="regenerate assets/*.png")
    mode.add_argument("--check", action="store_true", help="verify committed assets")
    args = parser.parse_args(argv)
    if args.write:
        write()
        print("BRAND_ASSETS WRITTEN " + " ".join(ASSETS))
        return 0
    problems = check()
    if problems:
        print("BRAND_ASSETS FAIL", file=sys.stderr)
        for problem in problems:
            print(f" - {problem}", file=sys.stderr)
        return 1
    print("BRAND_ASSETS PASS " + " ".join(ASSETS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
