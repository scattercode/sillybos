"""The hostile corpus, built by hand so that nothing hostile is checked in.

Every file here is made from bytes by code, at test time. The good files
are real (Pillow writes them; a PDF is written as the specification says),
and the bad ones are the shapes an attacker, or a broken scanner, produces:
a header that lies about the format, a header that claims a billion pixels,
a frame chain that loops, a PDF with a thousand pages or a page the size of
a wall. The tests are the library's claim made checkable.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

POSTSCRIPT = b"%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 100 100\n%%EOF\n"
GIF = b"GIF89a\x01\x00\x01\x00\x00\x00\x00;"
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 24
WEBP = b"RIFF\x1a\x00\x00\x00WEBPVP8 " + b"\x00" * 14
HEIC = b"\x00\x00\x00\x18ftypheic" + b"\x00" * 12
ZIP = b"PK\x03\x04" + b"\x00" * 26
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


# --- PNG ---------------------------------------------------------------------


def _chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def png(width: int, height: int, *, frames: int | None = None, extra: bytes = b"") -> bytes:
    """A PNG header with the given dimensions. No pixels: the check never reads them."""
    ihdr = _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    actl = _chunk(b"acTL", struct.pack(">II", frames, 0)) if frames is not None else b""
    return PNG_SIGNATURE + ihdr + extra + actl + _chunk(b"IDAT", b"") + _chunk(b"IEND", b"")


# --- JPEG --------------------------------------------------------------------


def _segment(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


def jpeg(
    width: int,
    height: int,
    *,
    before_sof: bytes = b"",
    sof: bool = True,
    marker: int = 0xC0,
    components: int = 1,
) -> bytes:
    """A JPEG header: SOI, a JFIF APP0, optional padding segments, a SOF (baseline by default)."""
    app0 = _segment(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
    layout = b"".join(bytes([n + 1, 0x11, 0]) for n in range(components))
    frame = _segment(marker, struct.pack(">BHHB", 8, height, width, components) + layout)
    return b"\xff\xd8" + app0 + before_sof + (frame if sof else b"") + b"\xff\xda\x00\x02\xff\xd9"


_MP_HEADER_AT = 2 + 18 + 4 + 4
"""Where the MP header starts in a picture built here: after SOI, APP0, the
APP2 marker and length, and the ``MPF`` identifier. Its offsets count from here."""


def mpo(
    pictures: list[tuple[int, int]],
    *,
    markers: list[int] | None = None,
    components: list[int] | None = None,
    declared: int | None = None,
    stray: bool = False,
    not_jpeg: bool = False,
    index: bytes | None = None,
) -> bytes:
    """A multi-picture JPEG: the first picture carries an MP index naming the rest.

    Each picture is a :func:`jpeg` header; ``markers`` and ``components``
    give each its SOF marker and component count. ``declared`` overrides
    the picture count the index states; ``stray`` points the last picture
    past the end of the file; ``not_jpeg`` flags the second picture's data
    format as something other than JPEG; ``index`` replaces the whole MP
    index (after the ``MPF`` identifier) with the given bytes.
    """
    n = len(pictures)
    markers = markers or [0xC0] * n
    components = components or [1] * n
    data_at = 8 + 2 + 3 * 12 + 4  # MP header, then the three-entry index, then the entries

    def build(entries: bytes) -> bytes:
        return (
            b"II*\x00"
            + struct.pack("<I", 8)
            + struct.pack("<H", 3)
            + struct.pack("<HHI", 0xB000, 7, 4)
            + b"0100"
            + struct.pack("<HHII", 0xB001, 4, 1, n if declared is None else declared)
            + struct.pack("<HHII", 0xB002, 7, len(entries), data_at)
            + struct.pack("<I", 0)
            + entries
        )

    bodies = [
        jpeg(w, h, marker=m, components=c)
        for (w, h), m, c in zip(pictures, markers, components, strict=True)
    ]
    # The first picture gains the APP2 segment, which moves everything after it.
    app2_size = 4 + 4 + len(build(b"\x00" * 16 * n))
    offsets = []
    position = 0
    for k, body in enumerate(bodies):
        offsets.append(position)
        position += len(body) + (app2_size if k == 0 else 0)
    entries = b""
    for k, body in enumerate(bodies):
        attribute = 0x01000000 if (not_jpeg and k == 1) else 0
        offset = 0 if k == 0 else offsets[k] - _MP_HEADER_AT
        if stray and k == n - 1:
            offset = 1 << 30
        entries += struct.pack("<IIIHH", attribute, len(body), offset, 0, 0)
    app2 = _segment(0xE2, b"MPF\x00" + (build(entries) if index is None else index))
    first = bodies[0][:20] + app2 + bodies[0][20:]  # after SOI and APP0
    return first + b"".join(bodies[1:])


def jpeg_padding(n: int) -> bytes:
    """``n`` empty comment segments, to pad a header out."""
    return _segment(0xFE, b"") * n


# --- TIFF --------------------------------------------------------------------


def tiff(
    frames: list[tuple[int, int]],
    *,
    endian: str = "<",
    loop_to_first: bool = False,
    dangling: bool = False,
    drop_height: bool = False,
    long_dims: bool = False,
) -> bytes:
    """A classic TIFF with one IFD per frame, holding just the two dimension tags.

    ``loop_to_first`` points the last IFD back at the first; ``dangling``
    points it past the end of the file; ``drop_height`` leaves the height
    out of the first frame; ``long_dims`` writes the dimensions as LONG
    rather than SHORT.
    """
    order = b"II" if endian == "<" else b"MM"
    header = order + struct.pack(endian + "HI", 42, 8)
    body = b""
    offset = 8
    first = 8
    for index, (width, height) in enumerate(frames):
        entries = []
        kind = 4 if long_dims else 3
        for tag, value in ((256, width), (257, height)):
            if tag == 257 and drop_height and index == 0:
                continue
            if long_dims:
                raw = struct.pack(endian + "I", value)
            else:
                raw = struct.pack(endian + "H", value) + b"\x00\x00"
            entries.append(struct.pack(endian + "HHI", tag, kind, 1) + raw)
        ifd_size = 2 + 12 * len(entries) + 4
        last = index == len(frames) - 1
        if not last:
            next_offset = offset + ifd_size
        elif loop_to_first:
            next_offset = first
        elif dangling:
            next_offset = 1 << 30
        else:
            next_offset = 0
        body += struct.pack(endian + "H", len(entries)) + b"".join(entries)
        body += struct.pack(endian + "I", next_offset)
        offset += ifd_size
    return header + body


# --- PDF ---------------------------------------------------------------------


def pdf(
    pages: int,
    width_pts: float = 595,
    height_pts: float = 842,
    *,
    sizes: list[tuple[float, float]] | None = None,
) -> bytes:
    """A minimal but well-formed PDF: ``pages`` empty pages of the given size, with an xref."""
    per_page = sizes or [(width_pts, height_pts)] * pages
    objects: list[bytes] = []
    kids = " ".join(f"{3 + i} 0 R" for i in range(pages))
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {pages} >>".encode())
    for w, h in per_page:
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {w:g} {h:g}] >>".encode())
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for position in offsets:
        out += f"{position:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return bytes(out)


def write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path
