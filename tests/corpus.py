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


def png(
    width: int,
    height: int,
    *,
    frames: int | None = None,
    extra: bytes = b"",
    after_idat: bytes = b"",
    idats: int = 1,
    depth: int = 8,
    colour: int = 2,
    interlace: int = 0,
    methods: tuple[int, int] = (0, 0),
) -> bytes:
    """A PNG header with the given dimensions. No pixels: the check never reads them.

    ``extra`` goes before the image data, ``after_idat`` between the image
    data and IEND; ``idats`` is how many empty image-data chunks to write.
    The IHDR's bit depth, colour type, interlace method and (compression,
    filter) methods default to an 8-bit RGB image as a scanner writes one.
    """
    fields = (width, height, depth, colour, *methods, interlace)
    ihdr = _chunk(b"IHDR", struct.pack(">IIBBBBB", *fields))
    actl = _chunk(b"acTL", struct.pack(">II", frames, 0)) if frames is not None else b""
    idat = _chunk(b"IDAT", b"") * idats
    return PNG_SIGNATURE + ihdr + extra + actl + idat + after_idat + _chunk(b"IEND", b"")


def png_chunk(kind: bytes, size: int) -> bytes:
    """One PNG chunk of the given type, ``size`` zero bytes long."""
    return _chunk(kind, b"\x00" * size)


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


def jpeg_profile(size: int) -> bytes:
    """``size`` bytes of colour profile, split across APP2 segments as a writer splits it."""
    per_segment = 65533 - 2 - len(b"ICC_PROFILE\x00")
    pieces = [b"\x00" * min(per_segment, size - at) for at in range(0, size, per_segment)]
    return b"".join(
        _segment(0xE2, b"ICC_PROFILE\x00" + bytes([n + 1, len(pieces)]) + piece)
        for n, piece in enumerate(pieces)
    )


# --- TIFF --------------------------------------------------------------------


Tile = tuple[int | None, int | None]
"""(TileWidth, TileLength) for a hand-made TIFF frame; ``None`` leaves that tag out."""

Layout = tuple[int, int, int | tuple[int, ...]]
"""(photometric, samples per pixel, bits per sample) for a hand-made TIFF frame;
the bits may be one value for every sample or one per sample."""


def tiff(
    frames: list[tuple[int, int]],
    *,
    endian: str = "<",
    loop_to_first: bool = False,
    dangling: bool = False,
    drop_height: bool = False,
    long_dims: bool = False,
    compression: int | list[int | None] | None = None,
    layout: Layout | list[Layout | None] | None = None,
    tags: list[tuple[int, int, bytes]] | None = None,
    data_outside: bool = False,
    tile: Tile | list[Tile | None] | None = None,
    subsampling: tuple[int, int] | list[tuple[int, int] | None] | None = None,
) -> bytes:
    """A classic TIFF with one IFD per frame, holding the two dimension tags.

    ``loop_to_first`` points the last IFD back at the first; ``dangling``
    points it past the end of the file; ``drop_height`` leaves the height
    out of the first frame; ``long_dims`` writes the dimensions as LONG
    rather than SHORT; ``compression`` adds a Compression tag with that
    value to every frame, or one value per frame from a list; ``layout``
    likewise adds PhotometricInterpretation, SamplesPerPixel and
    BitsPerSample, the last written out of line when there are more than
    two samples; ``tags`` adds further entries to every frame as (tag, type,
    data), written out of line when the data is over four bytes;
    ``data_outside`` points all out-of-line data past the end of the file;
    ``tile`` adds TileWidth and TileLength tags (either may be ``None`` to
    leave it out) to every frame, or one pair per frame from a list;
    ``subsampling`` likewise adds a YCbCrSubSampling tag.
    """
    order = b"II" if endian == "<" else b"MM"
    header = order + struct.pack(endian + "HI", 42, 8)
    body = b""
    offset = 8
    first = 8
    for index, (width, height) in enumerate(frames):
        # (tag, kind, count, inline field or out-of-line data)
        entries: list[tuple[int, int, int, bytes]] = []
        kind = 4 if long_dims else 3
        for tag, value in ((256, width), (257, height)):
            if tag == 257 and drop_height and index == 0:
                continue
            if long_dims:
                raw = struct.pack(endian + "I", value)
            else:
                raw = struct.pack(endian + "H", value) + b"\x00\x00"
            entries.append((tag, kind, 1, raw))
        code = compression[index] if isinstance(compression, list) else compression
        if code is not None:
            entries.append((259, 3, 1, struct.pack(endian + "H", code) + b"\x00\x00"))
        this = layout[index] if isinstance(layout, list) else layout
        if this is not None:
            photometric, samples, bits = this
            depths = (bits,) * samples if isinstance(bits, int) else bits
            entries.append((262, 3, 1, struct.pack(endian + "H", photometric) + b"\x00\x00"))
            entries.append((277, 3, 1, struct.pack(endian + "H", samples) + b"\x00\x00"))
            packed = struct.pack(endian + f"{len(depths)}H", *depths)
            entries.append((258, 3, len(depths), packed.ljust(4, b"\x00")))
        this_tile = tile[index] if isinstance(tile, list) else tile
        if this_tile is not None:
            for tag, side in zip((322, 323), this_tile, strict=True):
                if side is not None:
                    entries.append((tag, 4, 1, struct.pack(endian + "I", side)))
        this_subsampling = subsampling[index] if isinstance(subsampling, list) else subsampling
        if this_subsampling is not None:
            entries.append((530, 3, 2, struct.pack(endian + "HH", *this_subsampling)))
        for tag, type_, data in tags or []:
            per_value = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 12: 8}.get(type_, 1)
            entries.append((tag, type_, len(data) // per_value, data.ljust(4, b"\x00")))
        entries.sort()
        ifd_size = 2 + 12 * len(entries) + 4
        out_of_line = b""
        fields = b""
        for tag, kind, count, data in entries:
            if len(data) > 4:
                where = (1 << 30) if data_outside else offset + ifd_size + len(out_of_line)
                fields += struct.pack(endian + "HHII", tag, kind, count, where)
                out_of_line += data
            else:
                fields += struct.pack(endian + "HHI", tag, kind, count) + data
        total = ifd_size + len(out_of_line)
        last = index == len(frames) - 1
        if not last:
            next_offset = offset + total
        elif loop_to_first:
            next_offset = first
        elif dangling:
            next_offset = 1 << 30
        else:
            next_offset = 0
        body += struct.pack(endian + "H", len(entries)) + fields
        body += struct.pack(endian + "I", next_offset) + out_of_line
        offset += total
    return header + body


def tiled_tiff(width: int, height: int, tile: int) -> bytes:
    """A complete 8-bit greyscale uncompressed TIFF in ``tile`` x ``tile`` tiles, pixels and all.

    Unlike :func:`tiff`, this one decodes: the agreement test opens it with
    Pillow, which reads tiled files through libtiff.
    """
    across, down = -(-width // tile), -(-height // tile)
    count = across * down
    tile_bytes = tile * tile
    entries = [
        (256, 4, 1, width),
        (257, 4, 1, height),
        (258, 3, 1, 8),
        (259, 3, 1, 1),
        (262, 3, 1, 1),
        (277, 3, 1, 1),
        (322, 4, 1, tile),
        (323, 4, 1, tile),
    ]
    ifd_size = 2 + 12 * (len(entries) + 2) + 4
    offsets_at = 8 + ifd_size
    counts_at = offsets_at + 4 * count
    pixels_at = counts_at + 4 * count
    fields = b""
    for tag, kind, n, value in entries:
        raw = struct.pack("<I", value) if kind == 4 else struct.pack("<H", value) + b"\x00\x00"
        fields += struct.pack("<HHI", tag, kind, n) + raw
    fields += struct.pack("<HHII", 324, 4, count, offsets_at)
    fields += struct.pack("<HHII", 325, 4, count, counts_at)
    ifd = struct.pack("<H", len(entries) + 2) + fields + struct.pack("<I", 0)
    offsets = b"".join(struct.pack("<I", pixels_at + k * tile_bytes) for k in range(count))
    counts = struct.pack("<I", tile_bytes) * count
    return b"II*\x00" + struct.pack("<I", 8) + ifd + offsets + counts + bytes(tile_bytes * count)


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
