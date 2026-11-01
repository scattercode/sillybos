"""Width, height and page count from a JPEG, PNG or TIFF header, without a decoder.

Each reader here is a few dozen lines that understand just enough of its
format to find the dimensions and count the frames. None of them decodes a
pixel, and none of them is a decoder's own header code: the point of the
library is that a file is judged before any of that runs. Every read is
bounded, every offset is checked against the file's size, and a TIFF's
chain of frames is walked with a limit and a memory of where it has been,
so that a crafted file cannot send the reader round in a circle or off the
end of the file.

A header the reader cannot make sense of raises :class:`HeaderError` with a
reason; the check turns that into a refusal. "Cannot make sense of" is
deliberately broad: a file that is not shaped the way its format says is not
one to hand to a decoder, whatever a more forgiving reader would do with it.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import IO

Reader = IO[bytes]

MAX_SEGMENTS = 4096
"""How many JPEG segments or PNG chunks to walk before giving up: a bound
on the time a crafted file can cost. A real scan has tens."""

MAX_DIMENSION = 1 << 31
"""A width or height at or above this is not a dimension; it is a bug or
an attack, and refused before the multiplication that would overflow a C
decoder."""


class HeaderError(ValueError):
    """The header is not shaped the way its format says."""


@dataclass(frozen=True)
class Header:
    """What a header reader found.

    Attributes:
        width: Pixels across, for the first frame.
        height: Pixels down, for the first frame.
        pages: Frames in the file (1 for an ordinary image). For a TIFF with
            more frames than ``limit``, ``limit + 1``: the walk stopped.
        max_pixels: The most pixels in any one frame the reader looked at.
        complete: ``False`` if the walk stopped at the limit, so ``pages``
            and ``max_pixels`` describe only the frames it reached.
    """

    width: int
    height: int
    pages: int
    max_pixels: int
    complete: bool = True


def _read_exactly(f: Reader, n: int, what: str) -> bytes:
    data = f.read(n)
    if len(data) != n:
        raise HeaderError(f"the file ends inside its {what}")
    return data


def _dimensions(width: int, height: int, what: str) -> None:
    if width < 1 or height < 1:
        raise HeaderError(f"the {what} gives a zero width or height")
    if width >= MAX_DIMENSION or height >= MAX_DIMENSION:
        raise HeaderError(f"the {what} gives a width or height of {max(width, height):,}")


# --- JPEG -------------------------------------------------------------------

# Start-of-frame markers, which carry the dimensions. C4 (DHT), C8 (JPG
# extension) and CC (DAC) share the range but are not frames.
_SOF = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
# Markers with no length field.
_STANDALONE = {0x01, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8}


def jpeg(f: Reader, size: int, limit: int) -> Header:
    """Read a JPEG's frame header: walk the segments to the first SOF marker."""
    del limit  # a JPEG has one frame
    f.seek(0)
    if _read_exactly(f, 2, "header") != b"\xff\xd8":
        raise HeaderError("no JPEG start-of-image marker")
    for _ in range(MAX_SEGMENTS):
        byte = _read_exactly(f, 1, "segment marker")
        if byte != b"\xff":
            raise HeaderError("a segment does not start with a marker")
        marker = _read_exactly(f, 1, "segment marker")[0]
        while marker == 0xFF:  # fill bytes before a marker are allowed
            marker = _read_exactly(f, 1, "segment marker")[0]
        if marker in _STANDALONE:
            continue
        if marker in (0xD9, 0xDA):
            raise HeaderError("the image data starts before any frame header")
        (length,) = struct.unpack(">H", _read_exactly(f, 2, "segment length"))
        if length < 2:
            raise HeaderError("a segment claims a length shorter than its own length field")
        if marker in _SOF:
            if length < 7:
                raise HeaderError("the frame header is too short to hold the dimensions")
            _precision, height, width = struct.unpack(">BHH", _read_exactly(f, 5, "frame header"))
            if height == 0:
                # Legal (a DNL marker supplies it later) and never seen in a
                # scan; refusing it keeps every decoder's rarest path closed.
                raise HeaderError("the height is deferred to a DNL marker")
            _dimensions(width, height, "frame header")
            return Header(width, height, 1, width * height)
        next_offset = f.tell() + length - 2
        if next_offset > size:
            raise HeaderError("a segment runs past the end of the file")
        f.seek(next_offset)
    raise HeaderError(f"no frame header in the first {MAX_SEGMENTS} segments")


# --- PNG --------------------------------------------------------------------


def png(f: Reader, size: int, limit: int) -> Header:
    """Read a PNG's IHDR, and count the frames of an animated one (acTL)."""
    del limit  # the frame count is one field; no walk to bound
    f.seek(8)  # the signature was checked by sniff
    length, kind = struct.unpack(">I4s", _read_exactly(f, 8, "first chunk"))
    if kind != b"IHDR" or length != 13:
        raise HeaderError("the first chunk is not a 13-byte IHDR")
    width, height = struct.unpack(">II", _read_exactly(f, 8, "IHDR"))
    _dimensions(width, height, "IHDR")
    f.seek(13 - 8 + 4, 1)  # the rest of IHDR, and its CRC
    pages = 1
    for _ in range(MAX_SEGMENTS):
        head = f.read(8)
        if len(head) < 8:
            break
        length, kind = struct.unpack(">I4s", head)
        if kind in (b"IDAT", b"IEND"):
            break
        if kind == b"acTL" and length >= 4:
            (pages,) = struct.unpack(">I", _read_exactly(f, 4, "acTL"))
            if pages < 1:
                raise HeaderError("acTL gives zero frames")
            break
        next_offset = f.tell() + length + 4
        if next_offset > size:
            raise HeaderError("a chunk runs past the end of the file")
        f.seek(next_offset)
    return Header(width, height, pages, width * height)


# --- TIFF -------------------------------------------------------------------

_TIFF_SHORT = 3
_TIFF_LONG = 4
_IMAGE_WIDTH = 256
_IMAGE_LENGTH = 257


def tiff(f: Reader, size: int, limit: int) -> Header:
    """Walk a classic TIFF's IFD chain: dimensions per frame, frames counted.

    Stops after ``limit + 1`` frames and reports that many, so that a file
    with a million frames costs the time of ``limit`` reads, not a million.
    An IFD that points at itself, at an earlier one, or past the end of the
    file is an error, not a loop.
    """
    f.seek(0)
    order = _read_exactly(f, 2, "header")
    endian = {b"II": "<", b"MM": ">"}.get(order)
    if endian is None:
        raise HeaderError("no TIFF byte-order mark")
    (magic,) = struct.unpack(endian + "H", _read_exactly(f, 2, "header"))
    if magic != 42:
        raise HeaderError("not a classic TIFF (BigTIFF is refused by name)")
    (offset,) = struct.unpack(endian + "I", _read_exactly(f, 4, "header"))
    seen: set[int] = set()
    first: tuple[int, int] | None = None
    max_pixels = 0
    pages = 0
    while offset != 0:
        if pages > limit:
            if first is None:
                return _no_frames()
            return Header(first[0], first[1], pages, max_pixels, complete=False)
        if offset in seen:
            raise HeaderError("the frame chain loops back on itself")
        if offset + 2 > size or offset < 8:
            raise HeaderError("a frame directory lies outside the file")
        seen.add(offset)
        f.seek(offset)
        (count,) = struct.unpack(endian + "H", _read_exactly(f, 2, "frame directory"))
        if offset + 2 + count * 12 + 4 > size:
            raise HeaderError("a frame directory runs past the end of the file")
        width = height = None
        for _ in range(count):
            tag, kind, n, raw = struct.unpack(
                endian + "HHI4s", _read_exactly(f, 12, "frame directory")
            )
            if tag not in (_IMAGE_WIDTH, _IMAGE_LENGTH):
                continue
            if n != 1:
                raise HeaderError("a dimension tag holds more than one value")
            if kind == _TIFF_SHORT:
                # A SHORT sits in the first two bytes of the field in either
                # byte order: the value is left-justified, not right-aligned.
                (value,) = struct.unpack(endian + "H", raw[:2])
            elif kind == _TIFF_LONG:
                (value,) = struct.unpack(endian + "I", raw)
            else:
                raise HeaderError("a dimension tag is neither SHORT nor LONG")
            if tag == _IMAGE_WIDTH:
                width = value
            else:
                height = value
        if width is None or height is None:
            raise HeaderError(f"frame {pages + 1} has no width or height")
        _dimensions(width, height, f"frame {pages + 1}")
        pages += 1
        max_pixels = max(max_pixels, width * height)
        if first is None:
            first = (width, height)
        (offset,) = struct.unpack(endian + "I", _read_exactly(f, 4, "frame directory"))
    if first is None:
        return _no_frames()
    return Header(first[0], first[1], pages, max_pixels)


def _no_frames() -> Header:
    raise HeaderError("the file has no frames")


READERS = {"jpeg": jpeg, "png": png, "tiff": tiff}
"""The header reader for each raster format in :data:`sillybos.FORMATS`."""
