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
        coding: For a JPEG, how its frame is coded, by a name from
            :data:`sillybos.JPEG_FRAMES` (``"baseline"``, ``"progressive"``,
            ``"lossless"``, ...). ``None`` for the other formats.
    """

    width: int
    height: int
    pages: int
    max_pixels: int
    complete: bool = True
    coding: str | None = None


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

# Start-of-frame markers, which carry the dimensions, and how each codes the
# image. C4 (DHT), C8 (JPG extension) and CC (DAC) share the range but are
# not frames. A scanner writes baseline or progressive frames; the rest are
# legal JPEG that no scanner produces and the decoder's rarest paths, and the
# policy says which may pass. The names are :data:`sillybos.JPEG_FRAMES`.
_FRAME_CODINGS = {
    0xC0: "baseline",
    0xC1: "extended",
    0xC2: "progressive",
    0xC3: "lossless",
    0xC5: "hierarchical",
    0xC6: "hierarchical",
    0xC7: "hierarchical",
    0xC9: "arithmetic",
    0xCA: "arithmetic",
    0xCB: "arithmetic",
    0xCD: "hierarchical",
    0xCE: "hierarchical",
    0xCF: "hierarchical",
}
# Markers with no length field.
_STANDALONE = {0x01, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8}
_APP2 = 0xE2
_MPF = b"MPF\x00"
_MP_NUMBER_OF_IMAGES = 0xB001
_MP_ENTRY = 0xB002


@dataclass(frozen=True)
class _Frame:
    width: int
    height: int
    coding: str
    components: int


def jpeg(f: Reader, size: int, limit: int) -> Header:
    """Read a JPEG's frame header, and every picture of a multi-picture file.

    The segments are walked to the first SOF marker, which carries the
    dimensions, the coding and the component count. An APP2 segment holding
    a Multi-Picture Format index (the MPO files that cameras and phones
    write, which Pillow steps through as frames) names further pictures by
    offset and size. Each is read the same way and counted as a page, and
    each must match the first in coding and components, because the decoder
    that sized its buffers for the first picture is the one that will decode
    the rest. As with a TIFF, the walk stops after ``limit + 1`` pictures.
    """
    first, pictures = _frame(f, size, 0, "frame header", index=True)
    pages = 1
    max_pixels = first.width * first.height
    for number, offset in enumerate(pictures, start=2):
        if pages > limit:
            return Header(first.width, first.height, pages, max_pixels, False, first.coding)
        if not 2 <= offset < size:
            raise HeaderError(f"picture {number} lies outside the file")
        picture, _ = _frame(f, size, offset, f"picture {number}", index=False)
        if picture.coding != first.coding:
            raise HeaderError(
                f"picture {number} is {picture.coding} where picture 1 is {first.coding}"
            )
        if picture.components != first.components:
            raise HeaderError(
                f"picture {number} has {picture.components} components "
                f"where picture 1 has {first.components}"
            )
        pages += 1
        max_pixels = max(max_pixels, picture.width * picture.height)
    return Header(first.width, first.height, pages, max_pixels, coding=first.coding)


def _frame(f: Reader, size: int, start: int, what: str, *, index: bool) -> tuple[_Frame, list[int]]:
    """Walk one picture's segments from ``start`` to its frame header.

    Returns the frame and, when ``index`` is set and the picture carries a
    Multi-Picture index, the offset in the file of every further picture it
    names.
    """
    f.seek(start)
    if _read_exactly(f, 2, "header") != b"\xff\xd8":
        raise HeaderError(f"no JPEG start-of-image marker in the {what}")
    pictures: list[int] = []
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
        if marker in _FRAME_CODINGS:
            if length < 8:
                raise HeaderError("the frame header is too short to hold the dimensions")
            _precision, height, width, components = struct.unpack(
                ">BHHB", _read_exactly(f, 6, "frame header")
            )
            if height == 0:
                # Legal (a DNL marker supplies it later) and never seen in a
                # scan; refusing it keeps every decoder's rarest path closed.
                raise HeaderError("the height is deferred to a DNL marker")
            _dimensions(width, height, what)
            return _Frame(width, height, _FRAME_CODINGS[marker], components), pictures
        payload = f.tell()
        next_offset = payload + length - 2
        if next_offset > size:
            raise HeaderError("a segment runs past the end of the file")
        if (
            index
            and marker == _APP2
            and length >= 2 + len(_MPF)
            and _read_exactly(f, len(_MPF), "APP2 segment") == _MPF
        ):
            if pictures:
                raise HeaderError("two multi-picture indexes")
            data = _read_exactly(f, length - 2 - len(_MPF), "multi-picture index")
            pictures = _mp_index(data, payload + len(_MPF))
        f.seek(next_offset)
    raise HeaderError(f"no frame header in the first {MAX_SEGMENTS} segments")


def _mp_index(data: bytes, base: int) -> list[int]:
    """Read the MP Index IFD of a Multi-Picture Format segment.

    ``data`` is the segment after its ``MPF`` identifier: a small TIFF of
    its own, whose offsets count from its first byte, which sits at ``base``
    in the file. Returns the offset in the file of every picture after the
    first. An index that names one picture, or none, is an ordinary JPEG,
    which is how Pillow reads it too. Each entry also carries the picture's
    size, which is ignored here as it is by Pillow's reader (and written
    wrongly, from the third picture on, by Pillow's writer): a decoder that
    never reads a field cannot be steered by it.
    """
    if len(data) < 8:
        raise HeaderError("the multi-picture index is too short")
    endian = {b"II*\x00": "<", b"MM\x00*": ">"}.get(data[:4])
    if endian is None:
        raise HeaderError("the multi-picture index has no byte-order mark")
    (offset,) = struct.unpack(endian + "I", data[4:8])
    if offset + 2 > len(data):
        raise HeaderError("the multi-picture index lies outside its segment")
    (count,) = struct.unpack(endian + "H", data[offset : offset + 2])
    if offset + 2 + count * 12 > len(data):
        raise HeaderError("the multi-picture index runs past its segment")
    number = 1
    entries: list[tuple[int, int, int, int, int]] = []
    for position in range(offset + 2, offset + 2 + count * 12, 12):
        tag, _kind, n, raw = struct.unpack(endian + "HHI4s", data[position : position + 12])
        if tag == _MP_NUMBER_OF_IMAGES:
            (number,) = struct.unpack(endian + "I", raw)
        elif tag == _MP_ENTRY:
            (at,) = struct.unpack(endian + "I", raw)
            if n % 16 or at + n > len(data):
                raise HeaderError("the multi-picture entries lie outside their segment")
            entries = [
                struct.unpack(endian + "IIIHH", data[at + k : at + k + 16]) for k in range(0, n, 16)
            ]
    if number <= 1 and len(entries) <= 1:
        return []
    if number != len(entries):
        raise HeaderError(
            f"the multi-picture index names {number:,} pictures but lists {len(entries):,}"
        )
    pictures = []
    for position, (attribute, _length, offset, _dep1, _dep2) in enumerate(entries[1:], start=2):
        if (attribute >> 24) & 0x07:
            raise HeaderError(f"picture {position} is not coded as JPEG")
        pictures.append(base + offset)
    return pictures


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
