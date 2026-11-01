"""Width, height and page count from a JPEG, PNG or TIFF header, without a decoder.

Each reader here is a few dozen lines that understand just enough of its
format to find the dimensions and count the frames. None of them decodes a
pixel, and none of them is a decoder's own header code: the point of the
library is that a file is judged before any of that runs. Every read is
bounded, every offset is checked against the file's size, and a TIFF's
chain of frames is walked with a limit and a memory of where it has been,
so that a crafted file cannot send the reader round in a circle or off the
end of the file.

A header the reader cannot make sense of raises `HeaderError` with a
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

MAX_IDAT_CHUNKS = 1 << 18
"""How many image-data chunks a PNG may have before the walk gives up.
libpng writes one per 8 KiB, so a file at the default byte limit has a
quarter of this; the bound is on the time a crafted file can cost."""

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
            more frames than `limit`, `limit + 1`: the walk stopped.
        max_pixels: The most pixels in any one frame the reader looked at.
        complete: `False` if the walk stopped at the limit, so `pages`
            and `max_pixels` describe only the frames it reached.
        coding: For a JPEG, how its frame is coded, by a name from
            [sillybos.JPEG_FRAMES][] (`"baseline"`, `"progressive"`,
            `"lossless"`, ...). `None` for the other formats.
        compression: For a TIFF, how its frames are compressed, by a name
            from [sillybos.TIFF_COMPRESSIONS][] (`"none"`, `"lzw"`,
            `"jpeg"`, ...); every frame the reader looked at uses it.
            `None` for the other formats.
        metadata: The largest block of metadata the reader passed over, as
            (what it is, its size in bytes): a PNG chunk other than image
            data, a TIFF tag's out-of-line data, a JPEG colour profile
            across its segments. `None` if there was none.
        colour: For a PNG, its colour type by a name from
            [sillybos.PNG_COLOUR_TYPES][]; for a TIFF, its photometric
            interpretation by a name from [sillybos.TIFF_PHOTOMETRICS][].
            `None` for a JPEG.
        depth: For a PNG or TIFF, its bits per sample. `None` for a JPEG.
        interlaced: For a PNG, whether it is Adam7 interlaced.
        subsampling: For a YCbCr TIFF, its chroma subsampling as
            `"2x2"` (horizontal by vertical). `None` otherwise.
        tile: For a tiled TIFF, the (width, height) of its largest tile,
            which is what the decoder allocates whole. `None` for a TIFF
            in strips and for the other formats.
    """

    width: int
    height: int
    pages: int
    max_pixels: int
    complete: bool = True
    coding: str | None = None
    compression: str | None = None
    metadata: tuple[str, int] | None = None
    colour: str | None = None
    depth: int | None = None
    interlaced: bool = False
    tile: tuple[int, int] | None = None
    subsampling: str | None = None


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
# policy says which may pass. The names are [sillybos.JPEG_FRAMES][].
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
_ICC = b"ICC_PROFILE\x00"
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
    the rest. As with a TIFF, the walk stops after `limit + 1` pictures.
    """
    first, pictures, profile = _frame(f, size, 0, "frame header", index=True)
    metadata = ("JPEG colour profile", profile) if profile else None
    pages = 1
    max_pixels = first.width * first.height
    for number, offset in enumerate(pictures, start=2):
        if pages > limit:
            return Header(
                first.width, first.height, pages, max_pixels, False, first.coding, metadata=metadata
            )
        if not 2 <= offset < size:
            raise HeaderError(f"picture {number} lies outside the file")
        picture, _, _ = _frame(f, size, offset, f"picture {number}", index=False)
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
    return Header(
        first.width, first.height, pages, max_pixels, coding=first.coding, metadata=metadata
    )


def _frame(
    f: Reader, size: int, start: int, what: str, *, index: bool
) -> tuple[_Frame, list[int], int]:
    """Walk one picture's segments from `start` to its frame header.

    Returns the frame and, when `index` is set, the offset in the file of
    every further picture a Multi-Picture index names and the total bytes
    of colour profile carried in APP2 segments.
    """
    f.seek(start)
    if _read_exactly(f, 2, "header") != b"\xff\xd8":
        raise HeaderError(f"no JPEG start-of-image marker in the {what}")
    pictures: list[int] = []
    profile = 0
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
            return _Frame(width, height, _FRAME_CODINGS[marker], components), pictures, profile
        payload = f.tell()
        next_offset = payload + length - 2
        if next_offset > size:
            raise HeaderError("a segment runs past the end of the file")
        if index and marker == _APP2 and length >= 2 + len(_MPF):
            ident = _read_exactly(f, len(_MPF), "APP2 segment")
            if ident == _MPF:
                if pictures:
                    raise HeaderError("two multi-picture indexes")
                data = _read_exactly(f, length - 2 - len(_MPF), "multi-picture index")
                pictures = _mp_index(data, payload + len(_MPF))
            elif ident == _ICC[:4] and length >= 4 + len(_ICC):
                # After the identifier come the segment's number and the
                # count of segments, then the profile bytes themselves.
                if _read_exactly(f, len(_ICC) - 4, "APP2 segment") == _ICC[4:]:
                    profile += length - 4 - len(_ICC)
        f.seek(next_offset)
    raise HeaderError(f"no frame header in the first {MAX_SEGMENTS} segments")


def _mp_index(data: bytes, base: int) -> list[int]:
    """Read the MP Index IFD of a Multi-Picture Format segment.

    `data` is the segment after its `MPF` identifier: a small TIFF of
    its own, whose offsets count from its first byte, which sits at `base`
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

# Colour types by IHDR value, named as [sillybos.PNG_COLOUR_TYPES][] names
# them, with the bit depths the specification allows each.
_COLOUR_TYPES = {
    0: ("greyscale", {1, 2, 4, 8, 16}),
    2: ("rgb", {8, 16}),
    3: ("palette", {1, 2, 4, 8}),
    4: ("greyscale-alpha", {8, 16}),
    6: ("rgba", {8, 16}),
}


def png(f: Reader, size: int, limit: int) -> Header:
    """Read a PNG's IHDR, count the frames of an animated one, and size every other chunk.

    The walk goes to IEND, not just to the first image-data chunk, because
    a decoder reads the chunks after the image data too (an `eXIf` or a
    text chunk may sit there). Image-data chunks are skipped, not read, and
    counted against `MAX_IDAT_CHUNKS`; every other chunk counts
    against `MAX_SEGMENTS`, and the largest is reported so that the
    policy can bound it.
    """
    del limit  # the frame count is one field; no walk to bound
    f.seek(8)  # the signature was checked by sniff
    length, kind = struct.unpack(">I4s", _read_exactly(f, 8, "first chunk"))
    if kind != b"IHDR" or length != 13:
        raise HeaderError("the first chunk is not a 13-byte IHDR")
    width, height, depth, colour_type, compression, filter_method, interlace = struct.unpack(
        ">IIBBBBB", _read_exactly(f, 13, "IHDR")
    )
    _dimensions(width, height, "IHDR")
    if colour_type not in _COLOUR_TYPES:
        raise HeaderError(f"IHDR gives a colour type of {colour_type}")
    colour, depths = _COLOUR_TYPES[colour_type]
    if depth not in depths:
        raise HeaderError(f"IHDR gives a bit depth of {depth} for a {colour} image")
    if compression != 0 or filter_method != 0:
        raise HeaderError("IHDR gives a compression or filter method other than 0")
    if interlace > 1:
        raise HeaderError(f"IHDR gives an interlace method of {interlace}")
    f.seek(4, 1)  # the IHDR CRC
    pages = 1
    chunks = idats = 0
    metadata: tuple[str, int] | None = None
    while True:
        head = f.read(8)
        if len(head) < 8:
            break
        length, kind = struct.unpack(">I4s", head)
        next_offset = f.tell() + length + 4
        if next_offset > size:
            raise HeaderError("a chunk runs past the end of the file")
        if kind == b"IDAT":
            idats += 1
            if idats > MAX_IDAT_CHUNKS:
                raise HeaderError(f"more than {MAX_IDAT_CHUNKS:,} image-data chunks")
        else:
            chunks += 1
            if chunks > MAX_SEGMENTS:
                raise HeaderError(f"more than {MAX_SEGMENTS:,} chunks besides the image data")
            if not kind.isalpha() or not kind.isascii():
                raise HeaderError("a chunk type is not four letters")
            if length and (metadata is None or length > metadata[1]):
                metadata = (f"PNG {kind.decode('ascii')} chunk", length)
            if kind == b"IEND":
                break
            if kind == b"acTL" and length >= 4:
                (pages,) = struct.unpack(">I", _read_exactly(f, 4, "acTL"))
                if pages < 1:
                    raise HeaderError("acTL gives zero frames")
        f.seek(next_offset)
    return Header(
        width,
        height,
        pages,
        width * height,
        metadata=metadata,
        colour=colour,
        depth=depth,
        interlaced=interlace == 1,
    )


# --- TIFF -------------------------------------------------------------------

_TIFF_SHORT = 3
_TIFF_LONG = 4
_IMAGE_WIDTH = 256
_IMAGE_LENGTH = 257
_BITS_PER_SAMPLE = 258
_COMPRESSION = 259
_PHOTOMETRIC = 262
_SAMPLES_PER_PIXEL = 277
_TILE_WIDTH = 322
_TILE_LENGTH = 323
_YCBCR_SUBSAMPLING = 530
_YCBCR = 6
_SINGLE_VALUE_TAGS = (
    _IMAGE_WIDTH,
    _IMAGE_LENGTH,
    _COMPRESSION,
    _PHOTOMETRIC,
    _SAMPLES_PER_PIXEL,
    _TILE_WIDTH,
    _TILE_LENGTH,
)
_TAG_NAMES = {
    _IMAGE_WIDTH: "a dimension tag",
    _IMAGE_LENGTH: "a dimension tag",
    _COMPRESSION: "a compression tag",
    _PHOTOMETRIC: "a photometric tag",
    _SAMPLES_PER_PIXEL: "a samples-per-pixel tag",
    _TILE_WIDTH: "a tile tag",
    _TILE_LENGTH: "a tile tag",
}
_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4}
"""Bytes per value for each TIFF field type (BYTE, ASCII, SHORT, LONG,
RATIONAL, ...). A type not listed is counted as one byte, which is how
libtiff treats a type it does not know."""
_TAG_LABELS = {
    270: "ImageDescription",
    273: "StripOffsets",
    279: "StripByteCounts",
    324: "TileOffsets",
    325: "TileByteCounts",
    700: "XMP",
    33723: "IPTC",
    34377: "Photoshop",
    34665: "Exif",
    34675: "ICC profile",
}
MAX_SAMPLES = 64
"""The most samples per pixel a BitsPerSample tag may list. A scan has one,
three or four; the bound keeps the out-of-line read small."""

# Photometric interpretations by tag value, named as
# [sillybos.TIFF_PHOTOMETRICS][] names them. White-is-zero and
# black-is-zero are both greyscale: the same buffer, inverted.
_PHOTOMETRICS = {
    0: "greyscale",
    1: "greyscale",
    2: "rgb",
    3: "palette",
    4: "mask",
    5: "cmyk",
    6: "ycbcr",
    8: "cielab",
    9: "icclab",
    10: "itulab",
    32803: "cfa",
    32844: "logl",
    32845: "logluv",
    34892: "linear-raw",
}
_SUBSAMPLING_FACTORS = {1, 2, 4}

# Compression schemes by their tag value, named as [sillybos.TIFF_COMPRESSIONS][]
# names them. A scanner writes the first six. A code not listed here is
# refused outright: the policy can only name what the library knows.
_COMPRESSIONS = {
    1: "none",
    2: "ccitt",  # modified Huffman RLE
    3: "ccitt",  # T.4 (Group 3)
    4: "ccitt",  # T.6 (Group 4)
    32771: "ccitt",  # word-aligned RLE
    5: "lzw",
    7: "jpeg",
    8: "deflate",  # Adobe
    32946: "deflate",  # PKZIP-style
    32773: "packbits",
    6: "old-jpeg",
    32766: "next",
    32809: "thunderscan",
    32895: "it8",
    32896: "it8",
    32897: "it8",
    32898: "it8",
    32908: "pixar",  # PixarFilm
    32909: "pixar",  # PixarLog
    34661: "jbig",
    34676: "sgilog",
    34677: "sgilog",
    34712: "jpeg2000",
    34887: "lerc",
    34925: "lzma",
    50000: "zstd",
    50001: "webp",
    50002: "jxl",
    52546: "jxl",
}


def tiff(f: Reader, size: int, limit: int) -> Header:
    """Walk a classic TIFF's IFD chain: dimensions and compression per frame, frames counted.

    Stops after `limit + 1` frames and reports that many, so that a file
    with a million frames costs the time of `limit` reads, not a million.
    An IFD that points at itself, at an earlier one, or past the end of the
    file is an error, not a loop. Every frame must share the first frame's
    compression scheme and pixel layout (photometric interpretation, samples
    per pixel, bits per sample): a decoder that set itself up for the first
    frame is the one that reads the rest, and no scanner mixes them within
    one file.
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
    compression: str | None = None
    layout: tuple[str, int, int] | None = None
    metadata: tuple[str, int] | None = None
    tile: tuple[int, int] | None = None
    subsampling: str | None = None
    max_pixels = 0
    pages = 0
    while offset != 0:
        if pages > limit:
            if first is None:
                return _no_frames()
            assert layout is not None  # noqa: S101 - set with the first frame
            return Header(
                first[0],
                first[1],
                pages,
                max_pixels,
                False,
                compression=compression,
                metadata=metadata,
                tile=tile,
                colour=layout[0],
                depth=layout[2],
                subsampling=subsampling,
            )
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
        # The tags' defaults: uncompressed, white is zero, one sample per pixel, 1 bit.
        values: dict[int, int | None] = {
            _COMPRESSION: 1,
            _PHOTOMETRIC: 0,
            _SAMPLES_PER_PIXEL: 1,
            _TILE_WIDTH: None,
            _TILE_LENGTH: None,
        }
        bits: tuple[int, bytes] | None = None  # (count, field) to resolve after the directory
        factors = (2, 2)  # the subsampling tag's default
        for _ in range(count):
            tag, kind, n, raw = struct.unpack(
                endian + "HHI4s", _read_exactly(f, 12, "frame directory")
            )
            data_size = n * _TYPE_SIZES.get(kind, 1)
            if data_size > 4:
                # The field holds an offset to the data. A count that would
                # put it past the end of the file is what makes a decoder
                # allocate for nothing (CVE-2023-6277).
                (where,) = struct.unpack(endian + "I", raw)
                if where < 8 or where + data_size > size:
                    raise HeaderError(f"frame {pages + 1}'s tag {tag:,} data lies outside the file")
                if metadata is None or data_size > metadata[1]:
                    label = _TAG_LABELS.get(tag)
                    name = f"TIFF tag {tag:,}" + (f" ({label})" if label else "")
                    metadata = (name, data_size)
            if tag == _BITS_PER_SAMPLE:
                if kind != _TIFF_SHORT:
                    raise HeaderError("a bits-per-sample tag is not SHORT")
                if n < 1 or n > MAX_SAMPLES:
                    raise HeaderError(f"a bits-per-sample tag lists {n:,} samples")
                bits = (n, raw)
                continue
            if tag == _YCBCR_SUBSAMPLING:
                if kind != _TIFF_SHORT or n != 2:
                    raise HeaderError("a subsampling tag is not two SHORTs")
                horizontal, vertical = struct.unpack(endian + "HH", raw)
                if horizontal not in _SUBSAMPLING_FACTORS or vertical not in _SUBSAMPLING_FACTORS:
                    raise HeaderError(
                        f"frame {pages + 1} gives a subsampling of {horizontal}x{vertical}"
                    )
                factors = (horizontal, vertical)
                continue
            if tag not in _SINGLE_VALUE_TAGS:
                continue
            what = _TAG_NAMES[tag]
            if n != 1:
                raise HeaderError(f"{what} holds more than one value")
            if kind == _TIFF_SHORT:
                # A SHORT sits in the first two bytes of the field in either
                # byte order: the value is left-justified, not right-aligned.
                (value,) = struct.unpack(endian + "H", raw[:2])
            elif kind == _TIFF_LONG:
                (value,) = struct.unpack(endian + "I", raw)
            else:
                raise HeaderError(f"{what} is neither SHORT nor LONG")
            if tag == _IMAGE_WIDTH:
                width = value
            elif tag == _IMAGE_LENGTH:
                height = value
            else:
                values[tag] = value
        if width is None or height is None:
            raise HeaderError(f"frame {pages + 1} has no width or height")
        _dimensions(width, height, f"frame {pages + 1}")
        (next_offset,) = struct.unpack(endian + "I", _read_exactly(f, 4, "frame directory"))
        tile_width, tile_length = values[_TILE_WIDTH], values[_TILE_LENGTH]
        if (tile_width is None) != (tile_length is None):
            raise HeaderError(f"frame {pages + 1} has a tile width or length but not both")
        if tile_width is not None and tile_length is not None:
            _dimensions(tile_width, tile_length, f"frame {pages + 1}'s tile")
            if tile is None or tile_width * tile_length > tile[0] * tile[1]:
                tile = (tile_width, tile_length)
        depth = _bits_per_sample(f, size, endian, bits, pages + 1)
        photometric, samples = values[_PHOTOMETRIC], values[_SAMPLES_PER_PIXEL]
        assert photometric is not None and samples is not None  # noqa: S101 - defaults above
        colour = _PHOTOMETRICS.get(photometric)
        if colour is None:
            raise HeaderError(
                f"frame {pages + 1} uses photometric interpretation {photometric:,}, "
                "which is not one this library knows"
            )
        if photometric == _YCBCR:
            this_subsampling = f"{factors[0]}x{factors[1]}"
            if subsampling is None:
                subsampling = this_subsampling
            elif this_subsampling != subsampling:
                raise HeaderError(
                    f"frame {pages + 1} is subsampled {this_subsampling} "
                    f"where frame 1 is subsampled {subsampling}"
                )
        this_layout = (colour, samples, depth)
        if layout is None:
            layout = this_layout
        elif this_layout != layout:
            raise HeaderError(
                f"frame {pages + 1} is {_describe_layout(this_layout)} "
                f"where frame 1 is {_describe_layout(layout)}"
            )
        code = values[_COMPRESSION]
        scheme = _COMPRESSIONS.get(code) if code is not None else None
        if scheme is None:
            raise HeaderError(
                f"frame {pages + 1} uses compression code {code:,}, which is not one this "
                "library knows"
            )
        if compression is None:
            compression = scheme
        elif scheme != compression:
            raise HeaderError(
                f"frame {pages + 1} is compressed with {scheme} where frame 1 is "
                f"compressed with {compression}"
            )
        pages += 1
        max_pixels = max(max_pixels, width * height)
        if first is None:
            first = (width, height)
        offset = next_offset
    if first is None:
        return _no_frames()
    assert layout is not None  # noqa: S101 - set with the first frame
    return Header(
        first[0],
        first[1],
        pages,
        max_pixels,
        compression=compression,
        metadata=metadata,
        tile=tile,
        colour=layout[0],
        depth=layout[2],
        subsampling=subsampling,
    )


def _bits_per_sample(
    f: Reader, size: int, endian: str, bits: tuple[int, bytes] | None, frame: int
) -> int:
    """The one bit depth a frame's samples share, or 1 if the tag is absent.

    One or two values sit in the tag's own field; more sit at an offset the
    field holds, which is checked against the file before it is read.
    Samples of different depths are legal TIFF that no decoder here
    accepts, so they are a refusal.
    """
    if bits is None:
        return 1
    count, field = bits
    if count <= 2:
        values = struct.unpack(endian + f"{count}H", field[: 2 * count])
    else:
        (where,) = struct.unpack(endian + "I", field)
        if where + 2 * count > size or where < 8:  # pragma: no cover - the entry walk checks first
            raise HeaderError(f"frame {frame}'s bits per sample lie outside the file")
        f.seek(where)
        values = struct.unpack(endian + f"{count}H", _read_exactly(f, 2 * count, "bits per sample"))
    if len(set(values)) != 1:
        raise HeaderError(f"frame {frame} gives different bit depths per sample")
    return int(values[0])


def _describe_layout(layout: tuple[str, int, int]) -> str:
    colour, samples, depth = layout
    plural = "" if samples == 1 else "s"
    return f"{colour}, {samples} sample{plural} of {depth} bits"


def _no_frames() -> Header:
    raise HeaderError("the file has no frames")


READERS = {"jpeg": jpeg, "png": png, "tiff": tiff}
"""The header reader for each raster format in [sillybos.FORMATS][]."""
