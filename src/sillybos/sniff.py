"""What a file really is, from its first bytes.

An image library decides a file's format from its contents and then runs the
reader for that format, so a file's extension protects nothing: a PostScript
file named `page.png` reaches the PostScript reader. This module looks at
the same bytes first, and names the format, so that the check can refuse by
name before any reader runs.

The table names more formats than the library will ever pass. The extra
names exist for the reason text: "says PNG, is PostScript" tells an operator
more than "says PNG, is something else".
"""

from __future__ import annotations

HEAD_BYTES = 1024
"""How much of a file `sniff` needs. The longest signature here is
twelve bytes; the rest is slack for formats that put their mark later."""

# (name, offset, signature); checked in order, first match wins.
_SIGNATURES: tuple[tuple[str, int, bytes], ...] = (
    ("jpeg", 0, b"\xff\xd8\xff"),
    ("png", 0, b"\x89PNG\r\n\x1a\n"),
    ("tiff", 0, b"II*\x00"),
    ("tiff", 0, b"MM\x00*"),
    ("bigtiff", 0, b"II+\x00"),
    ("bigtiff", 0, b"MM\x00+"),
    ("pdf", 0, b"%PDF-"),
    ("postscript", 0, b"%!PS"),
    ("postscript", 0, b"\xc5\xd0\xd3\xc6"),  # DOS EPS binary header
    ("gif", 0, b"GIF87a"),
    ("gif", 0, b"GIF89a"),
    ("bmp", 0, b"BM"),
    ("ole", 0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),  # FlashPix, old Office
    ("psd", 0, b"8BPS"),
    ("jpeg2000", 0, b"\x00\x00\x00\x0cjP  \r\n\x87\n"),
    ("jpeg2000", 0, b"\xff\x4f\xff\x51"),
    ("zip", 0, b"PK\x03\x04"),
    ("gzip", 0, b"\x1f\x8b"),
    ("ico", 0, b"\x00\x00\x01\x00"),
    ("xml", 0, b"<?xml"),
    ("xml", 0, b"<svg"),
    ("pcx", 0, b"\x0a"),
)

_DESCRIPTIONS: dict[str, str] = {
    "jpeg": "JPEG",
    "png": "PNG",
    "tiff": "TIFF",
    "bigtiff": "BigTIFF",
    "pdf": "PDF",
    "postscript": "PostScript",
    "gif": "GIF",
    "bmp": "BMP",
    "ole": "an OLE compound file (FlashPix, or an old Office document)",
    "psd": "a Photoshop document",
    "jpeg2000": "JPEG 2000",
    "webp": "WebP",
    "heif": "HEIF or AVIF",
    "zip": "a zip archive",
    "gzip": "a gzip file",
    "ico": "a Windows icon",
    "xml": "XML (or SVG)",
    "pcx": "PCX",
}

_CLAIMS: dict[str, str] = {
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".jpe": "jpeg",
    ".jfif": "jpeg",
    ".png": "png",
    ".tif": "tiff",
    ".tiff": "tiff",
    ".pdf": "pdf",
}


def sniff(head: bytes) -> str | None:
    """Name the format of a file from its first bytes, or `None` if unknown.

    Args:
        head: The first `HEAD_BYTES` of the file (fewer, if the file is
            shorter).

    Returns:
        A lower-case name: one of [sillybos.FORMATS][], one of the other
            names the library knows only to refuse, or `None`.
    """
    for name, offset, signature in _SIGNATURES:
        if head[offset : offset + len(signature)] == signature:
            return name
    # RIFF containers and ISO base media files carry their type a few bytes in.
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in {b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1", b"avif", b"avis"}:
            return "heif"
    return None


def describe(name: str | None) -> str:
    """The format's name for a reason sentence: `"PostScript"`, `"a zip archive"`."""
    if name is None:
        return "an unknown format"
    return _DESCRIPTIONS.get(name, name)


def claimed_by(suffix: str) -> str | None:
    """What a file's extension says it is, as a name from [sillybos.FORMATS][].

    `None` for an extension the library does not map, including no
    extension at all: such a file makes no claim, so it cannot lie.
    """
    return _CLAIMS.get(suffix.lower())


FORMATS_KNOWN = frozenset(_DESCRIPTIONS)
"""Every name sniff() can return, for telling "not allowed" from "unknown"."""
