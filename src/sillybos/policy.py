"""What a file is allowed to be.

A :class:`Policy` is a plain settings object: which formats may pass, and the
ceilings on size, pixels and pages. Two presets cover most uses. The numbers
in :data:`DEFAULT` come from a real corpus of archival scans (the largest
page in it is 39 million pixels at 600 dpi; the longest book is 166 pages)
with room to spare; :data:`STRICT` is for files from further away.
"""

from __future__ import annotations

from dataclasses import dataclass, field

FORMATS: tuple[str, ...] = ("jpeg", "png", "tiff", "pdf")
"""The only formats the library will ever pass: the ones a scan can be.
Everything else is refused by name. Adding a format is adding attack surface,
so one is added only when someone shows a scan in it."""

JPEG_FRAMES: tuple[str, ...] = (
    "baseline",
    "extended",
    "progressive",
    "lossless",
    "hierarchical",
    "arithmetic",
)
"""Every way a JPEG frame can be coded, as its SOF marker says. A scanner
writes the first three. The rest are legal, rare, and the decoder's least
exercised code."""

MIB = 1024 * 1024


@dataclass(frozen=True)
class Policy:
    """The limits a file must sit inside to pass :func:`sillybos.check`.

    Args:
        formats: Which of :data:`FORMATS` may pass. A file of any other
            format is refused whatever its name says.
        max_bytes: The largest file, in bytes. Checked before anything is
            read, so an enormous file is never handed to ``pdfinfo``.
        max_pixels: The most pixels in any one page or frame once decoded.
            For a PDF page, the pixels it would render to at ``render_dpi``.
            The default is the threshold at which Pillow warns of a
            decompression bomb, enforced here rather than left to a global
            that another library may have raised.
        max_pages: The most pages in a PDF, or frames in a multi-frame TIFF
            or animated PNG. Bounds the time and the memory a run takes,
            and stops the header walk itself on a file with a million
            empty frames.
        render_dpi: The resolution the PDF renderer will be run at, so a
            page's size in points can be turned into pixels before the
            renderer allocates them.
        name_must_match: Refuse a file whose extension says one allowed
            format and whose contents are another (a JPEG called
            ``.png``). The readers would cope, but a file whose name lies
            is not one to trust, and the mismatch is the first thing an
            operator wants to know.
        jpeg_frames: Which of :data:`JPEG_FRAMES` may pass. The default is
            what a scanner writes: baseline, extended and progressive. A
            lossless, hierarchical or arithmetic-coded frame goes down a
            path of the decoder that almost no file exercises; a lossless
            frame was the way into a heap overflow in Pillow's JPEG decoder
            (CVE-2026-112403). A multi-picture JPEG's pictures count as
            pages and are each read.
        allow_encrypted_pdf: Pass a PDF that ``pdfinfo`` reports as
            encrypted. A scanned book never is, so the default refuses.
        pdfinfo_timeout: Seconds to give ``pdfinfo`` before giving up on a
            PDF, which is then refused. A crafted file can make a parser
            loop; a limit turns that into one file's failure.
    """

    formats: frozenset[str] = field(default_factory=lambda: frozenset(FORMATS))
    max_bytes: int = 512 * MIB
    max_pixels: int = 89_478_485
    max_pages: int = 500
    render_dpi: int = 200
    name_must_match: bool = True
    jpeg_frames: frozenset[str] = field(
        default_factory=lambda: frozenset({"baseline", "extended", "progressive"})
    )
    allow_encrypted_pdf: bool = False
    pdfinfo_timeout: float = 30.0

    def __post_init__(self) -> None:
        unknown = set(self.formats) - set(FORMATS)
        if unknown:
            raise ValueError(
                f"unknown format(s) {sorted(unknown)}; the formats are {', '.join(FORMATS)}"
            )
        if not self.formats:
            raise ValueError("a policy must allow at least one format")
        unknown = set(self.jpeg_frames) - set(JPEG_FRAMES)
        if unknown:
            raise ValueError(
                f"unknown JPEG frame coding(s) {sorted(unknown)}; "
                f"the codings are {', '.join(JPEG_FRAMES)}"
            )
        if not self.jpeg_frames:
            raise ValueError("a policy must allow at least one JPEG frame coding")
        for name in ("max_bytes", "max_pixels", "max_pages", "render_dpi"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")
        if self.pdfinfo_timeout <= 0:
            raise ValueError("pdfinfo_timeout must be positive")

    def allows(self, fmt: str) -> bool:
        """Whether ``fmt`` (a name from :data:`FORMATS`) may pass."""
        return fmt in self.formats


DEFAULT = Policy()
"""For files from a trusted laptop or your own scanner."""

STRICT = Policy(
    max_bytes=128 * MIB,
    max_pixels=50_000_000,
    max_pages=100,
)
"""For files from outside: smaller, shorter, and no more lenient on format."""
