"""What a file is allowed to be.

A [Policy][sillybos.Policy] is a plain settings object: which formats may pass, and the
ceilings on size, pixels and pages. Two presets cover most uses. The numbers
in [DEFAULT][sillybos.DEFAULT] come from a real corpus of archival scans (the largest
page in it is 39 million pixels at 600 dpi; the longest book is 166 pages)
with room to spare; [STRICT][sillybos.STRICT] is for files from further away.
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

TIFF_PHOTOMETRICS: tuple[str, ...] = (
    "greyscale",
    "rgb",
    "palette",
    "cmyk",
    "ycbcr",
    "mask",
    "cielab",
    "icclab",
    "itulab",
    "cfa",
    "logl",
    "logluv",
    "linear-raw",
)
"""Every photometric interpretation a TIFF can declare, by name. A scanner
writes the first five (YCbCr is what a JPEG-compressed scan is); the rest
are colour models a scan never uses. A value outside this list is refused
whatever the policy says."""

TIFF_SUBSAMPLINGS: tuple[str, ...] = ("1x1", "2x1", "1x2", "2x2", "4x1", "1x4", "4x2", "2x4", "4x4")
"""Every chroma subsampling a YCbCr TIFF can declare, horizontal by
vertical. A scanner writes the first four; the factor-of-four paths are
the least exercised in libtiff (CVE-2026-4775)."""

TIFF_COMPRESSIONS: tuple[str, ...] = (
    "none",
    "ccitt",
    "lzw",
    "jpeg",
    "deflate",
    "packbits",
    "old-jpeg",
    "next",
    "thunderscan",
    "it8",
    "pixar",
    "jbig",
    "sgilog",
    "jpeg2000",
    "lerc",
    "lzma",
    "zstd",
    "webp",
    "jxl",
)
"""Every TIFF compression scheme the library knows, by name. A scanner
writes the first six. The rest are codecs in libtiff that a scan never
needs and that most of its security history lives in; a code outside this
list is refused whatever the policy says."""

PNG_COLOUR_TYPES: tuple[str, ...] = ("greyscale", "rgb", "palette", "greyscale-alpha", "rgba")
"""Every colour type a PNG can have, by name. A scanner writes greyscale or
RGB; the palette paths are where several of libpng's recent flaws were."""

PDF_FEATURES: tuple[str, ...] = ("javascript", "forms", "attachments", "launch")
"""Everything a PDF can carry that makes a viewer do something other than
draw the page: JavaScript, an interactive form, attached (embedded) files, and
a launch action that runs a program. A scanned book has none of them, so the
default policy refuses them all; a policy names the ones it will pass."""

PDF_IMAGE_CODECS: tuple[str, ...] = ("jpeg", "jpx", "jbig2", "ccitt")
"""Every codec a PDF's images can be coded with that hands the stream to a
decoder of its own inside poppler, by name: DCT (JPEG), JPX (JPEG 2000,
through OpenJPEG), JBIG2 and CCITT fax. Scanners, and the archives that
derive PDFs from scans, write all four, so the default allows them all; a
policy that knows its source never writes one refuses it by name. Each is
found by its filter's name in the file, not by listing the images:
`pdfimages -list` opens a JPX stream with OpenJPEG to describe it, which is
the decoder's code the check exists to keep from the file."""

MIB = 1024 * 1024


@dataclass(frozen=True)
class Policy:
    """The limits a file must sit inside to pass [sillybos.check][sillybos.check.check].

    Args:
        formats: Which of [FORMATS][sillybos.FORMATS] may pass. A file of any other
            format is refused whatever its name says.
        max_bytes: The largest file, in bytes. Checked before anything is
            read, so an enormous file is never handed to `pdfinfo`.
        max_pixels: The most pixels in any one page or frame once decoded.
            For a PDF page, the pixels it would render to at `render_dpi`.
            The default is the threshold at which Pillow warns of a
            decompression bomb, enforced here rather than left to a global
            that another library may have raised.
        max_side: The most pixels along either side of any one page, frame
            or tile. A pixel budget alone lets through a page a few pixels
            wide and a million tall, and an abnormally tall image is what
            drove libtiff's RGBA reader to write colour data to an
            arbitrary address (CVE-2025-9900). No scanner writes a side
            longer than a few tens of thousands of pixels: the default is
            three times the longest side in the corpus (9,933 pixels, A3 at
            600 dpi).
        max_pages: The most pages in a PDF, or frames in a multi-frame TIFF
            or animated PNG. Bounds the time and the memory a run takes,
            and stops the header walk itself on a file with a million
            empty frames.
        max_metadata_bytes: The largest block of metadata in an image: a
            PNG chunk other than image data, a TIFF tag's out-of-line data,
            a JPEG colour profile across its segments. A scan carries a few
            kilobytes of EXIF and a colour profile well under a megabyte;
            a block the size of the file is where parsers' quadratic paths
            and allocation flaws have been found (CVE-2026-96643,
            CVE-2023-6277). Pillow refuses a PNG text chunk over 1 MiB on
            its own; the default leaves room for a large profile or XMP.
        render_dpi: The resolution the PDF renderer will be run at, so a
            page's size in points can be turned into pixels before the
            renderer allocates them.
        name_must_match: Refuse a file whose extension says one allowed
            format and whose contents are another (a JPEG called
            `.png`). The readers would cope, but a file whose name lies
            is not one to trust, and the mismatch is the first thing an
            operator wants to know.
        jpeg_frames: Which of [JPEG_FRAMES][sillybos.JPEG_FRAMES] may pass. The default is
            what a scanner writes: baseline, extended and progressive. A
            lossless, hierarchical or arithmetic-coded frame goes down a
            path of the decoder that almost no file exercises; a lossless
            frame was the way into a heap overflow in Pillow's JPEG decoder
            (CVE-2026-112403). A multi-picture JPEG's pictures count as
            pages and are each read.
        png_colour_types: Which of [PNG_COLOUR_TYPES][sillybos.PNG_COLOUR_TYPES] may pass. The
            default is all five; a policy for scans alone can keep to
            greyscale and RGB, which closes libpng's palette paths
            (CVE-2025-64720, CVE-2025-66293, CVE-2026-33636).
        max_png_bit_depth: The deepest PNG sample. A scanner writes 8 bits;
            some archival software writes 16-bit greyscale, so the default
            allows it and the strict preset does not.
        allow_interlaced_png: Pass an Adam7-interlaced PNG. No scanner
            writes one, and the interlaced 16-bit path was the way into
            two libpng overflows (CVE-2025-65018, CVE-2026-22695), so the
            default refuses.
        tiff_photometrics: Which of [TIFF_PHOTOMETRICS][sillybos.TIFF_PHOTOMETRICS] may pass. The
            default is what a scanner writes: greyscale, RGB, palette, CMYK
            and YCbCr. Every frame of a file must share one.
        tiff_subsamplings: Which of [TIFF_SUBSAMPLINGS][sillybos.TIFF_SUBSAMPLINGS] a YCbCr TIFF
            may declare. The default is the four a scanner writes; the
            factor-of-four paths are where libtiff's most recent heap
            write was found (CVE-2026-4775).
        allow_tiled_tiff: Pass a TIFF laid out in tiles rather than strips.
            A scanner writes strips; digitisation and mapping software
            write tiles, so the default allows them and the strict preset
            does not. A tile is what the decoder allocates whole, so a
            tile is also held to `max_pixels` on its own; the tiled decode
            path is where two of Pillow's recent over-reads were
            (CVE-2026-112395, CVE-2026-112404).
        tiff_compressions: Which of [TIFF_COMPRESSIONS][sillybos.TIFF_COMPRESSIONS] may pass. The
            default is what a scanner writes: none, CCITT, LZW, JPEG,
            Deflate and PackBits. The other codecs are where most of
            libtiff's flaws have been found (PixarLog most recently,
            CVE-2026-12912), and a scan never needs them. Every frame of a
            file must use the same scheme.
        allow_encrypted_pdf: Pass a PDF that `pdfinfo` reports as
            encrypted. A scanned book never is, so the default refuses.
        pdf_features: Which of [PDF_FEATURES][sillybos.PDF_FEATURES] a PDF may carry:
            JavaScript, a form, attached files, a launch action. Each is a
            way for a document to make the viewer act rather than draw, and
            a scanned book has none, so the default allows none. Forms are
            read from `pdfinfo`'s report and attached files from
            `pdfdetach`'s, both of which see inside compressed object
            streams; a launch action is found by its name in the file,
            since no poppler tool reports one, so an action hidden in a
            compressed stream is not seen; JavaScript is looked for both
            ways.
        pdf_image_codecs: Which of [PDF_IMAGE_CODECS][sillybos.PDF_IMAGE_CODECS] a PDF's
            images may be coded with: JPEG, JPEG 2000, JBIG2 and CCITT.
            Each hands the stream to a decoder of its own inside poppler,
            and the JBIG2 decoder is where several of its flaws have been
            (CVE-2025-32365, CVE-2026-93312, CVE-2026-93313). Scanners and
            the archives that derive PDFs from scans write all four, so the
            default allows them all; refuse one only when you know your
            source never writes it. Each is found by its filter's name in
            the file, the way a launch action is, so a filter named only
            through an indirect reference inside a compressed object
            stream is not seen.
        pdfinfo_timeout: Seconds to give `pdfinfo` before giving up on a
            PDF, which is then refused. A crafted file can make a parser
            loop; a limit turns that into one file's failure.
    """

    formats: frozenset[str] = field(default_factory=lambda: frozenset(FORMATS))
    max_bytes: int = 512 * MIB
    max_pixels: int = 89_478_485
    max_side: int = 30_000
    max_pages: int = 500
    max_metadata_bytes: int = 4 * MIB
    render_dpi: int = 200
    name_must_match: bool = True
    jpeg_frames: frozenset[str] = field(
        default_factory=lambda: frozenset({"baseline", "extended", "progressive"})
    )
    png_colour_types: frozenset[str] = field(default_factory=lambda: frozenset(PNG_COLOUR_TYPES))
    max_png_bit_depth: int = 16
    allow_interlaced_png: bool = False
    allow_tiled_tiff: bool = True
    tiff_photometrics: frozenset[str] = field(
        default_factory=lambda: frozenset({"greyscale", "rgb", "palette", "cmyk", "ycbcr"})
    )
    tiff_subsamplings: frozenset[str] = field(
        default_factory=lambda: frozenset({"1x1", "2x1", "1x2", "2x2"})
    )
    tiff_compressions: frozenset[str] = field(
        default_factory=lambda: frozenset({"none", "ccitt", "lzw", "jpeg", "deflate", "packbits"})
    )
    allow_encrypted_pdf: bool = False
    pdf_features: frozenset[str] = frozenset()
    pdf_image_codecs: frozenset[str] = field(default_factory=lambda: frozenset(PDF_IMAGE_CODECS))
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
        unknown = set(self.png_colour_types) - set(PNG_COLOUR_TYPES)
        if unknown:
            raise ValueError(
                f"unknown PNG colour type(s) {sorted(unknown)}; "
                f"the types are {', '.join(PNG_COLOUR_TYPES)}"
            )
        if not self.png_colour_types:
            raise ValueError("a policy must allow at least one PNG colour type")
        if self.max_png_bit_depth not in (1, 2, 4, 8, 16):
            raise ValueError("max_png_bit_depth must be 1, 2, 4, 8 or 16")
        for field_name, known, what in (
            ("tiff_compressions", TIFF_COMPRESSIONS, "TIFF compression"),
            ("tiff_photometrics", TIFF_PHOTOMETRICS, "TIFF photometric interpretation"),
            ("tiff_subsamplings", TIFF_SUBSAMPLINGS, "TIFF subsampling"),
        ):
            chosen = getattr(self, field_name)
            unknown = set(chosen) - set(known)
            if unknown:
                raise ValueError(
                    f"unknown {what}(s) {sorted(unknown)}; the names are {', '.join(known)}"
                )
            if not chosen:
                raise ValueError(f"a policy must allow at least one {what}")
        unknown = set(self.pdf_features) - set(PDF_FEATURES)
        if unknown:
            raise ValueError(
                f"unknown PDF feature(s) {sorted(unknown)}; the features are {', '.join(PDF_FEATURES)}"
            )
        unknown = set(self.pdf_image_codecs) - set(PDF_IMAGE_CODECS)
        if unknown:
            raise ValueError(
                f"unknown PDF image codec(s) {sorted(unknown)}; "
                f"the codecs are {', '.join(PDF_IMAGE_CODECS)}"
            )
        for name in (
            "max_bytes",
            "max_pixels",
            "max_side",
            "max_pages",
            "max_metadata_bytes",
            "render_dpi",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")
        if self.pdfinfo_timeout <= 0:
            raise ValueError("pdfinfo_timeout must be positive")

    def allows(self, fmt: str) -> bool:
        """Whether `fmt` (a name from [FORMATS][sillybos.FORMATS]) may pass."""
        return fmt in self.formats


DEFAULT = Policy()
"""For files from a trusted laptop or your own scanner."""

STRICT = Policy(
    max_bytes=128 * MIB,
    max_pixels=50_000_000,
    max_side=15_000,
    max_pages=100,
    max_metadata_bytes=1 * MIB,
    max_png_bit_depth=8,
    allow_tiled_tiff=False,
)
"""For files from outside: smaller, shorter, and no more lenient on format."""
