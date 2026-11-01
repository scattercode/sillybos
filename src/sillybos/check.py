"""The check itself: one function, one verdict.

:func:`check` runs the steps in the order that keeps the cheapest and safest
first, and stops handing the file to anything further once it has a reason
to refuse it:

1. The file's size, from the file system. Over the limit, nothing reads it
   but the sniff.
2. Its first bytes, to name the format it really is. A format the policy
   does not allow is refused by name, and no reader of ours runs on it.
3. Whether its name agrees with its contents.
4. Its header, with the reader for its format (ours for JPEG, PNG and TIFF;
   ``pdfinfo`` in a separate process for PDF): dimensions, frames, pages,
   how a JPEG is coded, how a TIFF is compressed, what kind of PNG it is.
5. The policy's ceilings against what the header said.

Every reason is a sentence an operator can act on, and the verdict carries
all of them, not just the first.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from sillybos import headers, sniff
from sillybos.pdf import pdf as read_pdf
from sillybos.policy import (
    DEFAULT,
    FORMATS,
    JPEG_FRAMES,
    PNG_COLOUR_TYPES,
    TIFF_COMPRESSIONS,
    TIFF_PHOTOMETRICS,
    TIFF_SUBSAMPLINGS,
    Policy,
)


@dataclass(frozen=True)
class Facts:
    """What was read from the file before any decoder saw it.

    Attributes:
        bytes: The file's size.
        width: Pixels across the first page or frame; for a PDF, at the
            policy's render dpi.
        height: Pixels down, likewise.
        pages: Pages in a PDF, frames in a TIFF or animated PNG, 1 otherwise.
            For a file with more than the policy allows, the walk may have
            stopped early: the number is then "more than" the limit.
        max_pixels: The most pixels any one page or frame would decode to,
            or ``None`` if the page count was over the limit and the sizes
            were not read.
        encrypted: Whether a PDF is encrypted. Always ``False`` for an image.
        pages_exact: ``False`` when the frame walk stopped at the limit, so
            ``pages`` is a floor, not a count.
        coding: How a JPEG's frame is coded, by a name from
            :data:`sillybos.JPEG_FRAMES`; ``None`` for the other formats.
        compression: How a TIFF's frames are compressed, by a name from
            :data:`sillybos.TIFF_COMPRESSIONS`; ``None`` for the other
            formats.
        metadata: The largest block of metadata in an image, as (what it
            is, bytes): a PNG chunk, a TIFF tag's data, a JPEG colour
            profile. ``None`` for a PDF or an image with none.
        colour: A PNG's colour type, by a name from
            :data:`sillybos.PNG_COLOUR_TYPES`, or a TIFF's photometric
            interpretation, from :data:`sillybos.TIFF_PHOTOMETRICS`;
            ``None`` for a JPEG or a PDF.
        depth: A PNG's or TIFF's bits per sample; ``None`` otherwise.
        interlaced: Whether a PNG is Adam7 interlaced.
        tile: A tiled TIFF's largest tile as (width, height); ``None`` for
            a TIFF in strips and for the other formats.
        subsampling: A YCbCr TIFF's chroma subsampling, horizontal by
            vertical, as ``"2x2"``; ``None`` otherwise.
    """

    bytes: int
    width: int
    height: int
    pages: int
    max_pixels: int | None
    encrypted: bool = False
    pages_exact: bool = True
    coding: str | None = None
    compression: str | None = None
    metadata: tuple[str, int] | None = None
    colour: str | None = None
    depth: int | None = None
    interlaced: bool = False
    tile: tuple[int, int] | None = None
    subsampling: str | None = None


@dataclass(frozen=True)
class Verdict:
    """The answer to "may a decoder open this file?".

    Attributes:
        path: The file.
        ok: ``True`` if nothing was found against it.
        format: What the file really is, from its contents: a name from
            :data:`sillybos.FORMATS`, another name the library knows only
            to refuse (``"postscript"``), or ``None`` for an unknown format.
        claimed: What its extension says it is, or ``None`` if the extension
            is not one the library maps.
        facts: What the header said, or ``None`` if it was never read.
        reasons: Why the file was refused, one sentence each. Empty when
            ``ok``.
    """

    path: Path
    ok: bool
    format: str | None
    claimed: str | None
    facts: Facts | None
    reasons: tuple[str, ...]

    def __str__(self) -> str:
        if self.ok:
            return f"{self.path.name}: ok ({self.summary()})"
        return f"{self.path.name}: refused. " + " ".join(r + "." for r in self.reasons)

    def summary(self) -> str:
        """One line of facts: ``"JPEG, 4000x6000, 1 page, 2.1 MB"``."""
        parts = [sniff.describe(self.format)]
        if self.facts is not None:
            parts.append(f"{self.facts.width}x{self.facts.height}")
            parts.append(f"{self.facts.pages} page{'s' if self.facts.pages != 1 else ''}")
            parts.append(f"{self.facts.bytes / 1_000_000:.1f} MB")
        return ", ".join(parts)


class Refused(Exception):
    """A file did not pass. Raised by :func:`require`; carries the :class:`Verdict`."""

    def __init__(self, verdict: Verdict) -> None:
        self.verdict = verdict
        super().__init__(str(verdict))


def check(path: str | os.PathLike[str], policy: Policy = DEFAULT) -> Verdict:
    """Decide whether a decoder may open ``path``, without opening it with one.

    Args:
        path: The file to check. It must exist; a missing file is the
            caller's error, not a verdict, and raises :class:`FileNotFoundError`.
        policy: The limits to apply. :data:`sillybos.DEFAULT` if not given.

    Returns:
        A :class:`Verdict`. Never raises for anything found *in* the file:
        a malformed header, a lying name and a page too large are all
        reasons, not exceptions.

    Raises:
        FileNotFoundError: If the file does not exist.
        sillybos.pdf.PdfInfoMissing: If the file is a PDF and ``pdfinfo``
            is not installed.
    """
    path = Path(path)
    size = path.stat().st_size
    reasons: list[str] = []
    claimed = sniff.claimed_by(path.suffix)

    if size > policy.max_bytes:
        reasons.append(f"{size:,} bytes; the limit is {policy.max_bytes:,}")

    with path.open("rb") as f:
        head = f.read(sniff.HEAD_BYTES)
        if not head:
            return Verdict(path, False, None, claimed, None, ("the file is empty",))
        fmt = sniff.sniff(head)

        if fmt is None or not policy.allows(fmt):
            reasons.append(_wrong_format(fmt, claimed, policy))
            return Verdict(path, False, fmt, claimed, None, tuple(reasons))

        if policy.name_must_match and claimed is not None and claimed != fmt:
            reasons.append(f"says {sniff.describe(claimed)}, is {sniff.describe(fmt)}")
            return Verdict(path, False, fmt, claimed, None, tuple(reasons))

        if reasons:
            # Over the byte limit: do not read on, and in particular do not
            # start pdfinfo on it.
            return Verdict(path, False, fmt, claimed, None, tuple(reasons))

        try:
            facts = _facts(path, fmt, f, size, policy)
        except headers.HeaderError as exc:
            reasons.append(f"the header could not be read: {exc}")
            return Verdict(path, False, fmt, claimed, None, tuple(reasons))

    reasons.extend(_against_limits(facts, policy, fmt))
    return Verdict(path, not reasons, fmt, claimed, facts, tuple(reasons))


def require(path: str | os.PathLike[str], policy: Policy = DEFAULT) -> Verdict:
    """As :func:`check`, but raise :class:`Refused` instead of returning a refusal."""
    verdict = check(path, policy)
    if not verdict.ok:
        raise Refused(verdict)
    return verdict


def _wrong_format(fmt: str | None, claimed: str | None, policy: Policy) -> str:
    real = sniff.describe(fmt)
    allowed = ", ".join(sniff.describe(name) for name in sorted(policy.formats))
    if claimed is not None and claimed != fmt:
        return f"says {sniff.describe(claimed)}, is {real}"
    if fmt in FORMATS:
        return f"is {real}, which this policy does not allow (allowed: {allowed})"
    return f"is {real}, not one of the formats a scan can be (allowed: {allowed})"


def _facts(path: Path, fmt: str, f: headers.Reader, size: int, policy: Policy) -> Facts:
    if fmt == "pdf":
        info = read_pdf(path, policy)
        return Facts(size, info.width, info.height, info.pages, info.max_pixels, info.encrypted)
    header = headers.READERS[fmt](f, size, policy.max_pages)
    return Facts(
        size,
        header.width,
        header.height,
        header.pages,
        header.max_pixels if header.complete else None,
        pages_exact=header.complete,
        coding=header.coding,
        compression=header.compression,
        metadata=header.metadata,
        colour=header.colour,
        depth=header.depth,
        interlaced=header.interlaced,
        tile=header.tile,
        subsampling=header.subsampling,
    )


def _against_limits(facts: Facts, policy: Policy, fmt: str) -> list[str]:
    reasons = []
    if facts.pages > policy.max_pages:
        if facts.pages_exact:
            reasons.append(f"{facts.pages:,} pages; the limit is {policy.max_pages:,}")
        else:
            reasons.append(f"more than {policy.max_pages:,} pages, which is the limit")
    if facts.max_pixels is not None and facts.max_pixels > policy.max_pixels:
        reasons.append(f"a page of {facts.max_pixels:,} pixels; the limit is {policy.max_pixels:,}")
    if facts.metadata is not None and facts.metadata[1] > policy.max_metadata_bytes:
        what, size = facts.metadata
        reasons.append(f"a {what} of {size:,} bytes; the limit is {policy.max_metadata_bytes:,}")
    if facts.encrypted and not policy.allow_encrypted_pdf:
        reasons.append("the PDF is encrypted")
    if facts.coding is not None and facts.coding not in policy.jpeg_frames:
        allowed = [name for name in JPEG_FRAMES if name in policy.jpeg_frames]
        article = "an" if facts.coding[0] in "aeiou" else "a"
        reasons.append(
            f"{article} {facts.coding} JPEG; the policy allows {_listed(allowed)} frames"
        )
    if fmt == "png" and facts.colour is not None and facts.colour not in policy.png_colour_types:
        allowed = [name for name in PNG_COLOUR_TYPES if name in policy.png_colour_types]
        reasons.append(f"a {facts.colour} PNG; the policy allows {_listed(allowed)}")
    if fmt == "tiff" and facts.colour is not None and facts.colour not in policy.tiff_photometrics:
        allowed = [name for name in TIFF_PHOTOMETRICS if name in policy.tiff_photometrics]
        reasons.append(f"a {facts.colour} TIFF; the policy allows {_listed(allowed)}")
    if facts.subsampling is not None and facts.subsampling not in policy.tiff_subsamplings:
        allowed = [name for name in TIFF_SUBSAMPLINGS if name in policy.tiff_subsamplings]
        reasons.append(
            f"a ycbcr TIFF subsampled {facts.subsampling}; the policy allows {_listed(allowed)}"
        )
    if facts.depth is not None and facts.depth > policy.max_png_bit_depth:
        reasons.append(f"a {facts.depth}-bit PNG; the limit is {policy.max_png_bit_depth} bits")
    if facts.interlaced and not policy.allow_interlaced_png:
        reasons.append("an interlaced PNG; the policy does not allow interlacing")
    if facts.tile is not None:
        if not policy.allow_tiled_tiff:
            reasons.append("a tiled TIFF; the policy allows strips only")
        tile_pixels = facts.tile[0] * facts.tile[1]
        if tile_pixels > policy.max_pixels:
            reasons.append(f"a tile of {tile_pixels:,} pixels; the limit is {policy.max_pixels:,}")
    if facts.compression is not None and facts.compression not in policy.tiff_compressions:
        allowed = [name for name in TIFF_COMPRESSIONS if name in policy.tiff_compressions]
        reasons.append(
            f"a {facts.compression}-compressed TIFF; the policy allows {_listed(allowed)}"
        )
    return reasons


def _listed(names: list[str]) -> str:
    if len(names) < 2:
        return "".join(names)
    return ", ".join(names[:-1]) + " and " + names[-1]
