"""Page count and page sizes of a PDF, from poppler's ``pdfinfo``.

A PDF's structure cannot be read from a fixed header the way an image's can:
the page count lives in an object tree that may be compressed, and finding
it means parsing. Rather than carry a PDF parser (which would be exactly the
kind of code the library exists to keep away from untrusted files), this
asks ``pdfinfo``, which parses the structure without rendering a page, in a
separate process with a time limit. A hang or a crash in ``pdfinfo`` is then
one file's refusal, not the caller's.

``pdfinfo`` comes with poppler (``brew install poppler``, ``apt install
poppler-utils``), which anything that renders PDFs in Python already needs.
Without it, a PDF cannot be checked, and :class:`PdfInfoMissing` says so;
that is a configuration error, not a verdict on the file.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from sillybos.headers import HeaderError
from sillybos.policy import Policy

_PAGES = re.compile(r"^Pages:\s+(\d+)\s*$", re.MULTILINE)
_ENCRYPTED = re.compile(r"^Encrypted:\s+yes", re.MULTILINE)
_PAGE_SIZE = re.compile(r"^Page(?:\s+(\d+))? size:\s+([\d.]+) x ([\d.]+) pts", re.MULTILINE)


class PdfInfoMissing(RuntimeError):
    """``pdfinfo`` is not on the PATH, so no PDF can be checked."""

    def __init__(self) -> None:
        super().__init__(
            "pdfinfo (from poppler) is needed to check a PDF and is not on the PATH: "
            "`brew install poppler` on macOS, `apt install poppler-utils` on Debian"
        )


@dataclass(frozen=True)
class PdfHeader:
    """What ``pdfinfo`` reported.

    Attributes:
        pages: The page count.
        encrypted: Whether the file is encrypted.
        width: The first page's width in pixels at the policy's render dpi.
        height: The first page's height, likewise.
        max_pixels: The most pixels any page would render to. ``None`` when
            the page count was over the limit and the sizes were not asked
            for.
    """

    pages: int
    encrypted: bool
    width: int
    height: int
    max_pixels: int | None


def _pdfinfo(args: list[str], path: Path, timeout: float) -> str:
    executable = shutil.which("pdfinfo")
    if executable is None:
        raise PdfInfoMissing
    try:
        # The arguments are a fixed list plus the path being checked: nothing
        # here is a shell, and the file's contents go to pdfinfo's parser,
        # which is the one process this library is willing to expose to them.
        done = subprocess.run(  # noqa: S603
            [executable, *args, str(path)],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise HeaderError(f"pdfinfo did not finish within {timeout:g} seconds") from None
    if done.returncode != 0:
        detail = done.stderr.strip().splitlines()
        reason = detail[-1] if detail else f"exit status {done.returncode}"
        raise HeaderError(f"pdfinfo could not read it ({reason})")
    return done.stdout


def _pixels(points: str, dpi: int) -> float:
    return float(points) / 72 * dpi


def pdf(path: Path, policy: Policy) -> PdfHeader:
    """Ask ``pdfinfo`` for the page count, encryption and, within the limit, every page's size.

    Page sizes are only asked for when the count is within ``policy.max_pages``:
    a listing of a hundred thousand pages is work the file should not be able
    to cause.

    Raises:
        HeaderError: If ``pdfinfo`` refuses the file or runs out of time.
        PdfInfoMissing: If ``pdfinfo`` is not installed.
    """
    summary = _pdfinfo([], path, policy.pdfinfo_timeout)
    pages_match = _PAGES.search(summary)
    if pages_match is None:
        raise HeaderError("pdfinfo reported no page count")
    pages = int(pages_match.group(1))
    if pages < 1:
        raise HeaderError("the PDF has no pages")
    encrypted = _ENCRYPTED.search(summary) is not None
    first = _PAGE_SIZE.search(summary)
    if first is None:
        raise HeaderError("pdfinfo reported no page size")
    width = round(_pixels(first.group(2), policy.render_dpi))
    height = round(_pixels(first.group(3), policy.render_dpi))
    if pages > policy.max_pages:
        return PdfHeader(pages, encrypted, width, height, None)
    listing = _pdfinfo(["-f", "1", "-l", str(pages)], path, policy.pdfinfo_timeout)
    sizes = [
        _pixels(w, policy.render_dpi) * _pixels(h, policy.render_dpi)
        for _page, w, h in _PAGE_SIZE.findall(listing)
    ]
    if not sizes:
        raise HeaderError("pdfinfo reported no page sizes")
    return PdfHeader(pages, encrypted, width, height, round(max(sizes)))
