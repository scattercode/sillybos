"""Page count, page sizes and the features of a PDF, from poppler's `pdfinfo` and `pdfdetach`.

A PDF's structure cannot be read from a fixed header the way an image's can:
the page count lives in an object tree that may be compressed, and finding
it means parsing. Rather than carry a PDF parser (which would be exactly the
kind of code the library exists to keep away from untrusted files), this
asks `pdfinfo`, which parses the structure without rendering a page, in a
separate process with a time limit. A hang or a crash in `pdfinfo` is then
one file's refusal, not the caller's.

The same report says whether the file carries JavaScript or a form, and
`pdfdetach -list`, from the same package, whether it carries attached files.
A launch action, which tells the viewer to run a program, is reported by no
poppler tool, so it is found by its name in the file, the way `pdfid` finds
it: a bounded scan for the bytes, with the `#xx` escapes a name may be
written with undone, and no parsing. JavaScript is looked for both ways,
because poppler before 26 reports only document-level scripts and not one
attached to an open-document action.

`pdfinfo` and `pdfdetach` come with poppler (`brew install poppler`, `apt
install poppler-utils`), which anything that renders PDFs in Python already
needs. Without them, a PDF cannot be checked, and [PdfInfoMissing][sillybos.pdf.PdfInfoMissing]
says so; that is a configuration error, not a verdict on the file.
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
_JAVASCRIPT = re.compile(r"^JavaScript:\s+yes", re.MULTILINE)
_FORM = re.compile(r"^Form:\s+(\S+)", re.MULTILINE)
_ATTACHMENTS = re.compile(r"^(\d+) embedded files?", re.MULTILINE)


def _name_pattern(name: str) -> re.Pattern[bytes]:
    """A pattern for the PDF name `/name`, however its letters are escaped.

    A name in a PDF may write any character as `#` and two hex digits, so
    `/Launch` may appear as `/L#61unch`. The pattern matches each letter
    either way, and requires a delimiter after the name so that `/Launcher`
    is not `/Launch`.
    """
    letters = "".join(
        f"(?:{re.escape(c)}|#{ord(c):02x}|#{ord(c):02X})" if c.isalpha() else re.escape(c)
        for c in name
    )
    return re.compile(rf"/{letters}(?![A-Za-z0-9#])".encode())


_LAUNCH = _name_pattern("Launch")
_JAVASCRIPT_NAMES = (_name_pattern("JavaScript"), _name_pattern("JS"))
_SCAN_CHUNK = 1024 * 1024
_SCAN_OVERLAP = 32  # longer than the longest escaped spelling of the name


class PdfInfoMissing(RuntimeError):
    """A poppler tool (`pdfinfo`, `pdfdetach`) is not on the PATH, so no PDF can be checked."""

    def __init__(self, tool: str = "pdfinfo") -> None:
        super().__init__(
            f"{tool} (from poppler) is needed to check a PDF and is not on the PATH: "
            "`brew install poppler` on macOS, `apt install poppler-utils` on Debian"
        )


@dataclass(frozen=True)
class PdfHeader:
    """What `pdfinfo` reported.

    Attributes:
        pages: The page count.
        encrypted: Whether the file is encrypted.
        width: The first page's width in pixels at the policy's render dpi.
        height: The first page's height, likewise.
        max_pixels: The most pixels any page would render to. `None` when
            the page count was over the limit and the sizes were not asked
            for.
        features: Which of [sillybos.PDF_FEATURES][] the file carries, in
            that order. Attached files and launch actions are only looked
            for when the page count is within the limit.
    """

    pages: int
    encrypted: bool
    width: int
    height: int
    max_pixels: int | None
    features: tuple[str, ...] = ()


def _pdfinfo(args: list[str], path: Path, timeout: float) -> str:
    return _tool("pdfinfo", args, path, timeout)


def _tool(tool: str, args: list[str], path: Path, timeout: float) -> str:
    executable = shutil.which(tool)
    if executable is None:
        raise PdfInfoMissing(tool)
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
        raise HeaderError(f"{tool} did not finish within {timeout:g} seconds") from None
    if done.returncode != 0:
        detail = done.stderr.strip().splitlines()
        reason = detail[-1] if detail else f"exit status {done.returncode}"
        raise HeaderError(f"{tool} could not read it ({reason})")
    return done.stdout


def _names_in(path: Path, *patterns: re.Pattern[bytes]) -> list[bool]:
    """Whether the bytes of the file spell each name anywhere, one answer per pattern.

    Read a chunk at a time with a short overlap, so a name across a chunk
    boundary is still seen and the memory used does not grow with the file.
    """
    found = [False] * len(patterns)
    tail = b""
    with path.open("rb") as f:
        while chunk := f.read(_SCAN_CHUNK):
            window = tail + chunk
            for i, pattern in enumerate(patterns):
                if not found[i] and pattern.search(window):
                    found[i] = True
            if all(found):
                break
            tail = chunk[-_SCAN_OVERLAP:]
    return found


def _has_launch_action(path: Path) -> bool:
    """Whether the bytes of the file spell the name `/Launch` anywhere."""
    return _names_in(path, _LAUNCH)[0]


def _features(summary: str, path: Path, policy: Policy, *, within_limit: bool) -> tuple[str, ...]:
    found = []
    if _JAVASCRIPT.search(summary):
        found.append("javascript")
    form = _FORM.search(summary)
    if form is not None and form.group(1).lower() != "none":
        found.append("forms")
    if within_limit:
        listing = _tool("pdfdetach", ["-list"], path, policy.pdfinfo_timeout)
        count = _ATTACHMENTS.search(listing)
        if count is not None and int(count.group(1)) > 0:
            found.append("attachments")
        scripted, script, launch = _names_in(path, *_JAVASCRIPT_NAMES, _LAUNCH)
        if (scripted or script) and "javascript" not in found:
            found.insert(0, "javascript")
        if launch:
            found.append("launch")
    return tuple(found)


def _pixels(points: str, dpi: int) -> float:
    return float(points) / 72 * dpi


def pdf(path: Path, policy: Policy) -> PdfHeader:
    """Ask poppler for the page count, encryption, features and, within the limit, every page's size.

    Page sizes, attached files and the scan for a launch action only happen
    when the count is within `policy.max_pages`: a listing of a hundred
    thousand pages is work the file should not be able to cause, and a file
    over the limit is refused whatever else it carries.

    Raises:
        HeaderError: If `pdfinfo` or `pdfdetach` refuses the file or runs out of time.
        PdfInfoMissing: If `pdfinfo` or `pdfdetach` is not installed.
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
        features = _features(summary, path, policy, within_limit=False)
        return PdfHeader(pages, encrypted, width, height, None, features)
    listing = _pdfinfo(["-f", "1", "-l", str(pages)], path, policy.pdfinfo_timeout)
    sizes = [
        _pixels(w, policy.render_dpi) * _pixels(h, policy.render_dpi)
        for _page, w, h in _PAGE_SIZE.findall(listing)
    ]
    if not sizes:
        raise HeaderError("pdfinfo reported no page sizes")
    features = _features(summary, path, policy, within_limit=True)
    return PdfHeader(pages, encrypted, width, height, round(max(sizes)), features)
