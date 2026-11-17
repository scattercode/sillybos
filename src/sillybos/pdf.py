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

The name that says JavaScript is `/JavaScript`: it is the type of the
action that carries a script, and the key of the document's own table of
scripts. The script itself sits under the key `/JS`, and that name alone
says nothing, because it is three bytes long and compressed image data
spells any three bytes by chance: about once in 24 MB of random bytes,
and about once in 2 MB of the ASCII85 text that ReportLab writes its
streams in. Taking `/JS` alone for a script refused 27 of 689 ordinary
PDFs, scanned books and newspapers among them, none of which `pdfinfo`
found a script in. So `/JS` counts only in a file that also spells
`/Rendition`, the one other type of action that may carry a script, and
whose scripts `/JavaScript` would not find.

Passing over the bytes of streams would not have been a fix. A reader
finds an object where the cross-reference table says it is, and the table
may point into the middle of another object's stream: poppler reads an
action placed there without complaint. A scan that skipped streams would
then miss what the viewer runs, so every byte of the file is searched,
and it is the name searched for that has to be one chance does not spell.

The codec of each image is found the same way, by the name of its filter
(`/JBIG2Decode`, `/JPXDecode`, `/DCTDecode`, `/CCITTFaxDecode`). A stream's
dictionary cannot be hidden inside a compressed object stream, so the name
is in plain bytes unless the filter is given through an indirect reference.
`pdfimages -list` would report the codecs too, but it opens a JPX stream
with OpenJPEG to describe it, which is exactly the decoder's code this
check exists to keep from the file, so it is never run.

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
    `/Launch` may appear as `/L#61unch` and `/JBIG2Decode` as `/JBIG#32Decode`.
    The pattern matches each letter and digit either way, and requires a
    delimiter after the name so that `/Launcher` is not `/Launch`.
    """
    letters = "".join(
        f"(?:{re.escape(c)}|#{ord(c):02x}|#{ord(c):02X})" if c.isalnum() else re.escape(c)
        for c in name
    )
    return re.compile(rf"/{letters}(?![A-Za-z0-9#])".encode())


_LAUNCH = _name_pattern("Launch")
_JAVASCRIPT_NAME = _name_pattern("JavaScript")
_SCRIPT_KEY = _name_pattern("JS")
_RENDITION = _name_pattern("Rendition")


def _any_name(*names: str) -> re.Pattern[bytes]:
    """A pattern for any of several PDF names, each however its letters are escaped."""
    return re.compile(b"|".join(_name_pattern(name).pattern for name in names))


_CODEC_NAMES: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    # The abbreviations are the ones an inline image may use.
    ("jpeg", _any_name("DCTDecode", "DCT")),
    ("jpx", _any_name("JPXDecode")),
    ("jbig2", _any_name("JBIG2Decode")),
    ("ccitt", _any_name("CCITTFaxDecode", "CCF")),
)
_SCAN_CHUNK = 1024 * 1024


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
        max_side: The longest side, in pixels at the render dpi, of any
            page. `None` in the same case.
        features: Which of [sillybos.PDF_FEATURES][] the file carries, in
            that order. Attached files and launch actions are only looked
            for when the page count is within the limit.
        codecs: Which of [sillybos.PDF_IMAGE_CODECS][] the file's images
            are coded with, in that order, by the filters named in it.
            Looked for in the same pass as the launch action.
    """

    pages: int
    encrypted: bool
    width: int
    height: int
    max_pixels: int | None
    max_side: int | None
    features: tuple[str, ...] = ()
    codecs: tuple[str, ...] = ()


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

    Read a chunk at a time, so the memory used does not grow with the file,
    and carry the end of each chunk over to the next, so a name across a
    chunk boundary is still seen. What is carried is as long as the longest
    pattern, and a pattern made by `_name_pattern` is longer than any
    spelling it matches: a fixed 32 bytes was shorter
    than `/JBIG2Decode` or `/CCITTFaxDecode` with every letter escaped, so
    one placed just before a boundary went unseen.

    A name that ends exactly where a chunk does is not counted yet, since
    the letters that follow may make it another name (`/Launch` and then
    `er`); the next chunk settles it. One that ends where the file does is
    counted.
    """
    overlap = max(len(pattern.pattern) for pattern in patterns)
    found = [False] * len(patterns)
    at_end = [False] * len(patterns)
    tail = b""
    with path.open("rb") as f:
        while chunk := f.read(_SCAN_CHUNK):
            window = tail + chunk
            for i, pattern in enumerate(patterns):
                if found[i]:
                    continue
                match = pattern.search(window)
                found[i] = match is not None and match.end() < len(window)
                at_end[i] = match is not None and match.end() == len(window)
            if all(found):
                break
            tail = window[-overlap:]
    return [hit or last for hit, last in zip(found, at_end, strict=True)]


def _has_launch_action(path: Path) -> bool:
    """Whether the bytes of the file spell the name `/Launch` anywhere."""
    return _names_in(path, _LAUNCH)[0]


def _contents(
    summary: str, path: Path, policy: Policy, *, within_limit: bool
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The features the file carries and the codecs its images use, as two tuples."""
    found = []
    codecs: list[str] = []
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
        named, key, rendition, launch, *coded = _names_in(
            path, _JAVASCRIPT_NAME, _SCRIPT_KEY, _RENDITION, _LAUNCH, *(p for _, p in _CODEC_NAMES)
        )
        # `/JS` alone is three bytes that compressed data spells by chance; see the module's notes.
        if (named or (key and rendition)) and "javascript" not in found:
            found.insert(0, "javascript")
        if launch:
            found.append("launch")
        codecs = [name for (name, _), hit in zip(_CODEC_NAMES, coded, strict=True) if hit]
    return tuple(found), tuple(codecs)


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
        features, codecs = _contents(summary, path, policy, within_limit=False)
        return PdfHeader(pages, encrypted, width, height, None, None, features, codecs)
    listing = _pdfinfo(["-f", "1", "-l", str(pages)], path, policy.pdfinfo_timeout)
    sides = [
        (_pixels(w, policy.render_dpi), _pixels(h, policy.render_dpi))
        for _page, w, h in _PAGE_SIZE.findall(listing)
    ]
    if not sides:
        raise HeaderError("pdfinfo reported no page sizes")
    features, codecs = _contents(summary, path, policy, within_limit=True)
    max_pixels = round(max(w * h for w, h in sides))
    max_side = round(max(max(w, h) for w, h in sides))
    return PdfHeader(pages, encrypted, width, height, max_pixels, max_side, features, codecs)
