"""The pdfinfo wrapper, including what happens when pdfinfo is slow, absent or unhappy."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from sillybos import Policy, check
from sillybos import pdf as pdf_module
from sillybos.headers import HeaderError
from sillybos.pdf import PdfInfoMissing
from tests import corpus

needs_pdfinfo = pytest.mark.skipif(shutil.which("pdfinfo") is None, reason="pdfinfo (poppler)")


def test_a_missing_pdfinfo_is_a_configuration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(PdfInfoMissing, match="brew install poppler"):
        check(corpus.write(tmp_path / "a.pdf", corpus.pdf(1)))


@needs_pdfinfo
def test_a_pdfinfo_that_does_not_finish_is_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def hang(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired("pdfinfo", 0.5)

    monkeypatch.setattr(subprocess, "run", hang)
    verdict = check(corpus.write(tmp_path / "a.pdf", corpus.pdf(1)), Policy(pdfinfo_timeout=0.5))
    assert verdict.reasons == (
        "the header could not be read: pdfinfo did not finish within 0.5 seconds",
    )


@needs_pdfinfo
def test_an_encrypted_pdf_is_refused_unless_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pdfinfo's own report is trusted; this fakes the one line, since writing an encrypted PDF needs a library."""
    real = pdf_module._pdfinfo

    def encrypted(args: list[str], path: Path, timeout: float) -> str:
        return re.sub(
            r"^Encrypted:\s+no",
            "Encrypted:      yes (print:no)",
            real(args, path, timeout),
            flags=re.M,
        )

    monkeypatch.setattr(pdf_module, "_pdfinfo", encrypted)
    path = corpus.write(tmp_path / "locked.pdf", corpus.pdf(1))
    assert check(path).reasons == ("the PDF is encrypted",)
    assert check(path, Policy(allow_encrypted_pdf=True)).ok


@pytest.mark.parametrize(
    ("output", "reason"),
    [
        ("Title: x\n", "no page count"),
        ("Pages:          0\n", "no pages"),
        ("Pages:          1\n", "no page size"),
    ],
)
def test_an_unreadable_pdfinfo_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str, reason: str
) -> None:
    monkeypatch.setattr(pdf_module, "_pdfinfo", lambda args, path, timeout: output)
    with pytest.raises(HeaderError, match=reason):
        pdf_module.pdf(tmp_path / "a.pdf", Policy())


def test_no_page_sizes_in_the_listing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    summary = "Pages:          1\nPage size:      595 x 842 pts (A4)\n"
    monkeypatch.setattr(
        pdf_module, "_pdfinfo", lambda args, path, timeout: summary if not args else ""
    )
    with pytest.raises(HeaderError, match="no page sizes"):
        pdf_module.pdf(tmp_path / "a.pdf", Policy())


def test_a_missing_pdfdetach_is_a_configuration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_which = shutil.which
    monkeypatch.setattr(
        shutil, "which", lambda name: None if name == "pdfdetach" else real_which(name)
    )
    if real_which("pdfinfo") is None:
        pytest.skip("pdfinfo (poppler)")
    with pytest.raises(PdfInfoMissing, match="pdfdetach"):
        check(corpus.write(tmp_path / "a.pdf", corpus.pdf(1)))


@pytest.mark.parametrize(
    ("escaped", "spelling"),
    [
        (b"/Launch", True),
        (b"/L#61unch", True),
        (b"/#4c#61#75#6e#63#68", True),
        (b"/Launcher", False),
        (b"/Launch2", False),
        (b"Launch", False),
    ],
)
def test_the_launch_scan_reads_names_however_they_are_escaped(
    tmp_path: Path, escaped: bytes, spelling: bool
) -> None:
    path = tmp_path / "a.pdf"
    path.write_bytes(b"%PDF-1.4\n1 0 obj << /S " + escaped + b" >> endobj\n")
    assert pdf_module._has_launch_action(path) is spelling


def test_the_launch_scan_sees_a_name_across_a_chunk_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pdf_module, "_SCAN_CHUNK", 16)
    path = tmp_path / "a.pdf"
    path.write_bytes(b"%PDF-1.4\n<< /S /Launch /F (x) >>")  # "/Launch" straddles byte 16
    assert pdf_module._has_launch_action(path)


@needs_pdfinfo
def test_javascript_is_found_by_name_when_pdfinfo_does_not_report_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """poppler before 26 says `JavaScript: no` for a script on an open action; the name scan still sees it."""
    real = pdf_module._pdfinfo

    def older(args: list[str], path: Path, timeout: float) -> str:
        return re.sub(
            r"^JavaScript:\s+yes", "JavaScript:     no", real(args, path, timeout), flags=re.M
        )

    monkeypatch.setattr(pdf_module, "_pdfinfo", older)
    verdict = check(corpus.write(tmp_path / "scripted.pdf", corpus.pdf_with("javascript")))
    assert verdict.facts is not None and verdict.facts.features == ("javascript",)
