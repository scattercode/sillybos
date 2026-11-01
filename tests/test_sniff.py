import pytest

from sillybos import FORMATS
from sillybos.sniff import FORMATS_KNOWN, claimed_by, describe, sniff
from tests import corpus


@pytest.mark.parametrize(
    ("head", "name"),
    [
        (corpus.jpeg(10, 10), "jpeg"),
        (corpus.png(10, 10), "png"),
        (corpus.tiff([(10, 10)]), "tiff"),
        (corpus.tiff([(10, 10)], endian=">"), "tiff"),
        (b"II+\x00" + b"\x00" * 12, "bigtiff"),
        (corpus.pdf(1), "pdf"),
        (corpus.POSTSCRIPT, "postscript"),
        (b"\xc5\xd0\xd3\xc6" + b"\x00" * 26, "postscript"),
        (corpus.GIF, "gif"),
        (corpus.OLE, "ole"),
        (corpus.WEBP, "webp"),
        (corpus.HEIC, "heif"),
        (corpus.ZIP, "zip"),
        (b"<?xml version='1.0'?><svg/>", "xml"),
        (b"8BPS\x00\x01", "psd"),
        (b"\x00\x00\x00\x0cjP  \r\n\x87\n", "jpeg2000"),
        (b"hello, world", None),
        (b"", None),
    ],
)
def test_names_the_format_from_the_first_bytes(head: bytes, name: str | None) -> None:
    assert sniff(head) == name


def test_every_allowed_format_is_a_known_one() -> None:
    assert set(FORMATS) <= FORMATS_KNOWN


def test_describes_formats_for_a_reason_sentence() -> None:
    assert describe("postscript") == "PostScript"
    assert describe("ole").startswith("an OLE compound file")
    assert describe(None) == "an unknown format"
    assert describe("something-new") == "something-new"


@pytest.mark.parametrize(
    ("suffix", "claim"),
    [
        (".jpg", "jpeg"),
        (".JPEG", "jpeg"),
        (".png", "png"),
        (".tif", "tiff"),
        (".TIFF", "tiff"),
        (".pdf", "pdf"),
        (".gif", None),
        ("", None),
    ],
)
def test_the_extension_makes_a_claim_or_none(suffix: str, claim: str | None) -> None:
    assert claimed_by(suffix) == claim
