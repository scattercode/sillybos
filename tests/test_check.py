"""check() end to end: good files pass, each hostile file is refused with the right reason."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from PIL import Image

from sillybos import DEFAULT, STRICT, Policy, Refused, check, require
from tests import corpus

needs_pdfinfo = pytest.mark.skipif(shutil.which("pdfinfo") is None, reason="pdfinfo (poppler)")


class TestGoodFiles:
    @pytest.mark.parametrize(
        ("name", "fmt"), [("scan.jpg", "JPEG"), ("scan.png", "PNG"), ("scan.tif", "TIFF")]
    )
    def test_a_real_scan_passes(self, tmp_path: Path, name: str, fmt: str) -> None:
        path = tmp_path / name
        Image.new("RGB", (300, 200), "white").save(path, format=fmt)

        verdict = check(path)

        assert verdict.ok and verdict.reasons == ()
        assert verdict.format == fmt.lower() == verdict.claimed
        assert verdict.facts is not None
        assert (verdict.facts.width, verdict.facts.height, verdict.facts.pages) == (300, 200, 1)
        assert verdict.facts.bytes == path.stat().st_size

    def test_a_file_with_no_extension_makes_no_claim(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "scan", corpus.png(10, 10)))
        assert verdict.ok and verdict.claimed is None

    def test_require_returns_the_verdict(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "scan.png", corpus.png(10, 10))
        assert require(path).ok

    def test_str_and_summary(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "scan.png", corpus.png(10, 10)))
        assert str(verdict) == "scan.png: ok (PNG, 10x10, 1 page, 0.0 MB)"


class TestHostileFiles:
    def test_a_renamed_postscript_file(self, tmp_path: Path) -> None:
        """The October 2026 path: Pillow would have run its EPS reader on this."""
        verdict = check(corpus.write(tmp_path / "page.png", corpus.POSTSCRIPT))
        assert verdict.reasons == ("says PNG, is PostScript",)
        assert (verdict.format, verdict.claimed, verdict.facts) == ("postscript", "png", None)

    def test_a_renamed_ole_file(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "page.jpg", corpus.OLE))
        assert verdict.reasons[0].startswith("says JPEG, is an OLE compound file")

    @pytest.mark.parametrize("data", [corpus.GIF, corpus.WEBP, corpus.HEIC, corpus.ZIP])
    def test_a_format_a_scan_never_is(self, tmp_path: Path, data: bytes) -> None:
        verdict = check(corpus.write(tmp_path / "file.bin", data))
        assert not verdict.ok
        assert "not one of the formats a scan can be" in verdict.reasons[0]

    def test_an_unknown_format(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "file.bin", b"nothing to see here"))
        assert verdict.format is None
        assert verdict.reasons[0].startswith("is an unknown format")

    def test_an_empty_file(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "scan.png", b""))
        assert verdict.reasons == ("the file is empty",)

    def test_an_allowed_format_the_policy_excludes(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "scan.png", corpus.png(10, 10))
        verdict = check(path, Policy(formats=frozenset({"jpeg", "tiff"})))
        assert verdict.reasons == (
            "is PNG, which this policy does not allow (allowed: JPEG, TIFF)",
        )

    def test_a_jpeg_called_png(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "scan.png", corpus.jpeg(10, 10))
        assert check(path).reasons == ("says PNG, is JPEG",)
        assert check(path, Policy(name_must_match=False)).ok

    def test_a_pixel_bomb(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "bomb.png", corpus.png(100_000, 100_000)))
        assert verdict.reasons == ("a page of 10,000,000,000 pixels; the limit is 89,478,485",)
        assert verdict.facts is not None and verdict.facts.max_pixels == 10_000_000_000

    def test_a_lossless_jpeg(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "scan.jpg", corpus.jpeg(10, 10, marker=0xC3)))
        assert verdict.reasons == (
            "a lossless JPEG; the policy allows baseline, extended and progressive frames",
        )
        assert verdict.facts is not None and verdict.facts.coding == "lossless"

    def test_the_policy_can_allow_a_coding(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "scan.jpg", corpus.jpeg(10, 10, marker=0xC9))
        assert check(path, Policy(jpeg_frames=frozenset({"arithmetic"}))).ok
        verdict = check(path, Policy(jpeg_frames=frozenset({"baseline"})))
        assert verdict.reasons == ("an arithmetic JPEG; the policy allows baseline frames",)

    def test_a_multi_picture_jpeg_whose_second_picture_is_a_bomb(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "scan.jpg", corpus.mpo([(10, 10), (65_535, 65_535)]))
        verdict = check(path)
        assert verdict.reasons == ("a page of 4,294,836,225 pixels; the limit is 89,478,485",)
        assert verdict.facts is not None and verdict.facts.pages == 2

    def test_a_multi_picture_jpeg_that_changes_mode(self, tmp_path: Path) -> None:
        path = corpus.write(
            tmp_path / "scan.jpg", corpus.mpo([(10, 10), (10, 10)], components=[1, 3])
        )
        assert check(path).reasons == (
            "the header could not be read: picture 2 has 3 components where picture 1 has 1",
        )

    def test_a_multi_picture_jpeg_with_too_many_pictures(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "scan.jpg", corpus.mpo([(10, 10)] * 4))
        assert check(path, Policy(max_pages=3)).reasons == ("4 pages; the limit is 3",)

    def test_a_tiff_with_ten_thousand_frames(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "frames.tif", corpus.tiff([(10, 10)] * 10_000)))
        assert verdict.reasons == ("more than 500 pages, which is the limit",)
        assert verdict.facts is not None and not verdict.facts.pages_exact

    def test_a_tiff_with_one_oversized_frame_among_many(self, tmp_path: Path) -> None:
        frames = [(10, 10)] * 5 + [(20_000, 20_000)] + [(10, 10)]
        verdict = check(corpus.write(tmp_path / "frames.tif", corpus.tiff(frames)))
        assert verdict.reasons == ("a page of 400,000,000 pixels; the limit is 89,478,485",)

    def test_a_looping_tiff(self, tmp_path: Path) -> None:
        verdict = check(
            corpus.write(tmp_path / "loop.tif", corpus.tiff([(10, 10)], loop_to_first=True))
        )
        assert verdict.reasons == (
            "the header could not be read: the frame chain loops back on itself",
        )

    def test_a_file_over_the_byte_limit_is_not_read_further(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "big.png", corpus.png(10, 10) + b"\x00" * 100)
        verdict = check(path, Policy(max_bytes=50))
        assert verdict.reasons == (f"{path.stat().st_size:,} bytes; the limit is 50",)
        assert verdict.facts is None

    def test_a_file_over_the_byte_limit_still_names_a_wrong_format(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "big.png", corpus.POSTSCRIPT + b"\x00" * 100)
        verdict = check(path, Policy(max_bytes=50))
        assert len(verdict.reasons) == 2 and verdict.reasons[1] == "says PNG, is PostScript"

    def test_require_raises_with_the_verdict(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "page.png", corpus.POSTSCRIPT)
        with pytest.raises(
            Refused, match=r"page\.png: refused\. says PNG, is PostScript\."
        ) as info:
            require(path)
        assert info.value.verdict.format == "postscript"

    def test_a_missing_file_is_the_callers_error(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            check(tmp_path / "nowhere.png")


@needs_pdfinfo
class TestPdf:
    def test_a_real_pdf_passes(self, tmp_path: Path) -> None:
        path = tmp_path / "book.pdf"
        Image.new("RGB", (300, 200), "white").save(path, format="PDF", resolution=100)

        verdict = check(path)

        assert verdict.ok
        assert verdict.facts is not None
        assert verdict.facts.pages == 1
        # 3 x 2 inches at 200 dpi.
        assert (verdict.facts.width, verdict.facts.height) == (600, 400)
        assert verdict.facts.max_pixels == 240_000
        assert not verdict.facts.encrypted

    def test_a_hand_written_two_page_pdf_passes(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "two.pdf", corpus.pdf(2)))
        assert verdict.ok and verdict.facts is not None and verdict.facts.pages == 2

    def test_a_thousand_page_pdf(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "long.pdf", corpus.pdf(1000)))
        assert verdict.reasons == ("1,000 pages; the limit is 500",)
        assert verdict.facts is not None and verdict.facts.max_pixels is None
        assert verdict.facts.pages_exact

    def test_a_page_the_size_of_a_wall(self, tmp_path: Path) -> None:
        """One A4 page and one of 200 x 300 inches: the large one is found wherever it is."""
        sizes = [(595.0, 842.0), (14400.0, 21600.0)]
        verdict = check(corpus.write(tmp_path / "wall.pdf", corpus.pdf(2, sizes=sizes)))
        assert verdict.reasons == ("a page of 2,400,000,000 pixels; the limit is 89,478,485",)

    def test_a_file_that_is_not_a_pdf_inside(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "broken.pdf", b"%PDF-1.4\ngarbage"))
        assert not verdict.ok
        assert verdict.reasons[0].startswith(
            "the header could not be read: pdfinfo could not read it"
        )

    def test_strict_is_shorter(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "long.pdf", corpus.pdf(150)), STRICT)
        assert verdict.reasons == ("150 pages; the limit is 100",)


class TestPolicy:
    def test_presets(self) -> None:
        assert DEFAULT.max_pages == 500 and STRICT.max_pages == 100
        assert STRICT.max_bytes < DEFAULT.max_bytes

    @pytest.mark.parametrize(
        ("changes", "reason"),
        [
            ({"formats": frozenset({"webp"})}, "unknown format"),
            ({"formats": frozenset()}, "at least one format"),
            ({"jpeg_frames": frozenset({"baseline", "mpeg"})}, "unknown JPEG frame coding"),
            ({"jpeg_frames": frozenset()}, "at least one JPEG frame coding"),
            ({"max_pages": 0}, "max_pages must be at least 1"),
            ({"pdfinfo_timeout": 0}, "must be positive"),
        ],
    )
    def test_refuses_an_impossible_policy(self, changes: dict[str, object], reason: str) -> None:
        with pytest.raises(ValueError, match=reason):
            Policy(**changes)  # type: ignore[arg-type]
