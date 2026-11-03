"""check() end to end: good files pass, each hostile file is refused with the right reason."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from PIL import Image

from sillybos import DEFAULT, PDF_IMAGE_CODECS, STRICT, Policy, Refused, check, require
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

    @pytest.mark.parametrize(
        "data",
        [corpus.GIF, corpus.WEBP, corpus.HEIC, corpus.ZIP, corpus.BMP, corpus.PSD, corpus.JP2],
    )
    def test_a_format_a_scan_never_is(self, tmp_path: Path, data: bytes) -> None:
        verdict = check(corpus.write(tmp_path / "file.bin", data))
        assert not verdict.ok
        assert "not one of the formats a scan can be" in verdict.reasons[0]

    def test_an_unknown_format(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "file.bin", b"nothing to see here"))
        assert verdict.format is None
        assert verdict.reasons[0].startswith("is an unknown format")

    @pytest.mark.parametrize(
        ("what", "head"),
        [
            ("a PILfont", b"PILfont\n;;;;;;1;\nDATA\n" + b"\x00" * 64),
            ("a BDF font", b"STARTFONT 2.1\nFONT -misc-fixed\n"),
            ("a PCF font", b"\x01fcp" + b"\x00" * 60),
            ("a TrueType font", b"\x00\x01\x00\x00\x00\x0c\x00\x80\x00\x03\x00\x20"),
            ("an OpenType font", b"OTTO\x00\x0c\x00\x80\x00\x03\x00\x20"),
            (
                "a tar archive",
                b"scan.jpg".ljust(100, b"\x00") + b"0000644\x00" * 7 + b"\x00" * 101 + b"ustar\x00",
            ),
            ("a GD2 image", b"gd2\x00\x00\x02\x00\x08\x00\x08"),
        ],
    )
    def test_a_font_or_archive_is_refused_as_unknown(
        self, tmp_path: Path, what: str, head: bytes
    ) -> None:
        # A file that carries a flaw's trigger is refused by the format gate
        # whatever its format, so the records on fonts and archives claim it
        # (CVE-2026-96641, CVE-2026-55379, CVE-2026-54059, CVE-2026-54060,
        # CVE-2026-42308, CVE-2026-112893, CVE-2026-96642, CVE-2026-55380).
        verdict = check(corpus.write(tmp_path / "file.bin", head))
        assert verdict.format is None, what
        assert verdict.reasons[0].startswith("is an unknown format"), what

    @pytest.mark.parametrize(
        ("name", "data"),
        [
            ("scan.png", corpus.png(0, 10)),
            ("scan.tif", corpus.tiff([(10, 0)])),
            ("scan.jpg", corpus.jpeg(0, 10)),
        ],
    )
    def test_an_image_with_a_zero_dimension(self, tmp_path: Path, name: str, data: bytes) -> None:
        # CVE-2026-112392: a zero-size image dereferences a null pointer in
        # Pillow's rank filters. A file whose header gives a zero width or
        # height is refused under every policy, before Pillow sees it.
        verdict = check(corpus.write(tmp_path / name, data))
        assert not verdict.ok
        assert "zero width or height" in verdict.reasons[0], verdict.reasons

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
        assert verdict.reasons == (
            "a page of 10,000,000,000 pixels; the limit is 89,478,485",
            "a page 100,000 pixels on its longest side; the limit is 30,000",
        )
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
        assert verdict.reasons == (
            "a page of 4,294,836,225 pixels; the limit is 89,478,485",
            "a page 65,535 pixels on its longest side; the limit is 30,000",
        )
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

    def test_a_pixarlog_tiff(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "scan.tif", corpus.tiff([(10, 10)], compression=32909))
        verdict = check(path)
        assert verdict.reasons == (
            "a pixar-compressed TIFF; the policy allows none, ccitt, lzw, jpeg, deflate "
            "and packbits",
        )
        assert verdict.facts is not None and verdict.facts.compression == "pixar"

    def test_the_policy_can_allow_a_scheme(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "scan.tif", corpus.tiff([(10, 10)], compression=50000))
        assert check(path, Policy(tiff_compressions=frozenset({"zstd"}))).ok
        verdict = check(path, Policy(tiff_compressions=frozenset({"lzw"})))
        assert verdict.reasons == ("a zstd-compressed TIFF; the policy allows lzw",)

    def test_a_cielab_tiff(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "scan.tif", corpus.tiff([(10, 10)], layout=(8, 3, 8)))
        verdict = check(path)
        assert verdict.reasons == (
            "a cielab TIFF; the policy allows greyscale, rgb, palette, cmyk and ycbcr",
        )
        assert verdict.facts is not None and verdict.facts.colour == "cielab"
        assert check(path, Policy(tiff_photometrics=frozenset({"cielab"}))).ok

    def test_a_ycbcr_tiff_subsampled_four_by_four(self, tmp_path: Path) -> None:
        data = corpus.tiff([(10, 10)], layout=(6, 3, 8), subsampling=(4, 4))
        path = corpus.write(tmp_path / "scan.tif", data)
        assert check(path).reasons == (
            "a ycbcr TIFF subsampled 4x4; the policy allows 1x1, 2x1, 1x2 and 2x2",
        )
        assert check(path, Policy(tiff_subsamplings=frozenset({"4x4"}))).ok
        usual = corpus.write(tmp_path / "usual.tif", corpus.tiff([(10, 10)], layout=(6, 3, 8)))
        verdict = check(usual)
        assert verdict.ok and verdict.facts is not None and verdict.facts.subsampling == "2x2"

    def test_a_tiled_tiff_passes_by_default_and_not_under_strict(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "map.tif", corpus.tiff([(5000, 5000)], tile=(512, 512)))
        verdict = check(path)
        assert verdict.ok and verdict.facts is not None and verdict.facts.tile == (512, 512)
        assert check(path, STRICT).reasons == ("a tiled TIFF; the policy allows strips only",)
        assert check(path, Policy(allow_tiled_tiff=False)).reasons == (
            "a tiled TIFF; the policy allows strips only",
        )

    def test_a_tile_bigger_than_the_pixel_limit(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "scan.tif", corpus.tiff([(10, 10)], tile=(65_535, 65_535)))
        assert check(path).reasons == (
            "a tile of 4,294,836,225 pixels; the limit is 89,478,485",
            "a tile 65,535 pixels on its longest side; the limit is 30,000",
        )

    def test_a_tall_narrow_tiff(self, tmp_path: Path) -> None:
        """Within the pixel budget, but 40,000 pixels tall: what CVE-2025-9900 needs."""
        path = corpus.write(tmp_path / "tall.tif", corpus.tiff([(2_000, 40_000)], long_dims=True))
        verdict = check(path)
        assert verdict.reasons == ("a page 40,000 pixels on its longest side; the limit is 30,000",)
        assert verdict.facts is not None and verdict.facts.max_side == 40_000
        assert verdict.facts.max_pixels == 80_000_000
        assert check(path, Policy(max_side=40_000)).ok

    def test_a_tall_frame_among_many(self, tmp_path: Path) -> None:
        frames = [(10, 10), (5, 35_000), (10, 10)]
        path = corpus.write(tmp_path / "scan.tif", corpus.tiff(frames, long_dims=True))
        assert check(path).reasons == (
            "a page 35,000 pixels on its longest side; the limit is 30,000",
        )

    def test_a_long_thin_tile(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "scan.tif", corpus.tiff([(10, 10)], tile=(40_000, 10)))
        assert check(path).reasons == (
            "a tile 40,000 pixels on its longest side; the limit is 30,000",
        )

    def test_a_tiff_that_changes_mode_between_frames(self, tmp_path: Path) -> None:
        path = corpus.write(
            tmp_path / "scan.tif",
            corpus.tiff([(10, 10), (10, 10)], layout=[(1, 1, 8), (2, 3, 8)]),
        )
        assert check(path).reasons == (
            "the header could not be read: frame 2 is rgb, 3 samples of 8 bits where frame 1 "
            "is greyscale, 1 sample of 8 bits",
        )

    def test_a_tiff_that_changes_scheme_between_frames(self, tmp_path: Path) -> None:
        path = corpus.write(
            tmp_path / "scan.tif", corpus.tiff([(10, 10), (10, 10)], compression=[1, 5])
        )
        assert check(path).reasons == (
            "the header could not be read: frame 2 is compressed with lzw where frame 1 is "
            "compressed with none",
        )

    def test_an_interlaced_png(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "scan.png", corpus.png(10, 10, interlace=1))
        assert check(path).reasons == ("an interlaced PNG; the policy does not allow interlacing",)
        assert check(path, Policy(allow_interlaced_png=True)).ok
        verdict = check(path, Policy(allow_interlaced_png=True))
        assert verdict.facts is not None and verdict.facts.interlaced

    def test_a_palette_png_under_a_scans_only_policy(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "scan.png", corpus.png(10, 10, colour=3, depth=8))
        assert check(path).ok
        verdict = check(path, Policy(png_colour_types=frozenset({"greyscale", "rgb"})))
        assert verdict.reasons == ("a palette PNG; the policy allows greyscale and rgb",)

    def test_a_sixteen_bit_png_is_strict_only_by_default(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "scan.png", corpus.png(10, 10, colour=0, depth=16))
        assert check(path).ok
        assert check(path, STRICT).reasons == ("a 16-bit PNG; the limit is 8 bits",)

    def test_a_png_with_an_enormous_exif_chunk(self, tmp_path: Path) -> None:
        data = corpus.png(10, 10, after_idat=corpus.png_chunk(b"eXIf", 5_000_000))
        verdict = check(corpus.write(tmp_path / "scan.png", data))
        assert verdict.reasons == ("a PNG eXIf chunk of 5,000,000 bytes; the limit is 4,194,304",)
        assert verdict.facts is not None and verdict.facts.metadata == ("PNG eXIf chunk", 5_000_000)

    def test_strict_allows_less_metadata(self, tmp_path: Path) -> None:
        data = corpus.jpeg(10, 10, before_sof=corpus.jpeg_profile(2_000_000))
        path = corpus.write(tmp_path / "scan.jpg", data)
        assert check(path).ok
        assert check(path, STRICT).reasons == (
            "a JPEG colour profile of 2,000,000 bytes; the limit is 1,048,576",
        )
        assert (
            check(path, Policy(max_metadata_bytes=1_999_999))
            .reasons[0]
            .startswith("a JPEG colour profile")
        )

    def test_a_jpeg_profile_that_fills_the_encoder_buffer(self, tmp_path: Path) -> None:
        # CVE-2026-96778: a 65,498-byte profile fills Pillow's 64 KB JPEG
        # output buffer exactly, and a comment written after it overflows.
        # Both ride from the opened file into a save that keeps the profile.
        # The profile is the measured block; a ceiling under it refuses the file.
        data = corpus.jpeg(10, 10, before_sof=corpus.jpeg_profile(65_498) + corpus.jpeg_padding(1))
        path = corpus.write(tmp_path / "scan.jpg", data)
        assert check(path).ok
        verdict = check(path, Policy(max_metadata_bytes=65_000))
        assert verdict.reasons == ("a JPEG colour profile of 65,498 bytes; the limit is 65,000",)

    def test_a_png_text_chunk_under_a_lower_ceiling(self, tmp_path: Path) -> None:
        # CVE-2026-112891: a comment carried from an opened file is copied in
        # quadratic time when the image is saved as a GIF. From a file it can
        # only come through a PNG text chunk, whose size the reader measures.
        data = corpus.png(10, 10, extra=corpus.png_chunk(b"tEXt", 1_000_000))
        path = corpus.write(tmp_path / "scan.png", data)
        assert check(path).ok
        verdict = check(path, Policy(max_metadata_bytes=65_536))
        assert verdict.reasons == ("a PNG tEXt chunk of 1,000,000 bytes; the limit is 65,536",)

    def test_an_animated_png_that_declares_too_many_frames(self, tmp_path: Path) -> None:
        # CVE-2026-112894: Pillow's PDF writer takes time proportional to the
        # square of the frame count it reads from the file before seeking any
        # frame. The acTL count is read here and bounded by max_pages.
        data = corpus.png(10, 10, frames=2**31 - 1)
        verdict = check(corpus.write(tmp_path / "scan.png", data))
        assert verdict.reasons == ("2,147,483,647 pages; the limit is 500",)

    def test_a_tiff_tag_over_the_limit(self, tmp_path: Path) -> None:
        data = corpus.tiff([(10, 10)], tags=[(34377, 7, b"\x00" * 4_194_305)])
        verdict = check(corpus.write(tmp_path / "scan.tif", data))
        assert verdict.reasons == (
            "a TIFF tag 34,377 (Photoshop) of 4,194,305 bytes; the limit is 4,194,304",
        )

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
        assert verdict.reasons == (
            "a page of 2,400,000,000 pixels; the limit is 89,478,485",
            "a page 60,000 pixels on its longest side; the limit is 30,000",
        )

    def test_a_tall_narrow_page(self, tmp_path: Path) -> None:
        """5 x 200 inches: 40 million pixels at 200 dpi, within the budget, but 40,000 tall."""
        sizes = [(595.0, 842.0), (360.0, 14400.0)]
        verdict = check(corpus.write(tmp_path / "tall.pdf", corpus.pdf(2, sizes=sizes)))
        assert verdict.reasons == ("a page 40,000 pixels on its longest side; the limit is 30,000",)
        assert verdict.facts is not None and verdict.facts.max_side == 40_000

    def test_a_file_that_is_not_a_pdf_inside(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "broken.pdf", b"%PDF-1.4\ngarbage"))
        assert not verdict.ok
        assert verdict.reasons[0].startswith(
            "the header could not be read: pdfinfo could not read it"
        )

    def test_strict_is_shorter(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "long.pdf", corpus.pdf(150)), STRICT)
        assert verdict.reasons == ("150 pages; the limit is 100",)

    def test_a_plain_pdf_carries_no_features(self, tmp_path: Path) -> None:
        verdict = check(corpus.write(tmp_path / "plain.pdf", corpus.pdf(1)))
        assert verdict.ok and verdict.facts is not None and verdict.facts.features == ()
        assert verdict.facts.codecs == ()

    @pytest.mark.parametrize(
        ("feature", "codec", "words"),
        [
            ("jpeg", "jpeg", "JPEG"),
            ("jpx", "jpx", "JPEG 2000"),
            ("jbig2", "jbig2", "JBIG2"),
            ("escaped-jbig2", "jbig2", "JBIG2"),
            ("ccitt", "ccitt", "CCITT"),
        ],
    )
    def test_an_image_codec_passes_by_default_and_is_refused_by_name(
        self, tmp_path: Path, feature: str, codec: str, words: str
    ) -> None:
        path = corpus.write(tmp_path / "scan.pdf", corpus.pdf_with(feature))

        verdict = check(path)

        assert verdict.ok and verdict.facts is not None and verdict.facts.codecs == (codec,)
        assert check(path, STRICT).ok
        refused = check(path, Policy(pdf_image_codecs=frozenset(PDF_IMAGE_CODECS) - {codec}))
        assert not refused.ok
        assert refused.reasons[0].startswith(
            f"a PDF with images coded as {words}; the policy allows "
        )

    def test_a_jbig2_pdf_under_a_policy_that_refuses_it(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "scan.pdf", corpus.pdf_with("jbig2"))
        verdict = check(path, Policy(pdf_image_codecs=frozenset({"jpeg", "jpx", "ccitt"})))
        assert verdict.reasons == (
            "a PDF with images coded as JBIG2; the policy allows JPEG, JPEG 2000 and CCITT",
        )
        assert check(path, Policy(pdf_image_codecs=frozenset())).reasons == (
            "a PDF with images coded as JBIG2; "
            "the policy allows none of the image codecs a PDF can carry",
        )

    @pytest.mark.parametrize(
        ("feature", "found", "words"),
        [
            ("javascript", "javascript", "JavaScript"),
            ("document-javascript", "javascript", "JavaScript"),
            ("escaped-javascript", "javascript", "JavaScript"),
            ("forms", "forms", "a form"),
            ("attachments", "attachments", "attached files"),
            ("launch", "launch", "a launch action"),
            ("escaped-launch", "launch", "a launch action"),
        ],
    )
    def test_a_pdf_with_a_feature_a_scan_never_has(
        self, tmp_path: Path, feature: str, found: str, words: str
    ) -> None:
        path = corpus.write(tmp_path / "doc.pdf", corpus.pdf_with(feature))

        verdict = check(path)

        assert verdict.reasons == (
            f"a PDF with {words}; the policy allows none of the features a PDF can carry",
        )
        assert verdict.facts is not None and verdict.facts.features == (found,)
        assert check(path, Policy(pdf_features=frozenset({found}))).ok

    def test_the_policy_names_what_it_allows(self, tmp_path: Path) -> None:
        path = corpus.write(tmp_path / "form.pdf", corpus.pdf_with("forms"))
        verdict = check(path, Policy(pdf_features=frozenset({"javascript", "attachments"})))
        assert verdict.reasons == (
            "a PDF with a form; the policy allows JavaScript and attached files",
        )

    def test_a_long_pdf_still_reports_what_the_summary_shows(self, tmp_path: Path) -> None:
        """Over the page limit nothing more is asked of the file, but what pdfinfo already said is kept."""
        path = corpus.write(tmp_path / "long.pdf", corpus.pdf_with("document-javascript", pages=3))
        verdict = check(path, Policy(max_pages=2))
        assert verdict.reasons == (
            "3 pages; the limit is 2",
            "a PDF with JavaScript; the policy allows none of the features a PDF can carry",
        )


class TestPolicy:
    def test_presets(self) -> None:
        assert DEFAULT.max_pages == 500 and STRICT.max_pages == 100
        assert DEFAULT.max_side == 30_000 and STRICT.max_side == 15_000
        assert STRICT.max_bytes < DEFAULT.max_bytes

    @pytest.mark.parametrize(
        ("changes", "reason"),
        [
            ({"formats": frozenset({"webp"})}, "unknown format"),
            ({"formats": frozenset()}, "at least one format"),
            ({"jpeg_frames": frozenset({"baseline", "mpeg"})}, "unknown JPEG frame coding"),
            ({"jpeg_frames": frozenset()}, "at least one JPEG frame coding"),
            ({"tiff_compressions": frozenset({"lzw", "rar"})}, "unknown TIFF compression"),
            ({"tiff_compressions": frozenset()}, "at least one TIFF compression"),
            ({"tiff_photometrics": frozenset({"hsv"})}, "unknown TIFF photometric"),
            ({"tiff_photometrics": frozenset()}, "at least one TIFF photometric"),
            ({"tiff_subsamplings": frozenset({"3x3"})}, "unknown TIFF subsampling"),
            ({"tiff_subsamplings": frozenset()}, "at least one TIFF subsampling"),
            ({"max_pages": 0}, "max_pages must be at least 1"),
            ({"max_side": 0}, "max_side must be at least 1"),
            ({"max_metadata_bytes": 0}, "max_metadata_bytes must be at least 1"),
            ({"png_colour_types": frozenset({"cmyk"})}, "unknown PNG colour type"),
            ({"png_colour_types": frozenset()}, "at least one PNG colour type"),
            ({"max_png_bit_depth": 12}, "must be 1, 2, 4, 8 or 16"),
            ({"pdfinfo_timeout": 0}, "must be positive"),
            ({"pdf_features": frozenset({"macros"})}, "unknown PDF feature"),
            ({"pdf_image_codecs": frozenset({"webp"})}, "unknown PDF image codec"),
        ],
    )
    def test_refuses_an_impossible_policy(self, changes: dict[str, object], reason: str) -> None:
        with pytest.raises(ValueError, match=reason):
            Policy(**changes)  # type: ignore[arg-type]
