"""The header readers, against hand-made files and against Pillow's own reading of real ones."""

from __future__ import annotations

import io

import pytest
from PIL import Image

from sillybos import headers
from sillybos.headers import HeaderError
from tests import corpus


def read(fmt: str, data: bytes, limit: int = 500) -> headers.Header:
    return headers.READERS[fmt](io.BytesIO(data), len(data), limit)


class TestJpeg:
    def test_reads_the_dimensions_from_the_frame_header(self) -> None:
        assert read("jpeg", corpus.jpeg(4000, 6000)) == headers.Header(4000, 6000, 1, 24_000_000)

    def test_skips_segments_before_the_frame(self) -> None:
        data = corpus.jpeg(30, 20, before_sof=corpus.jpeg_padding(50))
        assert read("jpeg", data).width == 30

    def test_a_progressive_frame_counts_too(self) -> None:
        data = corpus.jpeg(30, 20).replace(b"\xff\xc0", b"\xff\xc2")
        assert read("jpeg", data).height == 20

    @pytest.mark.parametrize(
        ("data", "reason"),
        [
            (b"\xff\xd8\xff", "ends inside"),
            (corpus.jpeg(30, 20, sof=False), "image data starts before"),
            (corpus.jpeg(0, 20), "zero width"),
            (
                corpus.jpeg(30, 20, before_sof=corpus.jpeg_padding(headers.MAX_SEGMENTS)),
                "no frame header",
            ),
            (b"\xff\xd8\x00\x00", "does not start with a marker"),
            (b"\xff\xd8\xff\xe0\x00\x01", "shorter than its own length"),
            (b"\xff\xd8\xff\xe0\xff\xff", "runs past the end"),
        ],
    )
    def test_refuses_a_malformed_header(self, data: bytes, reason: str) -> None:
        with pytest.raises(HeaderError, match=reason):
            read("jpeg", data)

    def test_a_deferred_height_is_refused(self) -> None:
        with pytest.raises(HeaderError, match="DNL"):
            read("jpeg", corpus.jpeg(30, 0))


class TestPng:
    def test_reads_the_dimensions_from_ihdr(self) -> None:
        assert read("png", corpus.png(640, 480)) == headers.Header(640, 480, 1, 307_200)

    def test_counts_the_frames_of_an_animated_png(self) -> None:
        assert read("png", corpus.png(10, 10, frames=12)).pages == 12

    def test_a_pixel_bomb_is_read_without_decoding(self) -> None:
        """A 100-byte file whose header claims ten billion pixels."""
        data = corpus.png(100_000, 100_000)
        assert len(data) < 100
        assert read("png", data).max_pixels == 10_000_000_000

    @pytest.mark.parametrize(
        ("data", "reason"),
        [
            (corpus.PNG_SIGNATURE + b"\x00\x00\x00\x0dIDAT", "not a 13-byte IHDR"),
            (corpus.png(0, 10), "zero width"),
            (corpus.png(1 << 31, 10), "width or height of"),
            (corpus.png(10, 10, extra=b"\xff\xff\xff\xfftEXt"), "runs past the end"),
            (corpus.png(10, 10, frames=0), "zero frames"),
        ],
    )
    def test_refuses_a_malformed_header(self, data: bytes, reason: str) -> None:
        with pytest.raises(HeaderError, match=reason):
            read("png", data)


class TestTiff:
    @pytest.mark.parametrize("endian", ["<", ">"])
    def test_reads_every_frame_in_either_byte_order(self, endian: str) -> None:
        data = corpus.tiff([(200, 300), (400, 600), (50, 50)], endian=endian)
        assert read("tiff", data) == headers.Header(200, 300, 3, 240_000)

    def test_reads_long_dimensions(self) -> None:
        data = corpus.tiff([(70_000, 2)], long_dims=True)
        assert read("tiff", data).width == 70_000

    def test_stops_walking_at_the_limit(self) -> None:
        """Ten thousand frames cost the time of the limit, and are reported as over it."""
        data = corpus.tiff([(10, 10)] * 10_000)
        header = read("tiff", data, limit=100)
        assert header.pages == 101 and not header.complete

    @pytest.mark.parametrize(
        ("data", "reason"),
        [
            (corpus.tiff([(10, 10)], loop_to_first=True), "loops back"),
            (corpus.tiff([(10, 10)], dangling=True), "outside the file"),
            (corpus.tiff([(10, 10)], drop_height=True), "no width or height"),
            (corpus.tiff([(0, 10)]), "zero width"),
            (b"II*\x00\x08\x00\x00\x00\xff\xff", "runs past the end"),
            (b"II*\x00\x00\x00\x00\x00", "no frames"),
            (b"XX*\x00" + b"\x00" * 8, "byte-order"),
            (b"II+\x00" + b"\x00" * 12, "BigTIFF"),
        ],
    )
    def test_refuses_a_malformed_header(self, data: bytes, reason: str) -> None:
        with pytest.raises(HeaderError, match=reason):
            read("tiff", data)


class TestAgainstPillow:
    """Real files, as Pillow writes them: our readers agree with Pillow's."""

    @pytest.mark.parametrize(("fmt", "mode"), [("JPEG", "RGB"), ("PNG", "RGBA"), ("TIFF", "1")])
    def test_single_images(self, fmt: str, mode: str) -> None:
        buffer = io.BytesIO()
        Image.new(mode, (123, 45)).save(buffer, format=fmt)
        data = buffer.getvalue()
        assert read(fmt.lower(), data) == headers.Header(123, 45, 1, 123 * 45)

    def test_a_multi_frame_tiff(self) -> None:
        buffer = io.BytesIO()
        first, *rest = [Image.new("L", (20 + i, 30)) for i in range(4)]
        first.save(buffer, format="TIFF", save_all=True, append_images=rest)
        header = read("tiff", buffer.getvalue())
        with Image.open(buffer) as image:
            assert header.pages == getattr(image, "n_frames", 1) == 4
        assert header.max_pixels == 23 * 30

    def test_a_progressive_jpeg_and_an_exif_jpeg(self) -> None:
        buffer = io.BytesIO()
        image = Image.new("RGB", (64, 32))
        exif = image.getexif()
        exif[0x0110] = "a camera"
        image.save(buffer, format="JPEG", progressive=True, exif=exif)
        assert read("jpeg", buffer.getvalue()).width == 64
