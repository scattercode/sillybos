"""The header readers, against hand-made files and against Pillow's own reading of real ones."""

from __future__ import annotations

import io
import struct

import pytest
from PIL import Image

from sillybos import JPEG_FRAMES, headers
from sillybos.headers import HeaderError
from tests import corpus


def read(fmt: str, data: bytes, limit: int = 500) -> headers.Header:
    return headers.READERS[fmt](io.BytesIO(data), len(data), limit)


class TestJpeg:
    def test_reads_the_dimensions_from_the_frame_header(self) -> None:
        assert read("jpeg", corpus.jpeg(4000, 6000)) == headers.Header(
            4000, 6000, 1, 24_000_000, coding="baseline"
        )

    def test_skips_segments_before_the_frame(self) -> None:
        data = corpus.jpeg(30, 20, before_sof=corpus.jpeg_padding(50))
        assert read("jpeg", data).width == 30

    def test_a_progressive_frame_counts_too(self) -> None:
        data = corpus.jpeg(30, 20).replace(b"\xff\xc0", b"\xff\xc2")
        assert read("jpeg", data) == headers.Header(30, 20, 1, 600, coding="progressive")

    @pytest.mark.parametrize(
        ("marker", "coding"),
        [
            (0xC0, "baseline"),
            (0xC1, "extended"),
            (0xC2, "progressive"),
            (0xC3, "lossless"),
            (0xC5, "hierarchical"),
            (0xC7, "hierarchical"),
            (0xC9, "arithmetic"),
            (0xCB, "arithmetic"),
            (0xCF, "hierarchical"),
        ],
    )
    def test_names_the_frame_coding(self, marker: int, coding: str) -> None:
        assert read("jpeg", corpus.jpeg(30, 20, marker=marker)).coding == coding

    def test_every_coding_name_is_one_the_policy_knows(self) -> None:
        assert set(headers._FRAME_CODINGS.values()) <= set(JPEG_FRAMES)

    def test_reads_every_picture_of_a_multi_picture_file(self) -> None:
        data = corpus.mpo([(30, 20), (40, 50), (10, 10)])
        assert read("jpeg", data) == headers.Header(30, 20, 3, 2000, coding="baseline")

    def test_an_index_naming_one_picture_is_an_ordinary_jpeg(self) -> None:
        assert read("jpeg", corpus.mpo([(30, 20)])).pages == 1

    def test_stops_walking_pictures_at_the_limit(self) -> None:
        data = corpus.mpo([(10, 10)] * 12)
        header = read("jpeg", data, limit=5)
        assert header.pages == 6 and not header.complete
        assert read("jpeg", data).pages == 12

    @pytest.mark.parametrize(
        ("data", "reason"),
        [
            (corpus.mpo([(10, 10), (0, 10)]), "picture 2 gives a zero width or height"),
            (corpus.mpo([(10, 10), (10, 10)], markers=[0xC0, 0xC2]), "picture 2 is progressive"),
            (corpus.mpo([(10, 10), (10, 10)], components=[1, 3]), "picture 2 has 3 components"),
            (corpus.mpo([(10, 10), (10, 10)], declared=3), "names 3 pictures but lists 2"),
            (corpus.mpo([(10, 10), (10, 10)], stray=True), "picture 2 lies outside the file"),
            (corpus.mpo([(10, 10), (10, 10)], not_jpeg=True), "picture 2 is not coded as JPEG"),
            (corpus.mpo([(10, 10), (10, 10)], index=b"II*\x00"), "index is too short"),
            (corpus.mpo([(10, 10), (10, 10)], index=b"XX*\x00" + b"\x00" * 4), "byte-order"),
            (
                corpus.mpo([(10, 10), (10, 10)], index=b"II*\x00" + struct.pack("<I", 1 << 20)),
                "index lies outside its segment",
            ),
            (
                corpus.mpo([(10, 10), (10, 10)], index=b"II*\x00" + struct.pack("<IH", 8, 500)),
                "index runs past its segment",
            ),
            (
                corpus.mpo(
                    [(10, 10), (10, 10)],
                    index=b"II*\x00"
                    + struct.pack("<IH", 8, 1)
                    + struct.pack("<HHII", 0xB002, 7, 32, 1 << 20),
                ),
                "entries lie outside their segment",
            ),
        ],
    )
    def test_refuses_a_malformed_multi_picture_file(self, data: bytes, reason: str) -> None:
        with pytest.raises(HeaderError, match=reason):
            read("jpeg", data)

    def test_a_second_picture_that_is_not_a_jpeg(self) -> None:
        data = corpus.mpo([(10, 10), (10, 10)])
        second = data.rindex(b"\xff\xd8")
        broken = data[:second] + b"\x00\x00" + data[second + 2 :]
        with pytest.raises(HeaderError, match="no JPEG start-of-image marker in the picture 2"):
            read("jpeg", broken)

    def test_two_indexes_are_refused(self) -> None:
        data = corpus.mpo([(10, 10), (10, 10)])
        app2 = data[20 : 20 + 2 + struct.unpack(">H", data[22:24])[0]]
        with pytest.raises(HeaderError, match="two multi-picture indexes"):
            read("jpeg", data[:20] + app2 + data[20:])

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
        coding = "baseline" if fmt == "JPEG" else None
        assert read(fmt.lower(), data) == headers.Header(123, 45, 1, 123 * 45, coding=coding)

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
        assert read("jpeg", buffer.getvalue()) == headers.Header(
            64, 32, 1, 2048, coding="progressive"
        )

    def test_a_multi_picture_jpeg(self) -> None:
        buffer = io.BytesIO()
        first, *rest = [Image.new("RGB", (20 + i, 30)) for i in range(3)]
        first.save(buffer, format="MPO", save_all=True, append_images=rest)
        header = read("jpeg", buffer.getvalue())
        with Image.open(buffer) as image:
            assert header.pages == getattr(image, "n_frames", 1) == 3
            image.seek(2)
            assert header.max_pixels == image.width * image.height == 22 * 30
        assert header.coding == "baseline"
