"""The header readers, against hand-made files and against Pillow's own reading of real ones."""

from __future__ import annotations

import dataclasses
import io
import os
import struct

import pytest
from PIL import Image, TiffImagePlugin

from sillybos import (
    JPEG_FRAMES,
    PNG_COLOUR_TYPES,
    TIFF_COMPRESSIONS,
    TIFF_PHOTOMETRICS,
    TIFF_SUBSAMPLINGS,
    headers,
)
from sillybos.headers import HeaderError
from tests import corpus


def read(fmt: str, data: bytes, limit: int = 500) -> headers.Header:
    return headers.READERS[fmt](io.BytesIO(data), len(data), limit)


class TestJpeg:
    def test_reads_the_dimensions_from_the_frame_header(self) -> None:
        assert read("jpeg", corpus.jpeg(4000, 6000)) == headers.Header(
            4000, 6000, 1, 24_000_000, 6000, coding="baseline"
        )

    def test_skips_segments_before_the_frame(self) -> None:
        data = corpus.jpeg(30, 20, before_sof=corpus.jpeg_padding(50))
        assert read("jpeg", data).width == 30

    def test_a_progressive_frame_counts_too(self) -> None:
        data = corpus.jpeg(30, 20).replace(b"\xff\xc0", b"\xff\xc2")
        assert read("jpeg", data) == headers.Header(30, 20, 1, 600, 30, coding="progressive")

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
        assert read("jpeg", data) == headers.Header(30, 20, 3, 2000, 50, coding="baseline")

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
        assert read("png", corpus.png(640, 480)) == headers.Header(
            640, 480, 1, 307_200, 640, colour="rgb", depth=8
        )

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
        assert read("tiff", data) == headers.Header(
            200, 300, 3, 240_000, 600, compression="none", colour="greyscale", depth=1
        )

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


class TestTiffCompression:
    def test_no_tag_means_uncompressed(self) -> None:
        assert read("tiff", corpus.tiff([(10, 10)])).compression == "none"

    @pytest.mark.parametrize(
        ("code", "name"),
        [
            (1, "none"),
            (2, "ccitt"),
            (4, "ccitt"),
            (5, "lzw"),
            (6, "old-jpeg"),
            (7, "jpeg"),
            (8, "deflate"),
            (32946, "deflate"),
            (32773, "packbits"),
            (32909, "pixar"),
            (34661, "jbig"),
            (34712, "jpeg2000"),
            (50001, "webp"),
        ],
    )
    def test_names_the_scheme(self, code: int, name: str) -> None:
        header = read("tiff", corpus.tiff([(10, 10), (10, 10)], compression=code))
        assert header == headers.Header(
            10, 10, 2, 100, 10, compression=name, colour="greyscale", depth=1
        )

    def test_every_scheme_name_is_one_the_policy_knows(self) -> None:
        assert set(headers._COMPRESSIONS.values()) <= set(TIFF_COMPRESSIONS)

    def test_the_scheme_is_reported_when_the_walk_stops_early(self) -> None:
        header = read("tiff", corpus.tiff([(10, 10)] * 8, compression=5), limit=3)
        assert not header.complete and header.compression == "lzw"

    @pytest.mark.parametrize(
        ("data", "reason"),
        [
            (corpus.tiff([(10, 10)], compression=12345), "compression code 12,345, which is not"),
            (
                corpus.tiff([(10, 10), (10, 10)], compression=[5, 7]),
                "frame 2 is compressed with jpeg where frame 1 is compressed with lzw",
            ),
            (
                corpus.tiff([(10, 10), (10, 10)], compression=[None, 5]),
                "frame 2 is compressed with lzw where frame 1 is compressed with none",
            ),
        ],
    )
    def test_refuses_an_unknown_or_mixed_scheme(self, data: bytes, reason: str) -> None:
        with pytest.raises(HeaderError, match=reason):
            read("tiff", data)

    def test_a_compression_tag_with_two_values_is_refused(self) -> None:
        data = corpus.tiff([(10, 10)], compression=5)
        broken = data.replace(struct.pack("<HHI", 259, 3, 1), struct.pack("<HHI", 259, 3, 2))
        with pytest.raises(HeaderError, match="a compression tag holds more than one value"):
            read("tiff", broken)


class TestPngKind:
    """Bit depth, colour type and interlacing from IHDR, and the combinations it forbids."""

    def test_the_default_is_eight_bit_rgb(self) -> None:
        header = read("png", corpus.png(10, 10))
        assert (header.colour, header.depth, header.interlaced) == ("rgb", 8, False)

    @pytest.mark.parametrize(
        ("colour", "depth", "name"),
        [
            (0, 1, "greyscale"),
            (0, 16, "greyscale"),
            (3, 4, "palette"),
            (4, 8, "greyscale-alpha"),
            (6, 16, "rgba"),
        ],
    )
    def test_names_the_colour_type(self, colour: int, depth: int, name: str) -> None:
        header = read("png", corpus.png(10, 10, colour=colour, depth=depth))
        assert (header.colour, header.depth) == (name, depth)

    def test_every_name_is_one_the_policy_knows(self) -> None:
        assert {name for name, _ in headers._COLOUR_TYPES.values()} == set(PNG_COLOUR_TYPES)

    def test_interlaced(self) -> None:
        assert read("png", corpus.png(10, 10, interlace=1)).interlaced

    @pytest.mark.parametrize(
        ("data", "reason"),
        [
            (corpus.png(10, 10, colour=1), "colour type of 1"),
            (corpus.png(10, 10, colour=7), "colour type of 7"),
            (corpus.png(10, 10, colour=2, depth=4), "bit depth of 4 for a rgb image"),
            (corpus.png(10, 10, colour=3, depth=16), "bit depth of 16 for a palette image"),
            (corpus.png(10, 10, colour=0, depth=3), "bit depth of 3 for a greyscale image"),
            (corpus.png(10, 10, methods=(1, 0)), "compression or filter method other than 0"),
            (corpus.png(10, 10, methods=(0, 1)), "compression or filter method other than 0"),
            (corpus.png(10, 10, interlace=2), "interlace method of 2"),
        ],
    )
    def test_refuses_an_impossible_ihdr(self, data: bytes, reason: str) -> None:
        with pytest.raises(HeaderError, match=reason):
            read("png", data)


class TestMetadata:
    """The largest block of metadata each reader passes over, for the policy to bound."""

    def test_the_largest_png_chunk_before_the_image_data(self) -> None:
        extra = corpus.png_chunk(b"iCCP", 3000) + corpus.png_chunk(b"tEXt", 500)
        assert read("png", corpus.png(10, 10, extra=extra)).metadata == ("PNG iCCP chunk", 3000)

    def test_a_png_chunk_after_the_image_data_counts(self) -> None:
        data = corpus.png(10, 10, after_idat=corpus.png_chunk(b"eXIf", 70_000), idats=40)
        assert read("png", data).metadata == ("PNG eXIf chunk", 70_000)

    def test_png_image_data_is_skipped_not_measured(self) -> None:
        data = corpus.png(10, 10, extra=corpus.png_chunk(b"IDAT", 90_000))
        assert read("png", data).metadata is None

    def test_a_png_with_too_many_image_data_chunks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(headers, "MAX_IDAT_CHUNKS", 10)
        with pytest.raises(HeaderError, match="more than 10 image-data chunks"):
            read("png", corpus.png(10, 10, idats=11))

    def test_a_png_with_too_many_other_chunks(self) -> None:
        data = corpus.png(10, 10, extra=corpus.png_chunk(b"tEXt", 0) * headers.MAX_SEGMENTS)
        with pytest.raises(HeaderError, match="chunks besides the image data"):
            read("png", data)

    def test_a_png_chunk_type_that_is_not_letters(self) -> None:
        with pytest.raises(HeaderError, match="not four letters"):
            read("png", corpus.png(10, 10, extra=corpus.png_chunk(b"eX\x00f", 4)))

    def test_a_png_chunk_after_the_image_data_that_runs_past_the_end(self) -> None:
        data = corpus.png(10, 10, after_idat=b"\x00\x10\x00\x00eXIf")
        with pytest.raises(HeaderError, match="runs past the end"):
            read("png", data)

    def test_a_jpeg_colour_profile_summed_across_segments(self) -> None:
        data = corpus.jpeg(10, 10, before_sof=corpus.jpeg_profile(200_000))
        assert read("jpeg", data).metadata == ("JPEG colour profile", 200_000)

    def test_a_jpeg_without_a_profile_has_no_metadata_block(self) -> None:
        assert read("jpeg", corpus.jpeg(10, 10, before_sof=corpus.jpeg_padding(3))).metadata is None

    def test_the_largest_tiff_tag_data(self) -> None:
        tags = [(700, 1, b"<xmp/>" * 1000), (270, 2, b"a scan\x00")]
        header = read("tiff", corpus.tiff([(10, 10)], tags=tags))
        assert header.metadata == ("TIFF tag 700 (XMP)", 6000)

    def test_an_unlabelled_tiff_tag(self) -> None:
        header = read("tiff", corpus.tiff([(10, 10)], tags=[(50_000, 7, b"\x00" * 99)]))
        assert header.metadata == ("TIFF tag 50,000", 99)

    def test_tiff_tag_data_inside_the_field_is_not_a_block(self) -> None:
        assert read("tiff", corpus.tiff([(10, 10)], tags=[(296, 3, b"\x02\x00")])).metadata is None

    @pytest.mark.parametrize("type_", [4, 12, 99])
    def test_tiff_tag_data_outside_the_file(self, type_: int) -> None:
        data = corpus.tiff([(10, 10)], tags=[(700, type_, b"\x00" * 64)], data_outside=True)
        with pytest.raises(HeaderError, match="frame 1's tag 700 data lies outside the file"):
            read("tiff", data)

    def test_a_tiff_tag_claiming_more_data_than_the_file_holds(self) -> None:
        data = corpus.tiff([(10, 10)]).replace(
            struct.pack("<HHI", 256, 3, 1), struct.pack("<HHI", 256, 3, 1 << 30)
        )
        with pytest.raises(HeaderError, match="tag 256 data lies outside the file"):
            read("tiff", data)


class TestTiffPhotometric:
    def test_white_and_black_is_zero_are_both_greyscale(self) -> None:
        data = corpus.tiff([(10, 10), (10, 10)], layout=[(0, 1, 1), (1, 1, 1)])
        header = read("tiff", data)
        assert (header.colour, header.depth, header.pages) == ("greyscale", 1, 2)

    @pytest.mark.parametrize(
        ("code", "name"),
        [
            (2, "rgb"),
            (3, "palette"),
            (4, "mask"),
            (5, "cmyk"),
            (6, "ycbcr"),
            (8, "cielab"),
            (32803, "cfa"),
            (34892, "linear-raw"),
        ],
    )
    def test_names_the_photometric(self, code: int, name: str) -> None:
        assert read("tiff", corpus.tiff([(10, 10)], layout=(code, 3, 8))).colour == name

    def test_every_name_is_one_the_policy_knows(self) -> None:
        assert set(headers._PHOTOMETRICS.values()) == set(TIFF_PHOTOMETRICS)

    def test_an_unknown_photometric_is_refused(self) -> None:
        with pytest.raises(HeaderError, match="photometric interpretation 99, which is not"):
            read("tiff", corpus.tiff([(10, 10)], layout=(99, 3, 8)))

    def test_ycbcr_defaults_to_two_by_two(self) -> None:
        assert read("tiff", corpus.tiff([(10, 10)], layout=(6, 3, 8))).subsampling == "2x2"

    def test_reads_the_subsampling_tag(self) -> None:
        data = corpus.tiff([(10, 10)], layout=(6, 3, 8), subsampling=(4, 4))
        assert read("tiff", data).subsampling == "4x4"

    def test_subsampling_is_ignored_unless_ycbcr(self) -> None:
        data = corpus.tiff([(10, 10)], layout=RGB, subsampling=(4, 4))
        assert read("tiff", data).subsampling is None

    def test_every_subsampling_name_is_one_the_policy_knows(self) -> None:
        names = {f"{h}x{v}" for h in (1, 2, 4) for v in (1, 2, 4)}
        assert names == set(TIFF_SUBSAMPLINGS)

    @pytest.mark.parametrize(
        ("data", "reason"),
        [
            (corpus.tiff([(10, 10)], layout=(6, 3, 8), subsampling=(3, 1)), "subsampling of 3x1"),
            (corpus.tiff([(10, 10)], layout=(6, 3, 8), subsampling=(2, 0)), "subsampling of 2x0"),
            (
                corpus.tiff([(10, 10)] * 2, layout=(6, 3, 8), subsampling=[(2, 2), (1, 1)]),
                "frame 2 is subsampled 1x1 where frame 1 is subsampled 2x2",
            ),
            (
                corpus.tiff([(10, 10)], layout=(6, 3, 8)).replace(
                    struct.pack("<HHI", 277, 3, 1), struct.pack("<HHI", 530, 3, 1)
                ),
                "subsampling tag is not two SHORTs",
            ),
        ],
    )
    def test_refuses_a_malformed_subsampling(self, data: bytes, reason: str) -> None:
        with pytest.raises(HeaderError, match=reason):
            read("tiff", data)


class TestTiffTiles:
    def test_strips_have_no_tile(self) -> None:
        assert read("tiff", corpus.tiff([(10, 10)])).tile is None

    def test_the_largest_tile_across_frames(self) -> None:
        data = corpus.tiff([(1000, 1000)] * 3, tile=[(256, 256), (512, 256), (16, 16)])
        assert read("tiff", data).tile == (512, 256)

    def test_a_tile_larger_than_the_image_is_legal(self) -> None:
        assert read("tiff", corpus.tiff([(100, 100)], tile=(256, 256))).tile == (256, 256)

    @pytest.mark.parametrize(
        ("data", "reason"),
        [
            (corpus.tiff([(10, 10)], tile=(16, None)), "tile width or length but not both"),
            (corpus.tiff([(10, 10)], tile=(None, 16)), "tile width or length but not both"),
            (corpus.tiff([(10, 10)], tile=(0, 16)), "frame 1's tile gives a zero width"),
            (
                corpus.tiff([(10, 10)], tile=(16, 1 << 31)),
                "frame 1's tile gives a width or height of",
            ),
        ],
    )
    def test_refuses_a_malformed_tiling(self, data: bytes, reason: str) -> None:
        with pytest.raises(HeaderError, match=reason):
            read("tiff", data)


GREY = (1, 1, 8)
RGB = (2, 3, 8)


class TestTiffLayout:
    """Every frame must share the first frame's photometric, samples and bit depth."""

    def test_defaults_when_the_tags_are_absent(self) -> None:
        assert read("tiff", corpus.tiff([(10, 10), (10, 10)])).pages == 2

    def test_a_shared_layout_passes_with_bits_out_of_line(self) -> None:
        data = corpus.tiff([(10, 10), (20, 20), (30, 30)], layout=RGB)
        assert read("tiff", data).pages == 3

    @pytest.mark.parametrize("endian", ["<", ">"])
    def test_in_either_byte_order(self, endian: str) -> None:
        data = corpus.tiff([(10, 10), (10, 10)], layout=[(2, 4, 16), (2, 4, 16)], endian=endian)
        assert read("tiff", data).pages == 2

    @pytest.mark.parametrize(
        ("layouts", "reason"),
        [
            ([GREY, RGB], "frame 2 is rgb, 3 samples of 8 bits where frame 1 is greyscale"),
            ([GREY, (1, 1, 16)], "frame 2 is greyscale, 1 sample of 16 bits"),
            ([RGB, (2, 4, 8)], "frame 2 is rgb, 4 samples of 8 bits where frame 1 is rgb, 3"),
            ([GREY, None], "frame 2 is greyscale, 1 sample of 1 bits"),
            ([(5, 4, 8), (6, 3, 8)], "frame 2 is ycbcr, 3 samples of 8 bits where frame 1 is cmyk"),
        ],
    )
    def test_refuses_a_frame_that_changes_layout(
        self, layouts: list[corpus.Layout | None], reason: str
    ) -> None:
        with pytest.raises(HeaderError, match=reason):
            read("tiff", corpus.tiff([(10, 10), (10, 10)], layout=layouts))

    @pytest.mark.parametrize(
        ("data", "reason"),
        [
            (corpus.tiff([(10, 10)], layout=(2, 3, (8, 8, 16))), "different bit depths per sample"),
            (corpus.tiff([(10, 10)], layout=(1, 2, (8, 16))), "different bit depths per sample"),
            (corpus.tiff([(10, 10)], layout=(2, 3, 8), data_outside=True), "outside the file"),
            (corpus.tiff([(10, 10)], layout=(2, 65, 8)), "lists 65 samples"),
            (
                corpus.tiff([(10, 10)], layout=GREY).replace(
                    struct.pack("<HHI", 258, 3, 1), struct.pack("<HHI", 258, 4, 1)
                ),
                "bits-per-sample tag is not SHORT",
            ),
            (
                corpus.tiff([(10, 10)], layout=GREY).replace(
                    struct.pack("<HHI", 262, 3, 1), struct.pack("<HHI", 262, 3, 2)
                ),
                "photometric tag holds more than one value",
            ),
        ],
    )
    def test_refuses_a_malformed_layout(self, data: bytes, reason: str) -> None:
        with pytest.raises(HeaderError, match=reason):
            read("tiff", data)


class TestAgainstPillow:
    """Real files, as Pillow writes them: our readers agree with Pillow's."""

    @pytest.mark.parametrize(("fmt", "mode"), [("JPEG", "RGB"), ("PNG", "RGBA"), ("TIFF", "1")])
    def test_single_images(self, fmt: str, mode: str) -> None:
        buffer = io.BytesIO()
        Image.new(mode, (123, 45)).save(buffer, format=fmt)
        data = buffer.getvalue()
        expected = headers.Header(123, 45, 1, 123 * 45, 123)
        if fmt == "JPEG":
            expected = dataclasses.replace(expected, coding="baseline")
        elif fmt == "PNG":
            expected = dataclasses.replace(expected, colour="rgba", depth=8)
        else:
            expected = dataclasses.replace(
                expected, compression="none", colour="greyscale", depth=1
            )
        assert read(fmt.lower(), data) == expected

    @pytest.mark.parametrize(
        ("mode", "pillow_name", "name"),
        [
            ("1", "group4", "ccitt"),
            ("L", "tiff_lzw", "lzw"),
            ("RGB", "jpeg", "jpeg"),
            ("L", "tiff_adobe_deflate", "deflate"),
            ("L", "packbits", "packbits"),
        ],
    )
    def test_compressed_tiffs(self, mode: str, pillow_name: str, name: str) -> None:
        buffer = io.BytesIO()
        Image.new(mode, (40, 24)).save(buffer, format="TIFF", compression=pillow_name)
        assert read("tiff", buffer.getvalue()).compression == name

    @pytest.mark.parametrize(
        ("mode", "colour", "depth"),
        [
            ("1", "greyscale", 1),
            ("L", "greyscale", 8),
            ("I;16", "greyscale", 16),
            ("P", "palette", 8),
            ("LA", "greyscale-alpha", 8),
            ("RGB", "rgb", 8),
            ("RGBA", "rgba", 8),
        ],
    )
    def test_png_kinds_as_pillow_writes_them(self, mode: str, colour: str, depth: int) -> None:
        buffer = io.BytesIO()
        image = Image.new(mode, (8, 8))
        if mode == "P":
            image.putpalette(list(range(256)) * 3)  # else Pillow writes the palette at 1 bit
        image.save(buffer, format="PNG")
        header = read("png", buffer.getvalue())
        assert (header.colour, header.depth, header.interlaced) == (colour, depth, False)

    @pytest.mark.parametrize(
        ("mode", "colour", "depth", "subsampling"),
        [
            ("1", "greyscale", 1, None),
            ("L", "greyscale", 8, None),
            ("I;16", "greyscale", 16, None),
            ("P", "palette", 8, None),
            ("RGB", "rgb", 8, None),
            ("CMYK", "cmyk", 8, None),
            ("YCbCr", "ycbcr", 8, "1x1"),
            ("LAB", "cielab", 8, None),
        ],
    )
    def test_tiff_photometrics_as_pillow_writes_them(
        self, mode: str, colour: str, depth: int, subsampling: str | None
    ) -> None:
        buffer = io.BytesIO()
        Image.new(mode, (8, 8)).save(buffer, format="TIFF")
        header = read("tiff", buffer.getvalue())
        assert (header.colour, header.depth, header.subsampling) == (colour, depth, subsampling)

    def test_a_tiled_tiff_as_pillow_reads_it(self) -> None:
        """Pillow does not write tiles, so a hand-made one is checked against its reading."""
        data = corpus.tiled_tiff(40, 24, 16)
        header = read("tiff", data)
        with Image.open(io.BytesIO(data)) as image:
            assert isinstance(image, TiffImagePlugin.TiffImageFile)
            image.load()
            assert (image.size, image.tag_v2[322], image.tag_v2[323]) == ((40, 24), 16, 16)
        assert header.width == 40 and header.height == 24 and header.tile == (16, 16)

    def test_metadata_blocks_as_pillow_writes_them(self) -> None:
        """The profile is incompressible so that a PNG's deflated iCCP stays its size."""
        profile = os.urandom(100_000)
        image = Image.new("RGB", (16, 16))
        exif = image.getexif()
        exif[0x010E] = "x" * 2000
        for fmt in ("JPEG", "PNG", "TIFF"):
            buffer = io.BytesIO()
            image.save(buffer, format=fmt, icc_profile=profile, exif=exif)
            header = read(fmt.lower(), buffer.getvalue())
            with Image.open(buffer) as back:
                assert len(back.info["icc_profile"]) == len(profile)
            assert header.metadata is not None
            assert header.metadata[1] >= len(profile), (fmt, header.metadata)
            assert header.metadata[1] < len(profile) + 100, (fmt, header.metadata)

    @pytest.mark.parametrize("mode", ["L", "RGB", "RGBA", "I;16"])
    def test_a_multi_frame_tiff(self, mode: str) -> None:
        buffer = io.BytesIO()
        first, *rest = [Image.new(mode, (20 + i, 30)) for i in range(4)]
        first.save(buffer, format="TIFF", save_all=True, append_images=rest)
        header = read("tiff", buffer.getvalue())
        with Image.open(buffer) as image:
            assert header.pages == getattr(image, "n_frames", 1) == 4
        assert header.max_pixels == 23 * 30

    def test_a_multi_frame_tiff_that_changes_mode_is_refused(self) -> None:
        """The shape of CVE-2026-96639: a later frame wider than the buffer sized for the first."""
        buffer = io.BytesIO()
        Image.new("L", (20, 30)).save(
            buffer, format="TIFF", save_all=True, append_images=[Image.new("RGB", (20, 30))]
        )
        with pytest.raises(HeaderError, match="frame 2 is rgb, 3 samples of 8 bits where frame 1"):
            read("tiff", buffer.getvalue())

    def test_a_progressive_jpeg_and_an_exif_jpeg(self) -> None:
        buffer = io.BytesIO()
        image = Image.new("RGB", (64, 32))
        exif = image.getexif()
        exif[0x0110] = "a camera"
        image.save(buffer, format="JPEG", progressive=True, exif=exif)
        assert read("jpeg", buffer.getvalue()) == headers.Header(
            64, 32, 1, 2048, 64, coding="progressive"
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
