from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from sillybos.cli import main
from tests import corpus


def test_passes_good_files_and_refuses_bad_ones(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    good = corpus.write(tmp_path / "good.png", corpus.png(10, 10))
    bad = corpus.write(tmp_path / "bad.png", corpus.POSTSCRIPT)

    assert main([str(good), str(bad)]) == 1

    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith(f"ok       {good}  (PNG, 10x10, 1 page")
    assert out[1] == f"refused  {bad}  says PNG, is PostScript"


def test_quiet_prints_only_refusals(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = corpus.write(tmp_path / "good.png", corpus.png(10, 10))
    assert main(["-q", str(good)]) == 0
    assert capsys.readouterr().out == ""


def test_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = corpus.write(tmp_path / "bomb.png", corpus.png(100_000, 100_000))
    assert main(["--json", str(bad)]) == 1
    record = json.loads(capsys.readouterr().out)
    assert record["ok"] is False
    assert record["facts"]["max_pixels"] == 10_000_000_000
    assert record["path"] == str(bad)


def test_options_adjust_the_policy(tmp_path: Path) -> None:
    png = corpus.write(tmp_path / "scan.png", corpus.png(10, 10))
    jpeg_called_png = corpus.write(tmp_path / "lie.png", corpus.jpeg(10, 10))
    assert main(["--max-pixels", "50", str(png)]) == 1
    assert main(["--formats", "jpeg,tiff", str(png)]) == 1
    lossless = corpus.write(tmp_path / "lossless.jpg", corpus.jpeg(10, 10, marker=0xC3))
    assert main([str(lossless)]) == 1
    assert main(["--jpeg-frames", "baseline,lossless", str(lossless)]) == 0
    webp_tiff = corpus.write(tmp_path / "webp.tif", corpus.tiff([(10, 10)], compression=50001))
    assert main([str(webp_tiff)]) == 1
    assert main(["--tiff-compressions", "none,webp", str(webp_tiff)]) == 0
    big_chunk = corpus.write(
        tmp_path / "chunk.png", corpus.png(10, 10, extra=corpus.png_chunk(b"zTXt", 5000))
    )
    assert main([str(big_chunk)]) == 0
    assert main(["--max-metadata-bytes", "4000", str(big_chunk)]) == 1
    deep = corpus.write(tmp_path / "deep.png", corpus.png(10, 10, colour=3, depth=8, interlace=1))
    assert main([str(deep)]) == 1
    assert main(["--interlaced-png", str(deep)]) == 0
    assert main(["--interlaced-png", "--png-colour-types", "rgb", str(deep)]) == 1
    assert main(["--interlaced-png", "--max-png-bit-depth", "4", str(deep)]) == 1
    tiled = corpus.write(tmp_path / "map.tif", corpus.tiff([(10, 10)], tile=(16, 16)))
    assert main([str(tiled)]) == 0
    assert main(["--no-tiled-tiff", str(tiled)]) == 1
    lab = corpus.write(tmp_path / "lab.tif", corpus.tiff([(10, 10)], layout=(8, 3, 8)))
    assert main([str(lab)]) == 1
    assert main(["--tiff-photometrics", "cielab", str(lab)]) == 0
    chroma = corpus.write(
        tmp_path / "chroma.tif", corpus.tiff([(10, 10)], layout=(6, 3, 8), subsampling=(4, 1))
    )
    assert main([str(chroma)]) == 1
    assert main(["--tiff-subsamplings", "2x2,4x1", str(chroma)]) == 0
    assert main(["--any-name", str(jpeg_called_png)]) == 0
    assert main(["--strict", "--max-bytes", "10", str(png)]) == 1


def test_a_bad_policy_is_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    png = corpus.write(tmp_path / "scan.png", corpus.png(10, 10))
    assert main(["--formats", "webp", str(png)]) == 2
    assert "unknown format" in capsys.readouterr().err


def test_a_missing_file_is_exit_2_and_the_rest_still_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    png = corpus.write(tmp_path / "scan.png", corpus.png(10, 10))
    assert main([str(tmp_path / "nowhere.png"), str(png)]) == 2
    captured = capsys.readouterr()
    assert "no such file" in captured.err
    assert captured.out.startswith("ok")


def test_version() -> None:
    with pytest.raises(SystemExit) as stop:
        main(["--version"])
    assert stop.value.code == 0


@pytest.mark.skipif(shutil.which("pdfinfo") is None, reason="pdfinfo (poppler)")
def test_pdf_features_can_be_allowed(tmp_path: Path) -> None:
    scripted = corpus.write(tmp_path / "scripted.pdf", corpus.pdf_with("javascript"))
    assert main([str(scripted)]) == 1
    assert main(["--pdf-features", "javascript", str(scripted)]) == 0
    assert main(["--pdf-features", "forms", str(scripted)]) == 1
