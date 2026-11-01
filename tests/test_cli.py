from __future__ import annotations

import json
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
