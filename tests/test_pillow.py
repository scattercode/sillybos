from __future__ import annotations

from pathlib import Path

import pytest
from PIL import Image, UnidentifiedImageError

from sillybos import Policy, Refused
from sillybos.pillow import open_checked, pillow_formats
from tests import corpus


def test_pillow_formats_from_the_policy() -> None:
    assert pillow_formats() == ["JPEG", "PNG", "TIFF"]
    assert pillow_formats(Policy(formats=frozenset({"pdf", "tiff"}))) == ["TIFF"]


def test_opens_a_checked_scan(tmp_path: Path) -> None:
    path = tmp_path / "scan.jpg"
    Image.new("RGB", (30, 20), "white").save(path)
    with open_checked(path) as image:
        assert image.size == (30, 20) and image.format == "JPEG"


def test_refuses_before_pillow_sees_it(tmp_path: Path) -> None:
    with pytest.raises(Refused, match="says PNG, is PostScript"):
        open_checked(corpus.write(tmp_path / "page.png", corpus.POSTSCRIPT))


def test_pillow_is_told_which_readers_it_may_use(tmp_path: Path) -> None:
    """A GIF that somehow passed would still not reach the GIF reader."""
    path = tmp_path / "scan.gif"
    Image.new("P", (5, 5)).save(path)
    with pytest.raises(Refused):
        open_checked(path)
    with pytest.raises(UnidentifiedImageError):
        Image.open(path, formats=pillow_formats())
