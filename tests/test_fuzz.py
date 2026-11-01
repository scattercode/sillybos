"""The header fuzzer runs, and a reader that misbehaves is a finding."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import fuzz_headers
from sillybos import headers


def test_a_short_run_finds_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(fuzz_headers, "FINDINGS", tmp_path / "findings")
    assert fuzz_headers.fuzz(seconds=30, iterations=2_000, seed_used=1, quiet=True) == 0
    assert not (tmp_path / "findings").exists()


def test_an_unexpected_exception_is_a_finding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(f: object, size: int, max_pages: int) -> None:
        raise ZeroDivisionError("a reader bug")

    monkeypatch.setattr(fuzz_headers, "FINDINGS", tmp_path / "findings")
    monkeypatch.setitem(headers.READERS, "png", broken)

    assert fuzz_headers.fuzz(seconds=30, iterations=300, seed_used=1, quiet=True) == 1

    notes = list((tmp_path / "findings").glob("*.txt"))
    assert notes and "ZeroDivisionError: a reader bug" in notes[0].read_text()
    assert "FINDING ZeroDivisionError" in capsys.readouterr().err


def test_main_parses_a_seed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(fuzz_headers, "FINDINGS", tmp_path / "findings")
    assert fuzz_headers.main(["--iterations", "50", "--seed", "3", "-q"]) == 0
