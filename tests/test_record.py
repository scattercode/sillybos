"""The advisory record: every committed record is sound, and record.json is current."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts import advisory_record as ar

SOUND: dict[str, Any] = {
    "key": "CVE-2026-1001",
    "aliases": ["GHSA-aaaa-bbbb-cccc"],
    "library": "Pillow",
    "package": "pillow",
    "ecosystem": "PyPI",
    "title": "A thing",
    "summary": "What upstream said.",
    "published": "2026-10-21",
    "severity": 9.2,
    "affected": "< 13.0.0",
    "fixed": "13.0.0",
    "reached_by": "open",
    "trigger": "Opening it.",
    "bucket": "A",
    "finding": "Refused by name.",
    "refusal": {"check": "formats", "default": True, "setting": "always"},
    "verified_by": ["tests/test_check.py::TestHostileFiles::test_a_renamed_postscript_file"],
    "protect": {"general": "Upgrade.", "specific": "Allow-list formats."},
    "sources": ["https://github.com/advisories/GHSA-aaaa-bbbb-cccc"],
    "triaged": "2026-11-01",
    "checked": "2026-11-01",
    "notes": None,
}


def _write(tmp_path: Path, record: dict[str, Any], name: str | None = None) -> Path:
    path = tmp_path / f"{name or record['key']}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


class TestTheCommittedRecords:
    def test_every_record_is_sound(self) -> None:
        assert ar.validate() == {}

    def test_every_record_is_in_the_baseline(self) -> None:
        """So the weekly job never opens an issue for an advisory already triaged."""
        state = json.loads((ar.ROOT / "docs/advisories/seen.json").read_text(encoding="utf-8"))
        known = set(state["seen"]) | set(state.get("pending", []))
        for path in ar.RECORD_DIR.glob("*.json"):
            record = ar.load(path)
            names = {record["key"], *record["aliases"]}
            assert names & known, f"{path.name} is not in seen.json; run `advisories.py record`"

    def test_record_json_is_current(self) -> None:
        assert ar.is_current(), "run `python scripts/advisory_record.py export`"

    def test_the_merged_file_counts_what_it_holds(self) -> None:
        merged = ar.merged()
        assert merged["counts"]["records"] == len(merged["records"])
        assert sum(merged["counts"]["by_bucket"].values()) == len(merged["records"])
        published = [r["published"] or "" for r in merged["records"]]
        assert published == sorted(published, reverse=True)


class TestProblems:
    def test_a_sound_record_has_none(self, tmp_path: Path) -> None:
        assert ar.problems(SOUND, _write(tmp_path, SOUND), ar.TESTS_DIR) == []

    @pytest.mark.parametrize(
        ("change", "expected"),
        [
            ({"bucket": "Z"}, "bucket 'Z' is not one of"),
            ({"reached_by": "magic"}, "reached_by 'magic' is not one of"),
            ({"published": "October"}, "published 'October' is not YYYY-MM-DD"),
            ({"checked": "2026-10-01"}, "checked is before triaged"),
            ({"finding": "  "}, "finding is empty"),
            ({"sources": ["http://insecure"]}, "sources must be one or more https links"),
            ({"protect": {"general": "x"}}, "protect.specific is missing or empty"),
            ({"aliases": ["CVE-2026-1001"]}, "key repeated in aliases"),
            ({"refusal": None}, "bucket A claims a refusal but refusal is null"),
            ({"verified_by": []}, "a claimed refusal needs at least one test"),
            ({"bucket": "N", "refusal": None}, "verified_by names tests but no refusal is claimed"),
            ({"bucket": "N", "verified_by": []}, "bucket N claims no refusal but refusal is set"),
            (
                {
                    "verified_by": [
                        "tests/test_check.py::TestHostileFiles::test_nothing_of_the_sort"
                    ]
                },
                "names a test that does not exist",
            ),
            (
                {"verified_by": ["tests/test_check.py::TestNoSuchClass::test_a_pixel_bomb"]},
                "names a test that does not exist",
            ),
            ({"verified_by": ["test_a_pixel_bomb"]}, "is not tests/file.py::Class::test_name"),
            ({"refusal": {"check": "formats", "default": "yes", "setting": ""}}, "refusal.default"),
            ({"extra": 1}, "unknown fields: extra"),
            ({"severity": "high"}, "severity is str"),
        ],
    )
    def test_catches(self, tmp_path: Path, change: dict[str, Any], expected: str) -> None:
        record = {**SOUND, **change}
        found = ar.problems(record, _write(tmp_path, record), ar.TESTS_DIR)
        assert any(expected in line for line in found), found

    def test_a_missing_field_is_reported_first(self, tmp_path: Path) -> None:
        record = {k: v for k, v in SOUND.items() if k != "trigger"}
        assert ar.problems(record, _write(tmp_path, record, "CVE-2026-1001"), ar.TESTS_DIR) == [
            "missing trigger"
        ]

    def test_the_file_must_be_named_after_the_key(self, tmp_path: Path) -> None:
        found = ar.problems(SOUND, _write(tmp_path, SOUND, "CVE-2026-1002"), ar.TESTS_DIR)
        assert found == ["file is named CVE-2026-1002.json, key is CVE-2026-1001"]


class TestValidate:
    def test_two_files_naming_one_advisory(self, tmp_path: Path) -> None:
        _write(tmp_path, SOUND)
        other = {**SOUND, "key": "CVE-2026-1002", "aliases": ["GHSA-aaaa-bbbb-cccc"]}
        _write(tmp_path, other)
        found = ar.validate(tmp_path, ar.TESTS_DIR)
        assert [p.name for p in found] == ["CVE-2026-1002.json"]
        assert found[tmp_path / "CVE-2026-1002.json"] == [
            "GHSA-aaaa-bbbb-cccc is also in CVE-2026-1001.json"
        ]

    def test_unreadable_json(self, tmp_path: Path) -> None:
        (tmp_path / "CVE-2026-1001.json").write_text("{", encoding="utf-8")
        found = ar.validate(tmp_path, ar.TESTS_DIR)
        assert "not readable as JSON" in found[tmp_path / "CVE-2026-1001.json"][0]


class TestExport:
    def test_render_is_stable_and_counts(self, tmp_path: Path) -> None:
        _write(tmp_path, SOUND)
        _write(tmp_path, {**SOUND, "key": "CVE-2026-1002", "aliases": [], "published": None})
        merged = ar.merged(tmp_path, today="2026-11-01")
        assert merged["generated"] == "2026-11-01"
        assert [r["key"] for r in merged["records"]] == ["CVE-2026-1001", "CVE-2026-1002"]
        assert merged["counts"] == {
            "records": 2,
            "refused_by_default": 2,
            "by_bucket": {"A": 2, "B": 0, "B2": 0, "C": 0, "D": 0, "N": 0, "U": 0},
            "by_library": {"Pillow": 2},
        }
        assert ar.render(tmp_path, "2026-11-01") == ar.render(tmp_path, "2026-11-01")

    def test_is_current_ignores_the_date_and_sees_a_change(self, tmp_path: Path) -> None:
        _write(tmp_path, SOUND)
        out = tmp_path.parent / f"{tmp_path.name}-record.json"
        out.write_text(ar.render(tmp_path, "2020-01-01"), encoding="utf-8")
        assert ar.is_current(out, tmp_path)
        _write(tmp_path, {**SOUND, "key": "CVE-2026-1002", "aliases": []})
        assert not ar.is_current(out, tmp_path)
        assert not ar.is_current(tmp_path / "missing.json", tmp_path)


class TestTheProposals:
    def test_every_proposal_has_the_record_shape(self) -> None:
        """A proposal is a record awaiting a person; only the refusal's test may be missing."""
        recorded = {ar.load(p)["key"] for p in ar.RECORD_DIR.glob("*.json")}
        for path in sorted(ar.PROPOSED_DIR.glob("*.json")):
            record = ar.load(path)
            found = [
                line
                for line in ar.problems(record, path)
                if "claims a refusal but refusal is null" not in line
                and "needs at least one test" not in line
            ]
            assert not found, f"{path.name}: {found}"
            assert record["key"] not in recorded, f"{path.name} is already in the record"
            assert record["notes"], f"{path.name} must say it is a proposal"

    def test_listing_groups_by_bucket_and_flags_what_is_in_the_way(self, tmp_path: Path) -> None:
        _write(tmp_path, SOUND)
        _write(
            tmp_path,
            {
                **SOUND,
                "key": "CVE-2026-1002",
                "aliases": [],
                "bucket": "B2",
                "refusal": None,
                "verified_by": [],
            },
        )
        lines = ar.proposals(tmp_path)
        assert lines[0].startswith("A (1)") and "CVE-2026-1001" in lines[1]
        assert lines[2].startswith("B2 (1)") and "needs at least one test" in lines[3]

    def test_an_empty_folder_says_so(self, tmp_path: Path) -> None:
        assert ar.proposals(tmp_path) == ["nothing proposed"]

    def test_promote_moves_a_sound_proposal_and_dates_it(self, tmp_path: Path) -> None:
        proposed, record = tmp_path / "proposed", tmp_path / "record"
        proposed.mkdir()
        record.mkdir()
        _write(proposed, {**SOUND, "triaged": "2026-01-01", "checked": "2026-01-01"})

        assert ar.promote(["CVE-2026-1001"], "2026-11-02", proposed, record) == []

        moved = ar.load(record / "CVE-2026-1001.json")
        assert (moved["triaged"], moved["checked"]) == ("2026-11-02", "2026-11-02")
        assert not (proposed / "CVE-2026-1001.json").exists()

    def test_promote_marks_the_note_as_confirmed(self, tmp_path: Path) -> None:
        proposed, record = tmp_path / "proposed", tmp_path / "record"
        proposed.mkdir()
        record.mkdir()
        _write(
            proposed, {**SOUND, "notes": "Proposed on 2026-11-01; not yet confirmed by a person."}
        )

        assert ar.promote(["CVE-2026-1001"], "2026-11-02", proposed, record) == []

        moved = ar.load(record / "CVE-2026-1001.json")
        assert moved["notes"] == "Proposed on 2026-11-01; confirmed by a person on 2026-11-02."

    def test_promote_refuses_what_is_not_ready(self, tmp_path: Path) -> None:
        proposed, record = tmp_path / "proposed", tmp_path / "record"
        proposed.mkdir()
        record.mkdir()
        _write(
            proposed,
            {
                **SOUND,
                "key": "CVE-2026-1002",
                "aliases": [],
                "bucket": "B",
                "refusal": None,
                "verified_by": [],
            },
        )
        _write(record, SOUND)
        _write(proposed, SOUND)

        stopped = ar.promote(
            ["CVE-2026-1002", "CVE-2026-1001", "CVE-2026-9999"], "2026-11-02", proposed, record
        )

        assert len(stopped) == 3
        assert "needs at least one test" in stopped[0]
        assert "already in the record" in stopped[1]
        assert stopped[2] == "CVE-2026-9999: no proposal"
        assert (proposed / "CVE-2026-1002.json").exists()
