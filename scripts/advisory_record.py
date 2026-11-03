"""The advisory record: what each triaged advisory means for sillybos, as data.

``docs/advisories/record/<KEY>.json`` holds one file per advisory that has
been triaged (``docs/advisories/README.md`` says how): the advisory's own
facts, the bucket it landed in, the finding, which check refuses the
triggering file and under which policy, the tests that prove it, and how
anyone could protect themselves whether or not they use this library.

``docs/advisories/record.json`` is the merged file that other things read:
the documentation's coverage page, and the security watch on tetrak.dev,
which fetches it at build time. It is generated, never edited::

    python scripts/advisory_record.py validate   # every file against the schema
    python scripts/advisory_record.py export     # write record.json
    python scripts/advisory_record.py export --check   # fail if record.json is stale

``docs/advisories/proposed/`` holds records that have been drafted but not
yet confirmed by a person: the same shape, written from the advisory's text
by whoever (or whatever) read it, waiting for a maintainer to agree with the
bucket and the finding. Nothing reads them but these two commands; the
export never includes them, so the watch on tetrak.dev shows only what a
person has confirmed::

    python scripts/advisory_record.py proposals        # what is waiting, by bucket
    python scripts/advisory_record.py promote KEY...   # confirm: move into record/, dated today

A proposal in bucket A, B or B2 cannot be promoted until the test it names
exists; a B finding is a policy field and a corpus case first.

Standard library only, like the rest of the repository.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
RECORD_DIR = ROOT / "docs" / "advisories" / "record"
RECORD_FILE = ROOT / "docs" / "advisories" / "record.json"
PROPOSED_DIR = ROOT / "docs" / "advisories" / "proposed"
TESTS_DIR = ROOT / "tests"

#: The buckets of docs/advisories/README.md, in its words.
BUCKETS = {
    "A": "Already refused by an existing check",
    "B": "Preventable from a header field our readers can see",
    "B2": "Preventable only by a coarse policy on a PDF's contents",
    "C": "Needs decoding to detect; out of this library's reach by design",
    "D": "Reaches pdfinfo itself",
    "N": "The check is not in the path: no file carries the trigger",
    "U": "A reserved CVE with no text yet",
}

#: How the triggering input reaches the flaw.
REACHED_BY = {
    "open": "by opening or reading a file",
    "save": "on a save or encode path",
    "api": "through a call beyond opening, such as a filter or transform",
    "tool": "through a command-line tool, not the library",
    "other": "some other way; the finding says",
}

#: The buckets in which a refusal is claimed and so must be proved.
REFUSING_BUCKETS = {"A", "B", "B2"}

KEY = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|PYSEC-\d{4}-\d+)$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TEST_ID = re.compile(r"^(tests/[\w/]+\.py)::(?:(\w+)::)?(\w+)$")

REQUIRED: dict[str, type | tuple[type, ...]] = {
    "key": str,
    "aliases": list,
    "library": str,
    "package": str,
    "ecosystem": str,
    "title": str,
    "summary": str,
    "published": (str, type(None)),
    "severity": (int, float, type(None)),
    "affected": str,
    "fixed": (str, type(None)),
    "reached_by": str,
    "trigger": str,
    "bucket": str,
    "finding": str,
    "refusal": (dict, type(None)),
    "verified_by": list,
    "protect": dict,
    "sources": list,
    "triaged": str,
    "checked": str,
    "notes": (str, type(None)),
}


def load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
    return data


def _test_exists(test_id: str, tests_dir: Path) -> bool:
    """True if the test the id names is defined, read from the file's text."""
    match = TEST_ID.match(test_id)
    if match is None:
        return False
    file, cls, name = match.groups()
    path = tests_dir.parent / file
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    if cls is not None and not re.search(rf"^class {cls}\b", text, re.MULTILINE):
        return False
    return re.search(rf"^\s*def {name}\(", text, re.MULTILINE) is not None


def problems(record: dict[str, Any], path: Path, tests_dir: Path = TESTS_DIR) -> list[str]:
    """Everything wrong with one record, in sentences; empty when it is sound."""
    found: list[str] = []
    for field, kind in REQUIRED.items():
        if field not in record:
            found.append(f"missing {field}")
        elif not isinstance(record[field], kind):
            found.append(f"{field} is {type(record[field]).__name__}")
    extra = set(record) - set(REQUIRED)
    if extra:
        found.append(f"unknown fields: {', '.join(sorted(extra))}")
    if found:
        return found

    key = record["key"]
    if not KEY.match(key):
        found.append(f"key {key!r} is not a CVE, GHSA or PYSEC id")
    if path.stem != key:
        found.append(f"file is named {path.name}, key is {key}")
    for alias in record["aliases"]:
        if not isinstance(alias, str) or not KEY.match(alias):
            found.append(f"alias {alias!r} is not a CVE, GHSA or PYSEC id")
    if key in record["aliases"]:
        found.append("key repeated in aliases")
    if record["bucket"] not in BUCKETS:
        found.append(f"bucket {record['bucket']!r} is not one of {', '.join(BUCKETS)}")
    if record["reached_by"] not in REACHED_BY:
        found.append(f"reached_by {record['reached_by']!r} is not one of {', '.join(REACHED_BY)}")
    for field in ("published", "triaged", "checked"):
        value = record[field]
        if value is not None and not DATE.match(value):
            found.append(f"{field} {value!r} is not YYYY-MM-DD")
    if record["checked"] < record["triaged"]:
        found.append("checked is before triaged")
    for field in ("title", "trigger", "finding"):
        if not record[field].strip():
            found.append(f"{field} is empty")
    protect = record["protect"]
    for part in ("general", "specific"):
        if not isinstance(protect.get(part), str) or not protect[part].strip():
            found.append(f"protect.{part} is missing or empty")
    if not record["sources"] or not all(
        isinstance(s, str) and s.startswith("https://") for s in record["sources"]
    ):
        found.append("sources must be one or more https links")

    refusal = record["refusal"]
    claims = record["bucket"] in REFUSING_BUCKETS
    if claims and refusal is None:
        found.append(f"bucket {record['bucket']} claims a refusal but refusal is null")
    if not claims and refusal is not None:
        found.append(f"bucket {record['bucket']} claims no refusal but refusal is set")
    if refusal is not None:
        for part, kind in (("check", str), ("default", bool), ("setting", str)):
            if not isinstance(refusal.get(part), kind):
                found.append(f"refusal.{part} is missing or not {kind.__name__}")
    if claims and not record["verified_by"]:
        found.append("a claimed refusal needs at least one test in verified_by")
    if not claims and record["verified_by"]:
        found.append("verified_by names tests but no refusal is claimed")
    for test_id in record["verified_by"]:
        if not isinstance(test_id, str) or not TEST_ID.match(test_id):
            found.append(f"verified_by {test_id!r} is not tests/file.py::Class::test_name")
        elif not _test_exists(test_id, tests_dir):
            found.append(f"verified_by names a test that does not exist: {test_id}")
    return found


def validate(record_dir: Path = RECORD_DIR, tests_dir: Path = TESTS_DIR) -> dict[Path, list[str]]:
    """Every record's problems, keyed by file; an empty dict means all sound."""
    result: dict[Path, list[str]] = {}
    seen: dict[str, Path] = {}
    for path in sorted(record_dir.glob("*.json")):
        try:
            record = load(path)
        except (OSError, ValueError) as exc:
            result[path] = [f"not readable as JSON: {exc}"]
            continue
        found = problems(record, path, tests_dir)
        for name in [record.get("key"), *record.get("aliases", [])]:
            if isinstance(name, str):
                if name in seen and seen[name] != path:
                    found.append(f"{name} is also in {seen[name].name}")
                seen.setdefault(name, path)
        if found:
            result[path] = found
    return result


def _sort_key(record: dict[str, Any]) -> tuple[str, str]:
    # Newest first; an undated record sorts after the dated ones.
    return (record["published"] or "0000-00-00", record["key"])


def merged(record_dir: Path = RECORD_DIR, today: str | None = None) -> dict[str, Any]:
    """The merged record: the records, newest first, and the counts."""
    records = [load(path) for path in sorted(record_dir.glob("*.json"))]
    records.sort(key=_sort_key, reverse=True)
    by_bucket = {bucket: 0 for bucket in BUCKETS}
    by_library: dict[str, int] = {}
    refused_by_default = 0
    for record in records:
        by_bucket[record["bucket"]] += 1
        by_library[record["library"]] = by_library.get(record["library"], 0) + 1
        if record["refusal"] is not None and record["refusal"]["default"]:
            refused_by_default += 1
    return {
        "generated": today or date.today().isoformat(),
        "buckets": BUCKETS,
        "reached_by": REACHED_BY,
        "counts": {
            "records": len(records),
            "refused_by_default": refused_by_default,
            "by_bucket": by_bucket,
            "by_library": dict(sorted(by_library.items())),
        },
        "records": records,
    }


def render(record_dir: Path = RECORD_DIR, today: str | None = None) -> str:
    return json.dumps(merged(record_dir, today), indent=2, ensure_ascii=False) + "\n"


def is_current(record_file: Path = RECORD_FILE, record_dir: Path = RECORD_DIR) -> bool:
    """True if record.json matches the records, ignoring the generated date."""
    if not record_file.is_file():
        return False
    current: dict[str, Any] = json.loads(record_file.read_text(encoding="utf-8"))
    fresh = merged(record_dir, today=current.get("generated"))
    return bool(current == fresh)


def proposals(proposed_dir: Path = PROPOSED_DIR, tests_dir: Path = TESTS_DIR) -> list[str]:
    """One line per proposal, grouped by bucket, with what still stands in its way."""
    lines: list[str] = []
    by_bucket: dict[str, list[tuple[str, str, list[str]]]] = {}
    for path in sorted(proposed_dir.glob("*.json")):
        record = load(path)
        found = problems(record, path, tests_dir)
        by_bucket.setdefault(str(record.get("bucket")), []).append(
            (str(record.get("key")), str(record.get("title", "")), found)
        )
    for bucket in sorted(by_bucket, key=lambda b: list(BUCKETS).index(b) if b in BUCKETS else 99):
        entries = by_bucket[bucket]
        lines.append(f"{bucket} ({len(entries)}): {BUCKETS.get(bucket, 'unknown bucket')}")
        for key, title, found in entries:
            flag = f"  [{'; '.join(found)}]" if found else ""
            lines.append(f"  {key}  {title}{flag}")
    if not lines:
        lines.append("nothing proposed")
    return lines


UNCONFIRMED = "not yet confirmed by a person"
"""What a proposal's ``notes`` says until it is promoted; ``promote`` rewrites it."""


def promote(
    keys: list[str],
    today: str,
    proposed_dir: Path = PROPOSED_DIR,
    record_dir: Path = RECORD_DIR,
    tests_dir: Path = TESTS_DIR,
) -> list[str]:
    """Confirm proposals: validate each strictly, date it today, move it into the record.

    A note saying the record is not yet confirmed by a person becomes one
    saying when it was.

    Returns the problems that stopped any of them; empty when all moved.
    """
    stopped: list[str] = []
    for key in keys:
        source = proposed_dir / f"{key}.json"
        if not source.is_file():
            stopped.append(f"{key}: no proposal")
            continue
        record = load(source)
        record["triaged"] = today
        record["checked"] = today
        if isinstance(record.get("notes"), str):
            record["notes"] = record["notes"].replace(
                UNCONFIRMED, f"confirmed by a person on {today}"
            )
        target = record_dir / source.name
        found = problems(record, target, tests_dir)
        if target.exists():
            found.append("already in the record")
        if found:
            stopped.append(f"{key}: " + "; ".join(found))
            continue
        target.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        source.unlink()
    return stopped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", choices=("validate", "export", "proposals", "promote"))
    parser.add_argument("keys", nargs="*", help="for promote: the proposals to confirm")
    parser.add_argument("--check", action="store_true", help="export: fail if record.json is stale")
    args = parser.parse_args(argv)

    if args.command == "proposals":
        print("\n".join(proposals()))
        return 0
    if args.command == "promote":
        if not args.keys:
            print("promote: name the proposals to confirm", file=sys.stderr)
            return 2
        stopped = promote(args.keys, date.today().isoformat())
        for line in stopped:
            print(f"not promoted: {line}", file=sys.stderr)
        moved = len(args.keys) - len(stopped)
        if moved:
            RECORD_FILE.write_text(render(), encoding="utf-8")
            print(f"promoted {moved}; wrote {RECORD_FILE.relative_to(ROOT)}")
        return 1 if stopped else 0

    found = validate()
    for path, lines in found.items():
        for line in lines:
            print(f"{path.relative_to(ROOT)}: {line}", file=sys.stderr)
    if found:
        return 1
    if args.command == "validate":
        print(f"{len(list(RECORD_DIR.glob('*.json')))} records are sound")
        return 0
    if args.check:
        if is_current():
            print(f"{RECORD_FILE.relative_to(ROOT)} is current")
            return 0
        print(
            f"{RECORD_FILE.relative_to(ROOT)} is stale: run `python scripts/advisory_record.py export`",
            file=sys.stderr,
        )
        return 1
    RECORD_FILE.write_text(render(), encoding="utf-8")
    print(f"wrote {RECORD_FILE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
