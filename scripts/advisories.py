"""Fetch the week's advisories for the libraries sillybos stands in front of.

Every week the Advisories workflow asks OSV.dev for the advisories on the
watchlist (Pillow on PyPI; tiff, libpng1.6, libjpeg-turbo, zlib, poppler,
openjpeg2 and freetype on Debian), drops what ``docs/advisories/seen.json``
and the repository's existing advisory issues already know, and opens one
GitHub issue per new advisory for a maintainer to triage into a bucket.
``docs/advisories/README.md`` says how.

Standard library only: the package has no runtime dependencies and this
script adds none. It runs locally too::

    python scripts/advisories.py fetch     # what is new; opens nothing
    python scripts/advisories.py run       # the weekly job; needs GITHUB_TOKEN and --repository
    python scripts/advisories.py record    # fold everything published so far into seen.json

Nothing is committed by the workflow. The issues it opens are the record of
what has been seen; ``seen.json`` is the baseline from the November 2026
backfill, which a maintainer refreshes with ``record`` when the issue list
has grown long enough to be worth folding in.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULNERABILITY = "https://osv.dev/vulnerability/"
GITHUB_API = "https://api.github.com"
TIMEOUT = 60  # seconds, per request
PAUSE = 1.0  # seconds between issues created

#: (package, ecosystem), as OSV names them. Debian without a release suffix
#: matches every release OSV carries.
WATCHLIST: tuple[tuple[str, str], ...] = (
    ("pillow", "PyPI"),
    ("tiff", "Debian"),
    ("libpng1.6", "Debian"),
    ("libjpeg-turbo", "Debian"),
    ("zlib", "Debian"),
    ("poppler", "Debian"),
    ("openjpeg2", "Debian"),
    ("freetype", "Debian"),
)

#: Debian's own bulletins repeat the per-CVE records with a release note
#: attached; the CVE record is the one we want.
BULLETIN_PREFIXES = ("DSA-", "DLA-", "DTSA-")

DEFAULT_STATE = Path("docs/advisories/seen.json")
ISSUE_LABEL = "advisory"
NOISE_LABEL = "likely-not-reached"
LABELS = {
    ISSUE_LABEL: ("0e8a16", "An advisory for a library sillybos stands in front of; needs triage"),
    NOISE_LABEL: (
        "c5def5",
        "A noise filter matched: the text names code that opening a file never runs",
    ),
}
MARKER = "sillybos-advisory"
TITLE_LIMIT = 200
DETAILS_LIMIT = 8_000

Http = Callable[[str, str, dict[str, Any] | None, dict[str, str] | None], Any]


# --- advisories -----------------------------------------------------------


@dataclass
class Advisory:
    """One advisory, after records that describe the same CVE are merged."""

    key: str
    ids: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    packages: list[tuple[str, str]] = field(default_factory=list)
    published: str = ""
    severity: str = ""
    summary: str = ""
    details: str = ""

    @property
    def reserved(self) -> bool:
        """A CVE that has been assigned but has no text yet: pending, not new."""
        return not (self.summary.strip() or self.details.strip())

    @property
    def text(self) -> str:
        return f"{self.summary}\n{self.details}"

    @property
    def identifiers(self) -> set[str]:
        return {self.key, *self.ids, *self.aliases}


def _severity(record: dict[str, Any]) -> str:
    word = str((record.get("database_specific") or {}).get("severity") or "").lower()
    scores = [str(s.get("score")) for s in record.get("severity") or [] if s.get("score")]
    return ", ".join(part for part in [word, *scores] if part)


def advisory_from(record: dict[str, Any], package: str, ecosystem: str) -> Advisory | None:
    """One OSV record as an advisory, or None for a bulletin or a withdrawn record."""
    osv_id = str(record["id"])
    if osv_id.startswith(BULLETIN_PREFIXES) or record.get("withdrawn"):
        return None
    aliases = sorted({str(a) for a in record.get("aliases") or []})
    cves = sorted(a for a in [osv_id.removeprefix("DEBIAN-"), *aliases] if a.startswith("CVE-"))
    return Advisory(
        key=cves[0] if cves else osv_id,
        ids=[osv_id],
        aliases=[a for a in aliases if a != osv_id],
        packages=[(package, ecosystem)],
        published=str(record.get("published") or "")[:10],
        severity=_severity(record),
        summary=str(record.get("summary") or ""),
        details=str(record.get("details") or ""),
    )


def merge(advisories: Iterable[Advisory]) -> list[Advisory]:
    """Dedupe by key (the CVE where there is one), oldest first.

    Pillow's GHSA and PYSEC records, and Debian's per-CVE record, describe
    one flaw; the record with a summary supplies the text.
    """
    merged: dict[str, Advisory] = {}
    for advisory in advisories:
        into = merged.get(advisory.key)
        if into is None:
            merged[advisory.key] = advisory
            continue
        into.ids = sorted({*into.ids, *advisory.ids})
        into.aliases = sorted({*into.aliases, *advisory.aliases} - set(into.ids))
        into.packages = sorted({*into.packages, *advisory.packages})
        into.published = min(d for d in (into.published, advisory.published) if d) or ""
        into.severity = into.severity or advisory.severity
        if (advisory.summary, len(advisory.details)) > (into.summary, len(into.details)):
            into.summary, into.details = advisory.summary, advisory.details
    return sorted(merged.values(), key=lambda a: (a.published, a.key))


def query_osv(http: Http, package: str, ecosystem: str) -> list[dict[str, Any]]:
    """Every record OSV holds for the package, following next_page_token."""
    records: list[dict[str, Any]] = []
    payload: dict[str, Any] = {"package": {"name": package, "ecosystem": ecosystem}}
    while True:
        response = http("POST", OSV_QUERY, payload, None) or {}
        records.extend(response.get("vulns") or [])
        token = response.get("next_page_token")
        if not token:
            return records
        payload = {**payload, "page_token": token}


def fetch_watchlist(http: Http, watchlist: Sequence[tuple[str, str]] = WATCHLIST) -> list[Advisory]:
    found: list[Advisory] = []
    for package, ecosystem in watchlist:
        for record in query_osv(http, package, ecosystem):
            advisory = advisory_from(record, package, ecosystem)
            if advisory is not None:
                found.append(advisory)
    return merge(found)


# --- noise filters --------------------------------------------------------
#
# Each filter labels; none drops. An advisory whose text names a path under
# tools/ or contrib/, the act of saving, encoding, writing or appending, or a
# Pillow module that opening a file never runs is probably not reached by a
# scan pipeline, and the label says so. The maintainer still decides.
#
# The path and module filters read the whole text. The word filter reads
# only the headline (the summary and the first paragraph of prose): a long
# write-up of a read-path flaw mentions "writes" somewhere, and a label that
# nearly every advisory carries says nothing.

_PATH = re.compile(r"(?<![\w/.-])(?:tools|contrib)/[\w./-]*\w")
_WRITE_WORDS = re.compile(
    r"\b(sav(?:e|es|ed|ing)|encod(?:e|es|er|ers)|writ(?:e|es|ing|ten|er|ers)|append(?:s|ed|ing)?)\b",
    re.IGNORECASE,
)
#: "out-of-bounds write" and its kin describe a memory fault on any path,
#: not the write path, so they are blanked before the words are looked for.
_MEMORY_WRITE = re.compile(
    r"\b(?:out[- ]of[- ]bounds?|oob|heap|stack|arbitrary|invalid|wild|memory)[- ]writes?\b",
    re.IGNORECASE,
)
PILLOW_MODULES = ("ImageFont", "ImageDraw", "ImageMath", "ImageShow", "PdfParser")
_PILLOW_MODULE = re.compile(r"\b(" + "|".join(PILLOW_MODULES) + r")\b")


@dataclass(frozen=True)
class Hit:
    label: str
    reason: str


def _unique(matches: Iterable[str]) -> list[str]:
    return sorted(set(matches), key=str.lower)


_FENCE = re.compile(r"```.*?```", re.DOTALL)


def headline(advisory: Advisory) -> str:
    """The summary and the first paragraph of prose, with fenced code left out."""
    prose = _FENCE.sub("", advisory.details).strip()
    first = re.split(r"\n\s*\n", prose, maxsplit=1)[0] if prose else ""
    return f"{advisory.summary}\n{first}"


def noise(advisory: Advisory) -> list[Hit]:
    text = advisory.text
    hits: list[Hit] = []
    paths = _unique(_PATH.findall(text))
    if paths:
        hits.append(Hit(NOISE_LABEL, "a path under tools/ or contrib/: " + ", ".join(paths)))
    words = _unique(
        m.lower() for m in _WRITE_WORDS.findall(_MEMORY_WRITE.sub(" ", headline(advisory)))
    )
    if words:
        hits.append(Hit(NOISE_LABEL, "the words save/encode/write/append: " + ", ".join(words)))
    modules = _unique(_PILLOW_MODULE.findall(text))
    if modules:
        hits.append(
            Hit(
                NOISE_LABEL, "a Pillow module that opening a file never runs: " + ", ".join(modules)
            )
        )
    return hits


# --- the issue ------------------------------------------------------------

BUCKETS: tuple[tuple[str, str], ...] = (
    ("A", "already refused by an existing check"),
    ("B", "preventable from a header field our readers can see: a policy field and a corpus case"),
    ("B2", "preventable only by a coarse policy on what `pdfimages -list` or `pdffonts` report"),
    ("C", "needs decoding to detect; out of this library's reach"),
    ("D", "reaches `pdfinfo` itself"),
    ("N", "the check is not in the path: the file is not the input, or it is not an image or PDF"),
    ("U", "a reserved CVE with no text yet; re-checked weekly"),
)


def _first_sentence(text: str, limit: int) -> str:
    line = " ".join(text.split())
    cut = line.find(". ")
    if 0 < cut < limit:
        line = line[: cut + 1]
    return line if len(line) <= limit else line[: limit - 1].rstrip() + "…"


def issue_title(advisory: Advisory) -> str:
    head = " ".join(advisory.summary.split()) or _first_sentence(advisory.details, 120)
    title = f"{advisory.key}: {head}"
    return title if len(title) <= TITLE_LIMIT else title[: TITLE_LIMIT - 1].rstrip() + "…"


def marker(advisory: Advisory) -> str:
    return f"<!-- {MARKER}: {' '.join(sorted(advisory.identifiers))} -->"


def marker_ids(body: str) -> set[str]:
    """The identifiers an issue body's marker names; empty when there is none."""
    found = re.search(rf"<!--\s*{MARKER}:\s*([^>]*?)\s*-->", body or "")
    return set(found.group(1).split()) if found else set()


def issue_body(advisory: Advisory, hits: Sequence[Hit]) -> str:
    details = advisory.details.strip()
    if len(details) > DETAILS_LIMIT:
        details = details[:DETAILS_LIMIT].rstrip() + "\n\n*(cut here; the rest is on OSV)*"
    links = ", ".join(f"[{i}]({OSV_VULNERABILITY}{i})" for i in advisory.ids)
    packages = ", ".join(f"{name} ({ecosystem})" for name, ecosystem in advisory.packages)
    labels = (
        "\n".join(f"- `{hit.label}`: {hit.reason}" for hit in hits)
        or "- none: no noise filter matched"
    )
    buckets = "\n".join(f"- [ ] **{code}** {meaning}" for code, meaning in BUCKETS)
    aliases = ", ".join(a for a in advisory.aliases if a != advisory.key) or "none"
    return f"""{marker(advisory)}
| | |
|---|---|
| Advisory | {advisory.key} |
| Aliases | {aliases} |
| Package | {packages} |
| Published | {advisory.published or "unknown"} |
| Severity | {advisory.severity or "not given"} |
| OSV | {links} |

**Labels**
{labels}

## Summary

{advisory.summary.strip() or "*(none given)*"}

## Details

{details or "*(none given)*"}

## Triage

Would a bounded header check, or what `pdfinfo`, `pdfimages -list` or
`pdffonts` report, have kept the triggering file from the decoder? Answer
that in a line, tick one bucket, and close the issue; the definitions and
what each bucket leads to are in `docs/advisories/README.md`.

{buckets}

**Finding:**
"""


# --- state ----------------------------------------------------------------


@dataclass
class State:
    recorded: str = ""
    seen: set[str] = field(default_factory=set)
    pending: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: Path) -> State:
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            recorded=str(data.get("recorded") or ""),
            seen=set(data.get("seen") or []),
            pending=set(data.get("pending") or []),
        )

    def save(self, path: Path) -> None:
        data = {
            "recorded": self.recorded,
            "seen": sorted(self.seen),
            "pending": sorted(self.pending),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def known(advisory: Advisory, seen: set[str]) -> bool:
    """Seen under any of its identifiers, so an alias gained later is no new advisory."""
    return bool(advisory.identifiers & seen)


# --- GitHub ---------------------------------------------------------------


def http_json(
    method: str, url: str, payload: dict[str, Any] | None, headers: dict[str, str] | None
) -> Any:
    """One JSON request. Raises urllib.error.HTTPError on any error status."""
    if not url.startswith("https://"):
        raise ValueError(f"refusing a request that is not https: {url}")
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(  # noqa: S310 -- https only, checked above
        url,
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            **(headers or {}),
        },
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310 -- https only, checked above
        body = response.read()
    return json.loads(body) if body.strip() else None


class GitHub:
    """The three calls the job makes, through the REST API."""

    def __init__(self, repository: str, token: str, http: Http = http_json):
        self.repository = repository
        self.http = http
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _url(self, path: str, **query: str) -> str:
        url = f"{GITHUB_API}/repos/{self.repository}/{path}"
        return f"{url}?{urllib.parse.urlencode(query)}" if query else url

    def seen(self) -> set[str]:
        """Every identifier named by the marker of an existing advisory issue, open or closed."""
        identifiers: set[str] = set()
        page = 1
        while True:
            url = self._url(
                "issues", labels=ISSUE_LABEL, state="all", per_page="100", page=str(page)
            )
            items = self.http("GET", url, None, self.headers) or []
            for item in items:
                if "pull_request" not in item:
                    identifiers |= marker_ids(str(item.get("body") or ""))
            if len(items) < 100:
                return identifiers
            page += 1

    def ensure_label(self, name: str) -> None:
        colour, description = LABELS[name]
        try:
            self.http("GET", self._url(f"labels/{urllib.parse.quote(name)}"), None, self.headers)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            payload = {"name": name, "color": colour, "description": description}
            self.http("POST", self._url("labels"), payload, self.headers)

    def create_issue(self, title: str, body: str, labels: Sequence[str]) -> str:
        payload = {"title": title, "body": body, "labels": list(labels)}
        created = self.http("POST", self._url("issues"), payload, self.headers) or {}
        time.sleep(PAUSE)  # the API's limit on creating content is per minute
        return str(created.get("html_url") or "")


# --- the commands ---------------------------------------------------------


@dataclass
class Report:
    opened: list[tuple[Advisory, str]] = field(default_factory=list)
    pending: list[Advisory] = field(default_factory=list)
    total: int = 0

    def markdown(self, dry_run: bool) -> str:
        verb = "Would open" if dry_run else "Opened"
        lines = ["## Advisories\n", f"{self.total} on the watchlist. {verb} {len(self.opened)}."]
        for advisory, url in self.opened:
            where = f" ({url})" if url else ""
            lines.append(f"- {issue_title(advisory)}{where}")
        if self.pending:
            lines.append(
                "\nPending, reserved with no text yet, re-checked next week: "
                + ", ".join(a.key for a in self.pending)
            )
        return "\n".join(lines) + "\n"


def run(
    http: Http,
    state: State,
    github: GitHub | None,
    *,
    dry_run: bool,
    out: Callable[[str], None] = print,
) -> Report:
    advisories = fetch_watchlist(http)
    seen = set(state.seen)
    if github is not None:
        seen |= github.seen()
    report = Report(total=len(advisories))
    new = [a for a in advisories if not known(a, seen)]
    report.pending = [a for a in new if a.reserved]
    to_open = [a for a in new if not a.reserved]
    if github is not None and not dry_run and to_open:
        for name in LABELS:
            github.ensure_label(name)
    for advisory in to_open:
        hits = noise(advisory)
        labels = [ISSUE_LABEL, *sorted({hit.label for hit in hits})]
        url = ""
        if github is not None and not dry_run:
            url = github.create_issue(issue_title(advisory), issue_body(advisory, hits), labels)
        report.opened.append((advisory, url))
        out(
            f"{'would open' if dry_run else 'opened'}  {issue_title(advisory)}  [{', '.join(labels)}]"
        )
    for advisory in report.pending:
        out(f"pending     {advisory.key}  (reserved, no text yet)")
    return report


def record(http: Http, path: Path, today: str) -> State:
    advisories = fetch_watchlist(http)
    state = State(
        recorded=today,
        seen={a.key for a in advisories if not a.reserved},
        pending={a.key for a in advisories if a.reserved},
    )
    state.save(path)
    return state


def main(argv: Sequence[str] | None = None, http: Http = http_json) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", choices=("fetch", "run", "record"))
    parser.add_argument(
        "--state", type=Path, default=DEFAULT_STATE, help="the seen.json to compare against"
    )
    parser.add_argument(
        "--repository", default=os.environ.get("GITHUB_REPOSITORY", ""), help="owner/name"
    )
    parser.add_argument(
        "--summary", type=Path, help="append a markdown report here (GITHUB_STEP_SUMMARY)"
    )
    args = parser.parse_args(argv)

    today = datetime.now(UTC).date().isoformat()
    if args.command == "record":
        state = record(http, args.state, today)
        print(f"recorded {len(state.seen)} seen and {len(state.pending)} pending in {args.state}")
        return 0

    token = os.environ.get("GITHUB_TOKEN", "")
    github = GitHub(args.repository, token, http) if token and args.repository else None
    dry_run = args.command == "fetch"
    if not dry_run and github is None:
        print(
            "run needs GITHUB_TOKEN in the environment and --repository owner/name", file=sys.stderr
        )
        return 2
    report = run(http, State.load(args.state), github, dry_run=dry_run)
    if args.summary is not None:
        with args.summary.open("a", encoding="utf-8") as summary:
            summary.write(report.markdown(dry_run))
    return 0


if __name__ == "__main__":
    sys.exit(main())
