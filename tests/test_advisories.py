"""The weekly advisory fetch, on sample OSV and GitHub responses built here.

No network: every response the script would get from OSV.dev or the GitHub
API is a dict made in this file, served by a fake of the one HTTP function
the script calls.
"""

from __future__ import annotations

import email.message
import json
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any

import pytest

from scripts import advisories
from scripts.advisories import (
    BUCKETS,
    GITHUB_API,
    ISSUE_LABEL,
    NOISE_LABEL,
    OSV_QUERY,
    Advisory,
    GitHub,
    State,
    advisory_from,
    fetch_watchlist,
    issue_body,
    issue_title,
    known,
    marker,
    marker_ids,
    merge,
    noise,
    query_osv,
    run,
)

# --- sample records, as OSV returns them ---------------------------------


def ghsa(
    ident: str,
    cve: str | None,
    summary: str,
    details: str = "Some details.",
    published: str = "2026-10-21T20:39:49Z",
    **extra: Any,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": ident,
        "summary": summary,
        "details": details,
        "published": published,
        "aliases": [cve, f"BIT-pillow-{cve.removeprefix('CVE-')}"] if cve else [],
        "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L"}],
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"ecosystem": "PyPI", "name": "pillow"}}],
    }
    record.update(extra)
    return record


def pysec(ident: str, cve: str, details: str) -> dict[str, Any]:
    return {"id": ident, "details": details, "aliases": [cve], "published": "2026-10-22T00:00:00Z"}


def debian(cve: str, details: str, published: str = "2026-10-02T12:00:00Z") -> dict[str, Any]:
    return {
        "id": f"DEBIAN-{cve}",
        "details": details,
        "published": published,
        "affected": [{"package": {"ecosystem": "Debian:13", "name": "tiff"}}],
    }


def bulletin(ident: str) -> dict[str, Any]:
    return {"id": ident, "summary": "tiff - security update", "published": "2026-10-03T00:00:00Z"}


# --- a fake of the HTTP function -------------------------------------------


class FakeHttp:
    """Serves OSV pages and a small GitHub: labels, an issue list, issue creation."""

    def __init__(
        self,
        osv: dict[tuple[str, str], list[list[dict[str, Any]]]],
        issues: list[dict[str, Any]] | None = None,
    ) -> None:
        self.osv = osv
        self.issues = list(issues or [])
        self.labels: set[str] = set()
        self.created: list[dict[str, Any]] = []
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def __call__(
        self, method: str, url: str, payload: dict[str, Any] | None, headers: dict[str, str] | None
    ) -> Any:
        self.calls.append((method, url, payload))
        if url == OSV_QUERY:
            assert payload is not None
            pages = self.osv.get(
                (payload["package"]["name"], payload["package"]["ecosystem"]), [[]]
            )
            index = int(payload.get("page_token", 0))
            response: dict[str, Any] = {"vulns": pages[index]}
            if index + 1 < len(pages):
                response["next_page_token"] = str(index + 1)
            return response
        assert url.startswith(f"{GITHUB_API}/repos/scattercode/sillybos/")
        assert headers is not None and headers["Authorization"] == "Bearer token"
        parts = urllib.parse.urlsplit(url)
        path = parts.path.removeprefix("/repos/scattercode/sillybos/")
        query = dict(urllib.parse.parse_qsl(parts.query))
        if method == "GET" and path.startswith("labels/"):
            if urllib.parse.unquote(path.removeprefix("labels/")) in self.labels:
                return {"name": path}
            raise urllib.error.HTTPError(url, 404, "Not Found", email.message.Message(), None)
        if method == "POST" and path == "labels":
            assert payload is not None
            self.labels.add(payload["name"])
            return payload
        if method == "GET" and path == "issues":
            assert query["labels"] == ISSUE_LABEL and query["state"] == "all"
            everything = [*self.issues, *self.created, {"pull_request": {}, "body": "<!-- x -->"}]
            page = int(query["page"])
            return everything[(page - 1) * 100 : page * 100]
        if method == "POST" and path == "issues":
            assert payload is not None
            created = {**payload, "html_url": f"https://github.com/i/{len(self.created) + 1}"}
            self.created.append(created)
            return created
        raise AssertionError(f"unexpected call {method} {url}")


@pytest.fixture(autouse=True)
def no_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(advisories, "PAUSE", 0.0)


# --- parsing and merging ----------------------------------------------------


def test_a_bulletin_is_dropped_and_a_withdrawn_record_too() -> None:
    assert advisory_from(bulletin("DSA-6000-1"), "tiff", "Debian") is None
    assert advisory_from(bulletin("DLA-4000-1"), "tiff", "Debian") is None
    assert advisory_from(bulletin("DTSA-10-1"), "tiff", "Debian") is None
    gone = ghsa("GHSA-gone", "CVE-2026-1", "Gone", withdrawn="2026-10-22T00:00:00Z")
    assert advisory_from(gone, "pillow", "PyPI") is None


def test_records_for_one_cve_merge_into_one_advisory() -> None:
    first = advisory_from(
        ghsa("GHSA-aaaa", "CVE-2026-10", "Pillow: a flaw", "Long details."), "pillow", "PyPI"
    )
    second = advisory_from(pysec("PYSEC-2026-1", "CVE-2026-10", "Short."), "pillow", "PyPI")
    assert first is not None and second is not None
    (merged,) = merge([second, first])
    assert merged.key == "CVE-2026-10"
    assert merged.ids == ["GHSA-aaaa", "PYSEC-2026-1"]
    assert merged.aliases == ["BIT-pillow-2026-10", "CVE-2026-10"]
    assert merged.summary == "Pillow: a flaw"
    assert merged.details == "Long details."
    assert merged.published == "2026-10-21"
    assert merged.severity == "high, CVSS:4.0/AV:N/AC:L"


def test_a_debian_record_is_keyed_by_its_cve_and_merges_with_pillows() -> None:
    deb = advisory_from(debian("CVE-2026-20", "A flaw in libtiff."), "tiff", "Debian")
    pil = advisory_from(ghsa("GHSA-bbbb", "CVE-2026-20", "Pillow: libtiff flaw"), "pillow", "PyPI")
    assert deb is not None and pil is not None
    assert deb.key == "CVE-2026-20"
    assert deb.severity == ""
    (merged,) = merge([deb, pil])
    assert merged.packages == [("pillow", "PyPI"), ("tiff", "Debian")]
    assert merged.ids == ["DEBIAN-CVE-2026-20", "GHSA-bbbb"]
    assert merged.published == "2026-10-02"


def test_a_record_without_a_cve_keeps_its_own_id() -> None:
    advisory = advisory_from(ghsa("GHSA-cccc", None, "Bundled libopenjp2"), "pillow", "PyPI")
    assert advisory is not None
    assert advisory.key == "GHSA-cccc"
    assert advisory.aliases == []


def test_an_empty_record_is_reserved() -> None:
    advisory = advisory_from(debian("CVE-2026-36849", ""), "tiff", "Debian")
    assert advisory is not None
    assert advisory.reserved
    assert not Advisory(key="x", summary="text").reserved


def test_merge_sorts_oldest_first() -> None:
    newer = Advisory(key="CVE-2026-2", published="2026-10-05", summary="b")
    older = Advisory(key="CVE-2026-9", published="2026-10-01", summary="a")
    assert [a.key for a in merge([newer, older])] == ["CVE-2026-9", "CVE-2026-2"]


def test_pagination_follows_the_token() -> None:
    http = FakeHttp(
        {
            ("pillow", "PyPI"): [
                [ghsa("GHSA-p1", "CVE-2026-1", "one")],
                [ghsa("GHSA-p2", "CVE-2026-2", "two")],
            ]
        }
    )
    records = query_osv(http, "pillow", "PyPI")
    assert [r["id"] for r in records] == ["GHSA-p1", "GHSA-p2"]
    assert http.calls[0][2] == {"package": {"name": "pillow", "ecosystem": "PyPI"}}
    assert http.calls[1][2] == {
        "package": {"name": "pillow", "ecosystem": "PyPI"},
        "page_token": "1",
    }


def test_fetch_watchlist_asks_about_every_package() -> None:
    http = FakeHttp({})
    assert fetch_watchlist(http) == []
    asked = {(c[2]["package"]["name"], c[2]["package"]["ecosystem"]) for c in http.calls if c[2]}
    assert asked == set(advisories.WATCHLIST)
    assert ("libpng1.6", "Debian") in asked


# --- noise filters ----------------------------------------------------------


def hits(summary: str, details: str = "") -> list[str]:
    return [hit.reason for hit in noise(Advisory(key="x", summary=summary, details=details))]


def test_a_path_under_tools_or_contrib_is_labelled() -> None:
    reasons = hits("libtiff: overflow", "In tools/tiffcrop.c and contrib/addtiffo/tif_ovrcache.c.")
    assert reasons == [
        "a path under tools/ or contrib/: contrib/addtiffo/tif_ovrcache.c, tools/tiffcrop.c"
    ]
    assert hits("libtiff: overflow", "The tools directory and libtiff/tif_dirread.c") == []
    assert hits("x", "in mytools/thing.c") == []


def test_the_write_words_are_labelled_from_the_headline_only() -> None:
    assert hits("Pillow: Quadratic-time DoS in PDF save_all") == []  # save_all is one word
    assert hits("Pillow: crash when saving a TIFF", "The encoder writes past the end.") == [
        "the words save/encode/write/append: encoder, saving, writes"
    ]
    assert hits("Pillow: appends a chunk") == ["the words save/encode/write/append: appends"]
    assert hits("Pillow: crash on open", "First paragraph.\n\nLater the code writes a log.") == []
    assert hits("Pillow: crash on open", "```\nwrites\n```\n\nProse with no such word.") == []


def test_a_memory_write_is_not_the_write_path() -> None:
    assert hits("libtiff: out-of-bounds write in tif_read.c") == []
    assert hits("libpng: heap write", "An OOB write and an arbitrary write.") == []
    assert hits("libtiff: out-of-bounds write", "The writer overflows.") == [
        "the words save/encode/write/append: writer"
    ]


def test_encoding_the_noun_is_not_the_encoder() -> None:
    assert hits("libtiff: RLE (run length encoding) decoders overflow") == []
    assert hits("libtiff: the JPEG encoder overflows") == [
        "the words save/encode/write/append: encoder"
    ]


def test_a_pillow_module_that_opening_never_runs_is_labelled() -> None:
    reasons = hits(
        "Pillow: PdfParser recursion", "ImageFont.truetype and ImageDraw too; ImageFile is fine."
    )
    assert reasons == [
        "a Pillow module that opening a file never runs: ImageDraw, ImageFont, PdfParser"
    ]
    assert hits("Pillow: ImageMath.eval", "and ImageShow") == [
        "a Pillow module that opening a file never runs: ImageMath, ImageShow"
    ]


def test_every_hit_carries_the_one_label() -> None:
    advisory = Advisory(key="x", summary="Pillow: PdfParser save", details="tools/a.c")
    assert {hit.label for hit in noise(advisory)} == {NOISE_LABEL}
    assert len(noise(advisory)) == 3
    assert noise(Advisory(key="x", summary="Pillow: heap over-read on open")) == []


# --- the issue --------------------------------------------------------------


def sample() -> Advisory:
    return Advisory(
        key="CVE-2026-112901",
        ids=["GHSA-xgh8", "PYSEC-2026-4335"],
        aliases=["BIT-pillow-2026-112901", "CVE-2026-112901"],
        packages=[("pillow", "PyPI")],
        published="2026-10-19",
        severity="moderate, CVSS:4.0/AV:N",
        summary="Pillow: ReDoS in XbmImagePlugin",
        details="A crafted file stalls Image.open().\n\nMore follows.",
    )


def test_the_title_is_the_key_and_the_summary() -> None:
    assert issue_title(sample()) == "CVE-2026-112901: Pillow: ReDoS in XbmImagePlugin"
    deb = Advisory(
        key="CVE-2026-95512",
        details="A flaw was found in FreeType. A remote attacker could exploit it.",
    )
    assert issue_title(deb) == "CVE-2026-95512: A flaw was found in FreeType."
    long = Advisory(key="CVE-2026-1", summary="x" * 300)
    assert len(issue_title(long)) == advisories.TITLE_LIMIT
    assert issue_title(long).endswith("…")


def test_the_body_follows_the_template() -> None:
    advisory = sample()
    body = issue_body(advisory, noise(advisory))
    assert body.startswith(
        "<!-- sillybos-advisory: BIT-pillow-2026-112901 CVE-2026-112901 GHSA-xgh8 PYSEC-2026-4335 -->"
    )
    assert "| Advisory | CVE-2026-112901 |" in body
    assert "| Aliases | BIT-pillow-2026-112901 |" in body
    assert "| Package | pillow (PyPI) |" in body
    assert "| Published | 2026-10-19 |" in body
    assert "| Severity | moderate, CVSS:4.0/AV:N |" in body
    assert "[GHSA-xgh8](https://osv.dev/vulnerability/GHSA-xgh8)" in body
    assert "[PYSEC-2026-4335](https://osv.dev/vulnerability/PYSEC-2026-4335)" in body
    assert "- none: no noise filter matched" in body
    assert "## Summary\n\nPillow: ReDoS in XbmImagePlugin" in body
    assert "## Details\n\nA crafted file stalls Image.open()." in body
    assert (
        "Would a bounded header check, or what `pdfinfo`, `pdfimages -list` or\n`pdffonts` report"
        in body
    )
    for code, meaning in BUCKETS:
        assert f"- [ ] **{code}** {meaning}" in body
    assert body.rstrip().endswith("**Finding:**")


def test_the_body_names_the_labels_and_cuts_long_details() -> None:
    advisory = Advisory(key="CVE-2026-2", summary="Pillow: PdfParser saves", details="d" * 10_000)
    body = issue_body(advisory, noise(advisory))
    assert "- `likely-not-reached`: the words save/encode/write/append: saves" in body
    assert (
        "- `likely-not-reached`: a Pillow module that opening a file never runs: PdfParser" in body
    )
    assert "*(cut here; the rest is on OSV)*" in body
    assert "| Severity | not given |" in body
    assert "| Aliases | none |" in body
    assert "*(none given)*" not in body.split("## Details")[0]


def test_the_marker_round_trips() -> None:
    advisory = sample()
    assert marker_ids(marker(advisory)) == advisory.identifiers
    assert marker_ids("no marker here") == set()
    assert marker_ids("") == set()


# --- state ------------------------------------------------------------------


def test_state_round_trips_and_a_missing_file_is_empty(tmp_path: Path) -> None:
    path = tmp_path / "seen.json"
    assert State.load(path) == State()
    State(recorded="2026-11-01", seen={"CVE-2026-2", "CVE-2026-1"}, pending={"CVE-2026-9"}).save(
        path
    )
    assert json.loads(path.read_text()) == {
        "recorded": "2026-11-01",
        "seen": ["CVE-2026-1", "CVE-2026-2"],
        "pending": ["CVE-2026-9"],
    }
    assert State.load(path).seen == {"CVE-2026-1", "CVE-2026-2"}


def test_known_under_any_identifier() -> None:
    advisory = Advisory(key="CVE-2026-5", ids=["GHSA-old"], aliases=["BIT-5"])
    assert known(advisory, {"GHSA-old"})  # recorded before it had a CVE
    assert known(advisory, {"CVE-2026-5"})
    assert not known(advisory, {"CVE-2026-6"})


# --- the job ----------------------------------------------------------------


def watchlist_sample() -> dict[tuple[str, str], list[list[dict[str, Any]]]]:
    return {
        ("pillow", "PyPI"): [
            [
                ghsa("GHSA-new1", "CVE-2026-101", "Pillow: new flaw on open"),
                ghsa("GHSA-old1", "CVE-2026-100", "Pillow: old flaw"),
                ghsa("GHSA-issued", "CVE-2026-102", "Pillow: already has an issue"),
            ]
        ],
        ("tiff", "Debian"): [
            [
                debian("CVE-2026-36849", ""),
                debian("CVE-2026-103", "Heap overflow in tools/tiffcrop.c."),
                bulletin("DSA-6000-1"),
            ]
        ],
    }


def existing_issue(advisory: Advisory) -> dict[str, Any]:
    return {"title": issue_title(advisory), "body": issue_body(advisory, []), "state": "closed"}


def test_run_opens_one_issue_per_new_advisory() -> None:
    issued = Advisory(key="CVE-2026-102", ids=["GHSA-issued"])
    http = FakeHttp(watchlist_sample(), issues=[existing_issue(issued)])
    github = GitHub("scattercode/sillybos", "token", http)
    lines: list[str] = []
    report = run(http, State(seen={"CVE-2026-100"}), github, dry_run=False, out=lines.append)

    assert [c["title"] for c in http.created] == [
        "CVE-2026-103: Heap overflow in tools/tiffcrop.c.",
        "CVE-2026-101: Pillow: new flaw on open",
    ]
    assert http.created[0]["labels"] == [ISSUE_LABEL, NOISE_LABEL]
    assert http.created[1]["labels"] == [ISSUE_LABEL]
    assert "tools/tiffcrop.c" in http.created[0]["body"]
    assert http.labels == {ISSUE_LABEL, NOISE_LABEL}
    assert report.total == 5
    assert [a.key for a in report.pending] == ["CVE-2026-36849"]
    assert [url for _, url in report.opened] == ["https://github.com/i/1", "https://github.com/i/2"]
    assert lines == [
        "opened  CVE-2026-103: Heap overflow in tools/tiffcrop.c.  [advisory, likely-not-reached]",
        "opened  CVE-2026-101: Pillow: new flaw on open  [advisory]",
        "pending     CVE-2026-36849  (reserved, no text yet)",
    ]
    summary = report.markdown(dry_run=False)
    assert "5 on the watchlist. Opened 2." in summary
    assert "- CVE-2026-101: Pillow: new flaw on open (https://github.com/i/2)" in summary
    assert "re-checked next week: CVE-2026-36849" in summary

    # The next run finds its own issues and opens nothing more.
    again = run(http, State(seen={"CVE-2026-100"}), github, dry_run=False, out=lines.append)
    assert len(http.created) == 2
    assert again.opened == []
    assert [a.key for a in again.pending] == ["CVE-2026-36849"]


def test_a_dry_run_opens_nothing() -> None:
    http = FakeHttp(watchlist_sample())
    github = GitHub("scattercode/sillybos", "token", http)
    report = run(http, State(), github, dry_run=True, out=lambda _: None)
    assert http.created == [] and http.labels == set()
    # Oldest first: the Debian record was published before Pillow's.
    assert [a.key for a, _ in report.opened] == [
        "CVE-2026-103",
        "CVE-2026-100",
        "CVE-2026-101",
        "CVE-2026-102",
    ]
    assert "Would open 4." in report.markdown(dry_run=True)
    assert not any(m == "POST" and "github" in url for m, url, _ in http.calls)


def test_without_github_the_state_file_is_the_only_memory() -> None:
    http = FakeHttp(watchlist_sample())
    report = run(
        http, State(seen={"CVE-2026-100", "CVE-2026-102"}), None, dry_run=True, out=lambda _: None
    )
    assert [a.key for a, _ in report.opened] == ["CVE-2026-103", "CVE-2026-101"]


def test_issue_pages_are_followed() -> None:
    issues = [
        existing_issue(Advisory(key=f"CVE-2026-{n}", ids=[f"GHSA-{n}"])) for n in range(1000, 1150)
    ]
    http = FakeHttp({}, issues=issues)
    seen = GitHub("scattercode/sillybos", "token", http).seen()
    assert "CVE-2026-1149" in seen and "GHSA-1000" in seen
    assert len([c for c in http.calls if "issues?" in c[1]]) == 2


def test_an_existing_label_is_left_alone_and_other_errors_surface() -> None:
    http = FakeHttp({})
    http.labels.add(ISSUE_LABEL)
    github = GitHub("scattercode/sillybos", "token", http)
    github.ensure_label(ISSUE_LABEL)
    assert not any(m == "POST" for m, _, _ in http.calls)

    def forbidden(method: str, url: str, payload: Any, headers: Any) -> Any:
        raise urllib.error.HTTPError(url, 403, "Forbidden", email.message.Message(), None)

    with pytest.raises(urllib.error.HTTPError):
        GitHub("scattercode/sillybos", "token", forbidden).ensure_label(ISSUE_LABEL)


# --- the command ------------------------------------------------------------


def test_record_writes_the_state(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    http = FakeHttp(watchlist_sample())
    path = tmp_path / "seen.json"
    assert advisories.main(["record", "--state", str(path)], http=http) == 0
    state = State.load(path)
    assert state.seen == {"CVE-2026-100", "CVE-2026-101", "CVE-2026-102", "CVE-2026-103"}
    assert state.pending == {"CVE-2026-36849"}
    assert state.recorded >= "2026-11-01"
    assert capsys.readouterr().out == f"recorded 4 seen and 1 pending in {path}\n"


def test_fetch_prints_and_writes_the_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    http = FakeHttp(watchlist_sample())
    path = tmp_path / "seen.json"
    State(seen={"CVE-2026-100", "CVE-2026-102", "CVE-2026-103"}).save(path)
    summary = tmp_path / "summary.md"
    code = advisories.main(["fetch", "--state", str(path), "--summary", str(summary)], http=http)
    assert code == 0
    out = capsys.readouterr().out
    assert out.startswith("would open  CVE-2026-101: Pillow: new flaw on open  [advisory]\n")
    assert "pending     CVE-2026-36849" in out
    assert "Would open 1." in summary.read_text()
    assert http.created == []


def test_fetch_with_a_token_reads_the_issues_but_opens_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "scattercode/sillybos")
    issued = Advisory(key="CVE-2026-101", ids=["GHSA-new1"])
    http = FakeHttp(watchlist_sample(), issues=[existing_issue(issued)])
    assert advisories.main(["fetch", "--state", "/nonexistent/seen.json"], http=http) == 0
    assert any(m == "GET" and "issues?" in url for m, url, _ in http.calls)
    assert http.created == []


def test_run_needs_a_token_and_a_repository(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    http = FakeHttp(watchlist_sample())
    assert advisories.main(["run", "--repository", "scattercode/sillybos"], http=http) == 2
    assert "GITHUB_TOKEN" in capsys.readouterr().err
    assert http.calls == []


def test_run_opens_issues_through_the_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    http = FakeHttp(watchlist_sample())
    path = tmp_path / "seen.json"
    State(seen={"CVE-2026-100", "CVE-2026-102", "CVE-2026-103"}).save(path)
    code = advisories.main(
        ["run", "--repository", "scattercode/sillybos", "--state", str(path)], http=http
    )
    assert code == 0
    assert [c["title"] for c in http.created] == ["CVE-2026-101: Pillow: new flaw on open"]


def test_the_checked_in_state_is_well_formed() -> None:
    state = State.load(advisories.DEFAULT_STATE)
    assert state.recorded
    assert state.seen and all(k.startswith(("CVE-", "GHSA-", "OSV-", "PYSEC-")) for k in state.seen)
    assert not (state.seen & state.pending)


def test_http_json_refuses_anything_but_https() -> None:
    with pytest.raises(ValueError, match="not https"):
        advisories.http_json("GET", "http://api.osv.dev/v1/query", None, None)
