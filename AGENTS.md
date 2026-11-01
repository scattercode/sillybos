# AGENTS.md

Guidance for anyone working in this repository with a coding agent --
Claude Code, Codex, Cursor, Gemini CLI or whatever else reads this file --
and a fair summary of the house rules for contributors who use none. The
rules are the repository's, not any one tool's; `CONTRIBUTING.md` has the
checks and the commit style at more length.

## What this repository is

**sillybos** is a dependency-free Python library and command that decides,
before any image library or PDF renderer opens a file, whether it is one of
the formats a scan can be (JPEG, PNG, TIFF, PDF), within a policy's
limits, and if not, why. It names the format from the first bytes, reads
the image headers with code of its own, asks poppler's `pdfinfo` about a
PDF in a separate process, and returns a verdict with reasons in plain
sentences. It came out of Tetrak OCR (brief 022, product zone, private),
where it sits in front of every scan, and is a separate repository because
its audience is anyone who runs Pillow or poppler over files they did not
make, most of whom will never install an OCR tool.

Published to PyPI as `sillybos`; the import package is `sillybos`; the
command is `sillybos`. MIT licensed, the same as Tetrak itself. Say it
*SIL-lee-boss*: the Greek σίλλυβος, the title tag that hung from a scroll.

## Hard rules

### The check runs no decoder

The library's whole claim is that a file is judged before any decoder's
code touches it. So:

- `src/sillybos/headers.py` reads JPEG, PNG and TIFF headers with its own
  bounded code. Never replace a reader with a call into Pillow, `imageio`
  or anything else that decodes; never import Pillow outside
  `sillybos/pillow.py`, which is the optional extra.
- A PDF is asked about through `pdfinfo` and `pdfdetach` in a subprocess
  with a timeout. Never add a PDF parser as a dependency, and never read a
  PDF's objects with code here. The one thing this code does read from a
  PDF's bytes is the *name* of a launch action, by a bounded search for
  its spelling (`pdf.py`, `_has_launch_action`), because no poppler tool
  reports one; a search for bytes is not a parser, and it must stay that
  way.
- The library has **no runtime dependencies**, and `[project] dependencies`
  stays `[]`. Everything else goes in an extra.
- Every read of a file is bounded by a constant or by the policy, and every
  offset is checked against the file's size before it is used. A header the
  reader cannot make sense of is a `HeaderError`, which becomes a refusal;
  being forgiving is not a virtue here.

### Four formats, by name

`FORMATS` in `policy.py` is JPEG, PNG, TIFF and PDF, and the sniff table
refuses everything else by name. Do not add a format because a library can
read it; add one only when a real scan in that format is shown, and then
with its own bounded header reader, its hostile cases and a note in the
README. BigTIFF is refused on purpose.

### Reasons are sentences for an operator

A `Verdict.reasons` entry says what was found and what the limit is, in
words a person running a batch can act on: "says PNG, is PostScript";
"a page of 2,400,000,000 pixels; the limit is 89,478,485". Numbers carry
thousands separators. Never return a code or a bare exception text.
`check()` never raises for anything found *in* a file; a missing file and a
missing `pdfinfo` are the caller's errors and do raise.

### The hostile corpus is built, never checked in

`tests/corpus.py` makes every hostile file from bytes at test time. Never
commit a binary test fixture, and never collect a sample from the internet:
a real malicious file in a public repository is a problem of its own. A new
refusal arrives with the case that triggers it; the readers are also tested
against Pillow's reading of real files, so they agree with the decoder they
stand in front of.

### What the README promises

`README.md` says exactly what the library does not protect against. A
change that widens or narrows that must change the README in the same
commit. A flaw in the library itself goes through the private report route
in `SECURITY.md`.

## Working here

- British English in prose, docstrings and reasons. Sentence case for
  headings. Docs in the first person plural: this is a collaborative
  project.
- The checks: `ruff check .`, `ruff format --check .`, `mypy`, `pytest --cov`
  (floor in `pyproject.toml`), `uv lock --check`, and
  `zensical build --clean --strict` with the `docs` extra. The Ruff set
  includes the `S` (bandit) rules; an ignore needs a reason beside it.
- The reference site (`docs/` and `zensical.toml`, published to GitHub
  Pages on merge) is the README, included between its two `--8<--` snippet
  markers, plus the API and command line generated from the docstrings.
  Document the API in the docstrings, Google style with Markdown
  cross-references (`[Policy][sillybos.Policy]`); never copy it into a
  page by hand.
- Conventional Commits, enforced by `.githooks/commit-msg` (shared from
  `scattercode/release-pipelines`; do not edit the copy). `fix` → patch,
  `feat` → minor, `!` → major. Releases are automatic on merge to `main`:
  never tag, never edit `CHANGELOG.md`.
- A change to a default limit in `Policy` is at least a `feat`, since it
  changes which files pass; a change that refuses something previously
  passed is breaking (`!`).
- Public repository: no partner, price or plan from Tetrak's private notes
  appears here. Cite briefs by number only.
