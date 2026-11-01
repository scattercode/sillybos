# Contributing

Thanks for your interest in sillybos. This document covers how we work in
this repository: the checks, the commit style, and the automation they feed.
It applies to us as much as to anyone sending a pull request.

## Before you start

Three constraints shape what we can accept:

- **The check runs no decoder.** The image headers are read by code of our
  own in `src/sillybos/headers.py`, and a PDF is asked about through
  `pdfinfo` in a subprocess. A change that has the check call into Pillow,
  a PDF parser or any other decoder, or that adds a runtime dependency,
  will not be accepted; that is the library's whole claim.
- **Four formats.** JPEG, PNG, TIFF and PDF. A new format needs a real scan
  that arrives in it, a bounded reader of its own, hostile cases for it,
  and a line in the README. Open an issue first.
- **Nothing hostile is checked in.** Every hostile file in the tests is
  built from bytes at test time in `tests/corpus.py`. Describe a new case
  as code, never as a binary fixture, and never as something collected
  from the internet.

If you work with a coding agent, point it at `AGENTS.md`, which carries the
repository's rules in the form such tools read. The rules there are the
same as here, stated for an agent.

## Getting set up

```bash
uv venv .venv && source .venv/bin/activate
uv pip install -e '.[dev,docs]'
```

(`python -m venv` and `pip` work too.) The PDF tests need `pdfinfo` from
poppler (`brew install poppler`, `apt install poppler-utils`) and skip
without it. The `docs` extra is Sphinx and its theme, for the reference
site; leave it out if you are not touching the docs. Then activate the git
hooks, one of:

```bash
lefthook install                          # if you have lefthook (brew install lefthook gitleaks zizmor)
git config core.hooksPath .githooks       # dependency-free fallback (commit-msg only)
```

The lefthook hooks run Ruff, gitleaks and the lockfile check before each
commit, the tests, mypy and zizmor before each push, and the Conventional
Commits check on every commit message.

## The checks

Everything the hooks and CI run, runnable by hand:

```bash
ruff check .
ruff format --check .
mypy
pytest --cov
uv lock --check                           # the lockfile matches pyproject.toml
sphinx-build -W -b html docs docs/_build/html   # the docs, with the docs extra
gitleaks git --no-banner --redact .       # secrets in the history
uvx zizmor --min-severity medium .github/workflows
```

All of these must pass before a pull request can merge. The Ruff rule set
is declared explicitly in `pyproject.toml` and includes the `S` (bandit)
rules; an ignore needs a dated reason beside it. Coverage must stay at or
above the floor in `pyproject.toml`.

## The docs

The reference site at <https://scattercode.github.io/sillybos/> is built by
Sphinx from `docs/` and published by `docs.yml` on every push to `main`. It
is the README (included, not copied, between the two `docs:` comment
markers) followed by the API and the command line, generated from the
docstrings and the parser. There is nothing to write by hand when the API
changes: the docstrings are the reference, in Google style with
reStructuredText cross-references (`:class:`, `:func:`, `:data:`), and a
docstring that does not render is a build failure, since the build runs
with warnings as errors on every pull request. Build it locally with the
command above and open `docs/_build/html/index.html`.

## Dependencies and the lockfile

The package has no runtime dependencies, and that is deliberate. The
development tooling is pinned in `uv.lock` so that security scanning (Trivy
in CI, Dependabot) sees real resolved versions rather than ranges. After any
change to an extra:

```bash
uv lock
```

and commit `uv.lock` alongside `pyproject.toml`. CI fails on a stale lock.

## Commit style

Commits follow [Conventional Commits](https://www.conventionalcommits.org/),
enforced by the shared hook in `.githooks/`:

```
<type>[(scope)][!]: <description>
```

- Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`,
  `build`, `ci`, `chore`, `revert`.
- The description is non-empty, has no trailing full stop, and the header is
  100 characters or fewer (72 or fewer preferred).

This is load-bearing, not cosmetic: the release automation computes the next
semantic version from the commit types (`fix` → patch, `feat` → minor,
`!` → major) and generates `CHANGELOG.md` from the messages. Write the
message for the changelog reader. Pull requests are squash-merged, so the
PR title must be a Conventional Commit too; a workflow checks it.

A change to a default limit in `Policy` is at least a `feat`, since it
changes which files pass. A change that refuses something a previous
release passed is breaking and takes a `!`.

## Releases and the changelog

Releases are fully automated; never perform one by hand:

- Every push to `main` runs `release.yml`, which computes the next version
  from the commit history, updates `CHANGELOG.md`, tags, publishes a GitHub
  Release, builds the wheel and publishes it to PyPI with a Trusted
  Publisher.
- Never edit `CHANGELOG.md` manually and never create tags or Releases;
  fix the commit messages (or `cliff.toml`) instead.
- The package version comes from the git tag via `hatch-vcs`; there is no
  version literal to bump.

## Conventions

- British English throughout; sentence case for headings.
- Docs are written in the first person plural; this is a collaborative
  project.
- The audience is anyone who runs an image library or a PDF renderer over
  files they did not make: archives, OCR pipelines, upload handlers. Most
  of them will never hear of Tetrak; write the README, the docstrings and
  the reasons for them.
- A reason is a sentence an operator can act on, with the number found and
  the limit it broke.

## Security

Please report suspected vulnerabilities privately; see
[SECURITY.md](SECURITY.md), not the issue tracker.
