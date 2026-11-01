# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/scattercode/sillybos/security/advisories/new)
(Security tab → "Report a vulnerability"). Do not open a public issue for a
security problem.

We aim to acknowledge reports within seven days. This is a small
collaborative project, not a company with a security team, but a flaw in a
library whose job is to refuse hostile files is the kind of report we take
most seriously, and we will keep you informed as we investigate.

A file that *should* have been refused and was not, or that made a reader
hang or crash, is a vulnerability for this purpose. Please describe how the
file is built rather than attaching it, if you can; if a sample is the only
way, send it through the private report, never in a public issue.

## Supported versions

Only the latest release receives fixes. There are no maintenance branches.

## What we do ourselves

- The package has no runtime dependencies, so there is no dependency tree
  to compromise at install time. Pillow is an optional extra, used only by
  `open_checked`, after the check has passed.
- The check runs no decoder: the image headers are read by bounded code of
  our own, and a PDF is asked about through poppler's `pdfinfo` in a
  separate process with a time limit.
- The hostile corpus in `tests/` is built from bytes at test time, so that
  nothing hostile is checked in and every release is tested against it.
- The development tooling is pinned in `uv.lock` and scanned by Trivy on
  every push and weekly on a schedule; the workflows are checked by zizmor
  and the history by gitleaks; Dependabot keeps the lock and the actions
  current.
- Releases are built in CI from the tagged commit and published to PyPI with
  a Trusted Publisher (OIDC): no long-lived token exists anywhere, and every
  release carries PEP 740 attestations.

## What the library does not protect against

The README says this at length. In short: a flaw in a decoder for a format
you *allow*, malware, and anything inside a PDF beyond what `pdfinfo`
reports. A report that one of those got through is welcome as an issue, but
it is not a vulnerability in this library.
