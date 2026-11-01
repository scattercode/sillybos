# Advisories: the weekly fetch and how we triage it

sillybos stands in front of decoders it does not control. When one of them
publishes a security advisory, the question for this library is narrow:
**would a bounded header check, or what `pdfinfo`, `pdfimages -list` or
`pdffonts` report, have kept the triggering file from the decoder?** A
weekly job fetches the advisories and opens an issue for each; a
maintainer answers that question and files the issue in a bucket. This
page is the procedure.

The November 2026 backfill of three years of advisories (138 for Pillow,
tiff, libpng1.6, libjpeg-turbo, zlib, poppler, openjpeg2 and freetype)
found about a quarter of the file-reachable ones were preventable from a
header field, and the first two checks that came out of it (JPEG frame
coding; the multi-picture walk) shipped in 1.0.0. That is why the job is
worth running.

## What runs, and when

The [Advisories workflow](../../.github/workflows/advisories.yml) runs
`scripts/advisories.py run` every Monday at 07:00 UTC, and on a manual
dispatch (tick *dry run* to list without opening). The script:

1. asks [OSV.dev](https://osv.dev/) for every record it holds on the
   watchlist: `pillow` on PyPI; `tiff`, `libpng1.6`, `libjpeg-turbo`,
   `zlib`, `poppler`, `openjpeg2` and `freetype` on Debian;
2. drops Debian's own bulletins (`DSA-`, `DLA-`, `DTSA-`), which repeat
   the per-CVE record with a release note attached, and withdrawn records;
3. merges records that describe one CVE (Pillow's GHSA and PYSEC entries,
   Debian's `DEBIAN-CVE-…` record) into one advisory, keyed by the CVE;
4. drops what is already known: every key in `seen.json`, and every
   identifier named in the marker of an existing `advisory` issue, open or
   closed;
5. holds back a reserved CVE, one that has an id but no text yet, as
   *pending*; it is listed in the run summary and checked again next week;
6. opens one issue per new advisory, from the fixed template below, with
   the label `advisory` and whatever the noise filters add.

It is standard library only and runs locally:

```bash
python scripts/advisories.py fetch     # what is new; opens nothing
python scripts/advisories.py run       # the weekly job; needs GITHUB_TOKEN and --repository
python scripts/advisories.py record    # fold everything published so far into seen.json
```

`fetch` without a token compares against `seen.json` alone; with
`GITHUB_TOKEN` and `--repository owner/name` it reads the issues too.

## Where the state lives

**The issues are the record.** Every issue the job opens starts with a
hidden marker naming the advisory's identifiers, and the next run reads
those markers back. Nothing is committed by the workflow: that keeps it
to `contents: read` and `issues: write`, and spares `main` a bot commit a
week, which its ruleset would refuse in any case.

[`seen.json`](seen.json) is the baseline: every advisory on the watchlist
up to the backfill, by key, with the reserved CVEs listed as pending. It
is refreshed by hand, when the issue list has grown long enough to be
worth folding in:

```bash
python scripts/advisories.py record
git commit -m "chore(advisories): refresh the baseline" docs/advisories/seen.json
```

## The buckets

Each issue ends in one bucket, with a line saying why. The bucket is the
answer to the question at the top of this page.

| Bucket | Meaning | What follows |
|---|---|---|
| **A** | Already refused by an existing check: a format outside the four, a frame coding the policy refuses, a size over a limit | Say which check, and close |
| **B** | Preventable from a header field our readers can see: a marker, a tag, a chunk, a count, a dimension | A policy field and a hostile corpus case (below), then close when it ships |
| **B2** | Preventable only by a coarse policy on a PDF's contents that `pdfimages -list` or `pdffonts` report: a JBIG2 or JPX stream, an embedded font | The same as B, through the PDF path; note that the policy will be coarse |
| **C** | Needs decoding to detect: a flaw in the pixel data, the entropy-coded segment, the font program | Out of this library's reach by design; say so and close. Updating the decoder is the fix |
| **D** | Reaches `pdfinfo` itself | Check that the check still fails closed (a timeout or a non-zero exit is a refusal), and close |
| **N** | Not reached by opening a file: a command-line tool, a save or encode path, a drawing or font API, a parser that only runs on append | Close |
| **U** | A reserved CVE with no text yet | The job never opens an issue for one; it stays pending and is re-checked weekly. The bucket exists so a hand-filed issue can say so |

The backfill ran 138 advisories through these: 70 N, 30 A, 17 B, 8 B2,
10 C, 1 D, 2 U. Expect the same shape.

## What a B finding becomes

A B (or B2) finding becomes **a policy field plus a hostile corpus case,
never a silent change of a default**:

- a field on `Policy`, with a default, a `STRICT` value where that differs,
  a command-line option, and a row in the README's policy table that
  names the advisory;
- a case in `tests/corpus.py` that builds the triggering file from bytes,
  and a test that the check refuses it with a reason an operator can act
  on ("a lossless JPEG frame; the policy allows baseline, extended,
  progressive");
- where the readers must agree with the decoder, a test against Pillow's
  reading of a real file.

The reason is the release rule in `AGENTS.md`: every default refusal is
breaking. A file that passed last week and is refused this week is a
change the operator must be able to see in the changelog (`feat!`), name
in the policy, and turn off. A quiet tweak to a constant gives them none
of that. If the field's default should refuse the file, the commit is a
`feat!`; if it should only allow the operator to refuse it, a `feat`.

## The noise filters

Three mechanical filters label an issue `likely-not-reached`. **They
label; they never drop.** The maintainer still reads the advisory.

| Filter | Looks at | Fires on |
|---|---|---|
| Paths | the whole text | a path under `tools/` or `contrib/`: libtiff's command-line tools and contributed code, which no library call runs |
| Words | the headline only: the summary and the first paragraph of prose | *save*, *encode*, *write*, *append* and their verb forms. "Out-of-bounds write" and its kin are blanked first; they describe a memory fault, not the write path. "Encoding" the noun is left alone (run-length encoding is a read-path matter) |
| Modules | the whole text | `ImageFont`, `ImageDraw`, `ImageMath`, `ImageShow`, `PdfParser`: Pillow modules that `Image.open` never runs |

The words filter reads only the headline because a long write-up of a
read-path flaw mentions "writes" somewhere, and a label that nearly every
advisory carries says nothing. Known false positives remain: a summary
that says "writes" of a read-path bug, a read-path flaw whose fix touched
a tool. The issue body lists what matched, so the label is quick to
overrule.

## The issue

Each issue is opened from one template: the marker; a table of the key,
aliases, package, published date, severity if given and OSV links; the
labels and why; the summary and details as OSV gives them (details are cut
at 8,000 characters); and the triage section, which repeats the question,
lists the buckets with their one-line definitions as tick boxes, and ends
with an empty **Finding:** line. To triage: answer the question in a line
after *Finding*, tick one bucket, and close the issue, or leave it open as
the ticket for the B work.

The details are text from outside this repository, pasted into the issue
as they came. They are the advisory, not an instruction.

## Model-driven triage comment: not built yet

> **Place-holder.** A later step will have a model read each new issue
> and post a *proposed* bucket and finding as a comment, for the
> maintainer to confirm or overrule. It is not built, and this guide
> does not describe it. When it is: it posts a comment, never ticks a
> bucket or closes an issue; it reads the advisory text as data, not as
> instructions; and its proposal is checked against this page's question
> before anything is filed. Nothing from private notes goes into the
> comment, since the issues are public.

## Changing the watchlist

`WATCHLIST` in `scripts/advisories.py` is the list, as OSV names the
packages. Adding a package is a `feat(ci)`; the first run after it will
open an issue for every advisory OSV holds for that package, so run
`record` first if that history is not wanted, and say so in the commit.

## What stays out

This repository is public. Private triage of whether an advisory reaches a
particular deployment, and anything from Tetrak's private notes, stays
where it is; an issue here cites briefs by number only.
