# Tutorials

Three worked examples, each a complete programme that we ran against the
files it names before writing it up. The [API reference](api.md) has every
name; the [policy table](index.md#the-policy) says what each limit bounds
and why. All three turn on one idea: the check runs first, on the file's
own bytes, and only a file that passes is handed to a decoder.

## Opening an image with Pillow, checked first

`sillybos.pillow.open_checked` is two lines of code, and it is worth
knowing both of them:

```python
require(path, policy)
return Image.open(path, formats=pillow_formats(policy))
```

The first line is the check: size, real format, name against contents, the
header, the limits. Anything outside the policy raises `Refused` and Pillow
never hears of the file. The second line opens the file with `formats` set
from the policy, `["JPEG", "PNG", "TIFF"]` by default, so Pillow consults
only those readers, whatever the file claims to be. That one argument was
the whole of the fix for the October 2026 Pillow advisories; the check in
front of it is what makes the limits bite before a pixel is allocated.

Install the extra, then the one-liner:

```bash
pip install 'sillybos[pillow]'
```

```python
from sillybos.pillow import open_checked

with open_checked("scans/page-001.png") as image:
    print(image.format, image.size, image.mode)  # PNG (2480, 3508) L
```

A refusal is an exception with the verdict on it. The verdict says what the
file really is, what its name claimed, and every reason it was refused:

```python
from sillybos import Refused
from sillybos.pillow import open_checked

try:
    open_checked("inbox/page.png")
except Refused as refusal:
    print(refusal)  # page.png: refused. says PNG, is PostScript.
    verdict = refusal.verdict
    verdict.format, verdict.claimed  # ('postscript', 'png')
    verdict.reasons  # ('says PNG, is PostScript',)
```

Two things to know about the edges. A PDF passes the default policy, since
a PDF is one of the four formats, but Pillow does not read PDFs, so
`open_checked` on one raises Pillow's `UnidentifiedImageError`. If a code
path only ever wants images, say so in the policy, and a PDF becomes a
refusal in sillybos's words rather than an error in Pillow's:

```python
from sillybos import Policy, Refused
from sillybos.pillow import open_checked

IMAGES = Policy(formats={"jpeg", "png", "tiff"})

try:
    open_checked("scans/book.pdf", IMAGES)
except Refused as refusal:
    print(refusal.verdict.reasons)
    # ('is PDF, which this policy does not allow (allowed: JPEG, PNG, TIFF)',)
```

### Wrapping a call of your own

`open_checked` is a wrapper, and the same shape wraps anything. Here is a
thumbnailer. Pillow decodes nothing when it opens a file; the pixels are
read on first use, which here is the `thumbnail` call, and by then the
check has already said the frame is within `max_pixels`:

```python
from pathlib import Path

from sillybos import DEFAULT, Policy
from sillybos.pillow import open_checked


def thumbnail(path: Path, out: Path, policy: Policy = DEFAULT) -> None:
    """Make a 300-pixel thumbnail, but only of a file the policy passes."""
    with open_checked(path, policy) as image:  # the check, then Image.open(formats=...)
        image.thumbnail((300, 300))  # the first time any pixel is decoded
        image.save(out)
```

For a reader that has no `formats` argument, the check is the whole guard,
and it still removes every format you did not mean to read, every file too
large to be safe and the rare codings a scanner never writes. The pattern
is the same two lines, with your reader in place of `Image.open`:

```python
from sillybos import require


def read_with(reader, path, policy=DEFAULT):
    require(path, policy)
    return reader(path)


array = read_with(tifffile.imread, "scans/register.tif", Policy(formats={"tiff"}))
```

The same goes for `imageio`, OpenCV's `imread`, `rawpy`, or a command run
with `subprocess`. What the check cannot do is protect against a flaw in
the reader you do allow, on a file of a sensible size in a format you meant
to read; the README's [what it does not do](index.md#what-it-does-not-do)
says so plainly, and the [security watch](https://tetrak.dev/security/)
records, advisory by advisory, which published flaws a check in front of
the decoder refuses and which it cannot.

### The policy is yours

The same file, under the two presets:

```python
from sillybos import DEFAULT, STRICT, check

for policy in (DEFAULT, STRICT):
    verdict = check("inbox/poster.jpg", policy)
    print(verdict.ok, verdict.reasons)

# True  ()
# False ('a page of 63,000,000 pixels; the limit is 50,000,000',)
```

`DEFAULT` is for a trusted laptop and your own scanner. `STRICT` is for
files from outside. Neither is a substitute for a policy set from your own
corpus: find the largest real file you have and the longest real book,
multiply by two or three, and write those numbers down as a `Policy` in
one place. A limit with a reason beside it is one a colleague can raise
with confidence when the collection grows.

## Rendering a PDF with poppler

A PDF is checked without being rendered. sillybos runs poppler's `pdfinfo`
in a separate process with a time limit, and from its output knows the
page count, whether the file is encrypted, and the size of every page in
points. At the policy's `render_dpi`, a page's size in points becomes the
pixels the renderer would allocate, so a page too large is refused before
anything draws it:

```python
from sillybos import Policy, check

BOOKS = Policy(formats={"pdf"}, max_pages=200, render_dpi=200)

verdict = check("scans/book.pdf", BOOKS)
print(verdict)  # book.pdf: ok (PDF, 1653x2339, 4 pages, 0.1 MB)

facts = verdict.facts
facts.pages, facts.pages_exact  # (4, True)
facts.width, facts.height  # (1653, 2339): the largest page, at 200 dpi
facts.max_pixels  # 3866596
facts.encrypted  # False
```

The renderer then runs at the dpi the check was made at, so what it
allocates is what was checked, give or take a pixel of rounding. Knowing
the page count before rendering also means the time limit can be a budget
per page rather than a guess for the whole file:

```python
import subprocess
from pathlib import Path

from sillybos import Policy, require

BOOKS = Policy(formats={"pdf"}, max_pages=200, render_dpi=200)


def render(pdf: Path, out_dir: Path, policy: Policy = BOOKS) -> list[Path]:
    """Render every page with pdftoppm, at the dpi the policy was checked at."""
    facts = require(pdf, policy).facts  # Refused if too long, too large, encrypted, or not a PDF
    out_dir.mkdir(exist_ok=True)
    subprocess.run(
        [
            "pdftoppm",
            "-r",
            str(policy.render_dpi),
            "-gray",
            "-png",
            str(pdf),
            str(out_dir / "page"),
        ],
        check=True,
        timeout=60 * facts.pages,  # a minute a page, now that the count is known
    )
    return sorted(out_dir.glob("page-*.png"))
```

`pdf2image`, `pypdfium2` and the rest take the same place as `pdftoppm`
here: the check first, then the renderer, at the same dpi. And the
refusals read as they do for images. A PostScript file called `page.pdf`
is `says PDF, is PostScript`; a book longer than the policy allows is
`4 pages; the limit is 2`, with `facts.pages` on the verdict so the log
can say how long it was.

## Taking files from outside

An upload handler, a shared inbox, a hard drive from a donor: the files
were made by someone else, and the question is the same for each. The
programme below decides about every file in an inbox, moves it to
`accepted` or `quarantine`, and writes the verdict beside it, so that
whoever looks at the quarantine later can read why without running
anything.

It uses `check` rather than `require`, because here every reason matters,
not just the first; and a policy of its own, set from the real collection,
with a comment on each limit saying where the number came from:

```python
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from sillybos import Policy, check

UPLOADS = Policy(
    formats={"jpeg", "png", "tiff", "pdf"},
    max_bytes=64 * 2**20,  # 64 MiB: our largest real scan is 21 MiB
    max_pixels=40_000_000,  # our largest real page is 17 million pixels
    max_pages=120,  # our longest book is 58 pages
    png_colour_types={"greyscale", "rgb"},  # a scan is never a palette image
)

ACCEPTED = Path("accepted")
QUARANTINE = Path("quarantine")
for directory in (ACCEPTED, QUARANTINE):
    directory.mkdir(exist_ok=True)


def receive(upload: Path) -> bool:
    """Decide about a file we did not make, and keep the decision with it."""
    verdict = check(upload, UPLOADS)
    record = {
        "received": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "name": upload.name,
        "format": verdict.format,
        "ok": verdict.ok,
        "reasons": list(verdict.reasons),
        "summary": verdict.summary(),
    }
    dest = (ACCEPTED if verdict.ok else QUARANTINE) / upload.name
    shutil.move(upload, dest)
    dest.with_suffix(dest.suffix + ".json").write_text(json.dumps(record, indent=2))
    return verdict.ok


for upload in sorted(Path("inbox").iterdir()):
    print("accepted" if receive(upload) else "quarantined", upload.name)
```

Run over an inbox with a real scan, a GIF, a PostScript file called
`page.png` and a 63-megapixel poster:

```text
accepted    cover.png
quarantined invoice.gif
quarantined page.png
quarantined poster.jpg
```

and the records say why: `is GIF, not one of the formats a scan can be
(allowed: JPEG, PDF, PNG, TIFF)`; `says PNG, is PostScript`; `a page of
63,000,000 pixels; the limit is 40,000,000`. The accepted file's record
carries its summary, `PNG, 800x800, 1 page, 0.0 MB`, which is worth
keeping too: it is what the file looked like on the day it arrived.

Two habits make this hold up. Check a file you own: write an upload to a
directory nobody else can write to, then check and open that copy, so
that what the decoder opens is the same bytes the check read. And keep
the policy and the decoder's own limits in agreement. If the renderer
runs at 300 dpi, say `render_dpi=300`; if Pillow is allowed JPEG, PNG and
TIFF, say so in `formats`, and let `pillow_formats` carry the same list to
`Image.open`.

For a shell pipeline, the command does the same job: `sillybos --json
inbox/*` prints one verdict per line, and `sillybos -q --strict inbox/*`
prints only the refusals and exits 1 if there were any.
