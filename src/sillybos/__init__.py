"""sillybos: decide before decoding.

A σίλλυβος (*sillybos*, Latin *sittybus*) was the little parchment tag that
hung from a rolled scroll in an ancient library, giving its title and author
so that a reader could tell what a scroll was without unrolling it. This
library is that tag for the files a scanning or OCR pipeline is handed. It
answers one narrow question before any image library or PDF renderer opens a
file: *is this one of the formats I mean to read, within the limits I
expect, and if not, why?*

It reads the first bytes to learn what the file really is, whatever its name
says; reads the header of a JPEG, PNG or TIFF with code of its own, never a
decoder's; asks poppler's `pdfinfo`, in a separate process, how many pages
a PDF has and how large they are; and refuses, with a reason in plain words,
anything outside a [Policy][sillybos.Policy].

```python
from sillybos import check

verdict = check("scan.png")
verdict.ok, verdict.reasons  # (False, ('says PNG, is PostScript',))
```

The whole surface is [check][sillybos.check.check], which returns a [Verdict][sillybos.Verdict];
[require][sillybos.require], which raises [Refused][sillybos.Refused] instead; [Policy][sillybos.Policy],
with the presets [DEFAULT][sillybos.DEFAULT] and [STRICT][sillybos.STRICT]; and, with the
`[pillow]` extra, [sillybos.pillow.open_checked][].
"""

from __future__ import annotations

from sillybos.check import Facts, Refused, Verdict, check, require
from sillybos.policy import (
    DEFAULT,
    FORMATS,
    JPEG_FRAMES,
    PNG_COLOUR_TYPES,
    STRICT,
    TIFF_COMPRESSIONS,
    TIFF_PHOTOMETRICS,
    TIFF_SUBSAMPLINGS,
    Policy,
)

try:
    from sillybos._version import __version__
except ImportError:  # pragma: no cover - only in a checkout that has not been built
    __version__ = "0.0.0"

__all__ = [
    "DEFAULT",
    "FORMATS",
    "JPEG_FRAMES",
    "PNG_COLOUR_TYPES",
    "STRICT",
    "TIFF_COMPRESSIONS",
    "TIFF_PHOTOMETRICS",
    "TIFF_SUBSAMPLINGS",
    "Facts",
    "Policy",
    "Refused",
    "Verdict",
    "__version__",
    "check",
    "require",
]
