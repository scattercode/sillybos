"""Check a file, then open it with Pillow using only the readers the policy allows.

The one-line fix that October 2026's Pillow advisories made everyone want,
packaged: `Image.open` takes a `formats` list, and a file that is not one
of them is never handed to the other readers, whatever it claims to be.
[open_checked][sillybos.pillow.open_checked] runs [sillybos.require][] first, so a file that is
too large, lies about its format or has a page beyond the limit is refused
before Pillow sees it, and then opens it with `formats` set from the
policy.

Needs the `[pillow]` extra: `pip install 'sillybos[pillow]'`.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from sillybos.check import require
from sillybos.policy import DEFAULT, Policy

if TYPE_CHECKING:
    from PIL import Image

_PILLOW_NAMES = {"jpeg": "JPEG", "png": "PNG", "tiff": "TIFF"}


def pillow_formats(policy: Policy = DEFAULT) -> list[str]:
    """The `formats` argument for `Image.open`, from a policy: `["JPEG", "PNG", "TIFF"]`."""
    return [_PILLOW_NAMES[name] for name in sorted(policy.formats) if name in _PILLOW_NAMES]


def open_checked(path: str | os.PathLike[str], policy: Policy = DEFAULT) -> Image.Image:
    """Check `path` against `policy`, then open it with only the allowed Pillow readers.

    A PDF passes the check but Pillow does not read PDFs; opening one raises
    `PIL.UnidentifiedImageError`, as it would for any file outside
    `formats`.

    Raises:
        sillybos.Refused: If the file does not pass the policy.
        ImportError: If Pillow is not installed.
    """
    try:
        from PIL import Image
    except ImportError:
        raise ImportError("open_checked needs Pillow: pip install 'sillybos[pillow]'") from None
    require(path, policy)
    return Image.open(path, formats=pillow_formats(policy))
