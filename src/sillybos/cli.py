"""The `sillybos` command: check files, print verdicts, exit non-zero on a refusal.

For a shell pipeline or a Dockerfile:

```bash
sillybos scans/*.tif && run-the-ocr scans/
```

Exit status 0 when every file passed, 1 when any was refused, 2 when the
command could not do its job (a missing file, no `pdfinfo` for a PDF).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from sillybos import __version__, check
from sillybos.pdf import PdfInfoMissing
from sillybos.policy import DEFAULT, STRICT, Policy


def _policy(args: argparse.Namespace) -> Policy:
    base = STRICT if args.strict else DEFAULT
    changes = {
        name: value
        for name, value in (
            ("max_bytes", args.max_bytes),
            ("max_pixels", args.max_pixels),
            ("max_pages", args.max_pages),
            ("max_metadata_bytes", args.max_metadata_bytes),
            ("max_png_bit_depth", args.max_png_bit_depth),
        )
        if value is not None
    }
    if args.formats:
        changes["formats"] = frozenset(args.formats.split(","))
    if args.jpeg_frames:
        changes["jpeg_frames"] = frozenset(args.jpeg_frames.split(","))
    if args.tiff_compressions:
        changes["tiff_compressions"] = frozenset(args.tiff_compressions.split(","))
    if args.png_colour_types:
        changes["png_colour_types"] = frozenset(args.png_colour_types.split(","))
    if args.interlaced_png:
        changes["allow_interlaced_png"] = True
    if args.no_tiled_tiff:
        changes["allow_tiled_tiff"] = False
    if args.tiff_photometrics:
        changes["tiff_photometrics"] = frozenset(args.tiff_photometrics.split(","))
    if args.tiff_subsamplings:
        changes["tiff_subsamplings"] = frozenset(args.tiff_subsamplings.split(","))
    if args.any_name:
        changes["name_must_match"] = False
    return dataclasses.replace(base, **changes) if changes else base


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sillybos",
        description=(
            "Decide before decoding: say whether each file is one of the formats a scan "
            "can be, within the limits, before any image library or PDF renderer opens it."
        ),
    )
    parser.add_argument("files", nargs="+", type=Path, metavar="FILE")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--strict", action="store_true", help="the strict preset, for files from outside"
    )
    parser.add_argument(
        "--formats",
        metavar="LIST",
        help="comma-separated formats to allow, from jpeg,png,tiff,pdf (default: all four)",
    )
    parser.add_argument("--max-bytes", type=int, metavar="N", help="largest file, in bytes")
    parser.add_argument(
        "--max-pixels", type=int, metavar="N", help="most pixels in any one page or frame"
    )
    parser.add_argument("--max-pages", type=int, metavar="N", help="most pages or frames")
    parser.add_argument(
        "--max-metadata-bytes",
        type=int,
        metavar="N",
        help="largest metadata block (a PNG chunk, a TIFF tag's data, a JPEG colour profile)",
    )
    parser.add_argument(
        "--jpeg-frames",
        metavar="LIST",
        help=(
            "comma-separated JPEG frame codings to allow, from "
            "baseline,extended,progressive,lossless,hierarchical,arithmetic "
            "(default: the first three)"
        ),
    )
    parser.add_argument(
        "--png-colour-types",
        metavar="LIST",
        help=(
            "comma-separated PNG colour types to allow, from "
            "greyscale,rgb,palette,greyscale-alpha,rgba (default: all five)"
        ),
    )
    parser.add_argument(
        "--max-png-bit-depth", type=int, metavar="N", help="deepest PNG sample (default: 16)"
    )
    parser.add_argument(
        "--interlaced-png", action="store_true", help="do not refuse an interlaced PNG"
    )
    parser.add_argument(
        "--no-tiled-tiff", action="store_true", help="refuse a TIFF laid out in tiles"
    )
    parser.add_argument(
        "--tiff-photometrics",
        metavar="LIST",
        help=(
            "comma-separated TIFF photometric interpretations to allow, by name "
            "(default: greyscale,rgb,palette,cmyk,ycbcr)"
        ),
    )
    parser.add_argument(
        "--tiff-subsamplings",
        metavar="LIST",
        help="comma-separated YCbCr subsamplings to allow, as 2x2 (default: 1x1,2x1,1x2,2x2)",
    )
    parser.add_argument(
        "--tiff-compressions",
        metavar="LIST",
        help=(
            "comma-separated TIFF compression schemes to allow, by name "
            "(default: none,ccitt,lzw,jpeg,deflate,packbits)"
        ),
    )
    parser.add_argument(
        "--any-name",
        action="store_true",
        help="do not refuse a file whose extension disagrees with its contents",
    )
    parser.add_argument("--json", action="store_true", help="one JSON object per line")
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="print only the files that were refused"
    )
    return parser


def _line(verdict: object, as_json: bool) -> str:
    from sillybos.check import Verdict

    if not isinstance(verdict, Verdict):  # pragma: no cover - typing guard
        raise TypeError(type(verdict))
    if as_json:
        record = dataclasses.asdict(verdict)
        record["path"] = str(verdict.path)
        return json.dumps(record, ensure_ascii=False)
    if verdict.ok:
        return f"ok       {verdict.path}  ({verdict.summary()})"
    return f"refused  {verdict.path}  {'; '.join(verdict.reasons)}"


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = _policy(args)
    except ValueError as exc:
        print(f"sillybos: {exc}", file=sys.stderr)
        return 2
    status = 0
    for path in args.files:
        try:
            verdict = check(path, policy)
        except FileNotFoundError:
            print(f"sillybos: {path}: no such file", file=sys.stderr)
            status = 2
            continue
        except PdfInfoMissing as exc:
            print(f"sillybos: {exc}", file=sys.stderr)
            return 2
        if not verdict.ok:
            status = max(status, 1)
        if verdict.ok and args.quiet:
            continue
        print(_line(verdict, args.json))
    return status


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
