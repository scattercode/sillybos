"""The ``sillybos`` command: check files, print verdicts, exit non-zero on a refusal.

For a shell pipeline or a Dockerfile::

    sillybos scans/*.tif && run-the-ocr scans/

Exit status 0 when every file passed, 1 when any was refused, 2 when the
command could not do its job (a missing file, no ``pdfinfo`` for a PDF).
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
        )
        if value is not None
    }
    if args.formats:
        changes["formats"] = frozenset(args.formats.split(","))
    if args.jpeg_frames:
        changes["jpeg_frames"] = frozenset(args.jpeg_frames.split(","))
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
        "--jpeg-frames",
        metavar="LIST",
        help=(
            "comma-separated JPEG frame codings to allow, from "
            "baseline,extended,progressive,lossless,hierarchical,arithmetic "
            "(default: the first three)"
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
