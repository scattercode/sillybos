"""Fuzz the header readers: mutate well-formed files and check that every outcome is a verdict.

The library's claim is that its own readers can be shown any bytes and will
either describe the file or refuse it with a reason, in bounded time and
memory, with nothing in between: no other exception, no hang, no runaway
allocation. The hostile corpus proves that for the cases we thought of. This
script looks for the ones we did not, by taking the corpus's well-formed
files as seeds, damaging them at random, and running each result through
the same readers the check uses.

A finding is any input on which a reader raises something other than
``HeaderError``, or takes longer than the per-input limit. The input is
written to ``fuzz-findings/`` with the exception beside it, so the case can
be turned into a test, and the script exits 1.

Run it for a while before a release, and CI runs it briefly on every pull
request and for longer each week::

    python scripts/fuzz_headers.py --seconds 60
    python scripts/fuzz_headers.py --seconds 300 --seed 7

Standard library and the test corpus only. The seed makes a run
reproducible; the default is random, and the seed used is printed.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import random
import signal
import struct
import sys
import time
import traceback
from collections.abc import Callable, Iterable
from pathlib import Path
from types import FrameType

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sillybos import headers, sniff  # noqa: E402
from sillybos.headers import HeaderError  # noqa: E402
from tests import corpus  # noqa: E402

FINDINGS = ROOT / "fuzz-findings"
PER_INPUT_SECONDS = 5
MAX_PAGES = 500

#: Values a mutated length or offset field is set to: the edges where an
#: unchecked read or multiplication goes wrong.
BOUNDARIES = (0, 1, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF)


class Timeout(Exception):
    """A reader did not finish within the per-input limit."""


def seeds() -> list[bytes]:
    """Well-formed files in every shape the readers know, from the test corpus."""
    out = [
        corpus.jpeg(640, 480),
        corpus.jpeg(640, 480, marker=0xC2),
        corpus.jpeg(64, 64, before_sof=corpus.jpeg_profile(4096)),
        corpus.jpeg(64, 64, before_sof=corpus.jpeg_padding(300)),
        corpus.mpo([(64, 64), (32, 32), (16, 16)]),
        corpus.png(640, 480),
        corpus.png(64, 64, frames=3),
        corpus.png(64, 64, extra=corpus.png_chunk(b"eXIf", 2048)),
        corpus.png(64, 64, after_idat=corpus.png_chunk(b"tEXt", 128)),
        corpus.tiff([(64, 64), (32, 32), (16, 16)]),
        corpus.tiff([(64, 64)], endian=">"),
        corpus.tiled_tiff(256, 256, 64),
    ]
    try:
        from PIL import Image
    except ImportError:
        return out
    for fmt, mode in (("JPEG", "RGB"), ("PNG", "L"), ("TIFF", "RGB")):
        buffer = io.BytesIO()
        Image.new(mode, (48, 40), 128).save(buffer, format=fmt)
        out.append(buffer.getvalue())
    pages = [Image.new("L", (24, 24), 255) for _ in range(3)]
    buffer = io.BytesIO()
    pages[0].save(
        buffer, format="TIFF", save_all=True, append_images=pages[1:], compression="tiff_lzw"
    )
    out.append(buffer.getvalue())
    return out


Mutation = Callable[[bytearray, random.Random], None]


def flip_bits(data: bytearray, rng: random.Random) -> None:
    for _ in range(rng.randint(1, 8)):
        i = rng.randrange(len(data))
        data[i] ^= 1 << rng.randrange(8)


def set_bytes(data: bytearray, rng: random.Random) -> None:
    for _ in range(rng.randint(1, 4)):
        data[rng.randrange(len(data))] = rng.choice((0x00, 0xFF, 0x7F, 0x80, rng.randrange(256)))


def set_field(data: bytearray, rng: random.Random) -> None:
    """Overwrite a 2- or 4-byte field, either endian, with a boundary value."""
    width = rng.choice((2, 4))
    if len(data) <= width:
        return
    i = rng.randrange(len(data) - width)
    value = rng.choice(BOUNDARIES) & ((1 << (8 * width)) - 1)
    data[i : i + width] = struct.pack(rng.choice(("<", ">")) + ("H" if width == 2 else "I"), value)


def truncate(data: bytearray, rng: random.Random) -> None:
    if len(data) > 1:
        del data[rng.randrange(1, len(data)) :]


def delete_run(data: bytearray, rng: random.Random) -> None:
    i = rng.randrange(len(data))
    del data[i : i + rng.randint(1, 64)]


def insert_run(data: bytearray, rng: random.Random) -> None:
    i = rng.randrange(len(data) + 1)
    data[i:i] = rng.randbytes(rng.randint(1, 64))


def duplicate_block(data: bytearray, rng: random.Random) -> None:
    i = rng.randrange(len(data))
    j = min(len(data), i + rng.randint(1, 512))
    k = rng.randrange(len(data) + 1)
    data[k:k] = data[i:j]


def splice(data: bytearray, rng: random.Random, pool: list[bytes]) -> None:
    other = rng.choice(pool)
    i = rng.randrange(len(other))
    j = min(len(other), i + rng.randint(1, 256))
    k = rng.randrange(len(data) + 1)
    data[k:k] = other[i:j]


def mutate(seed: bytes, rng: random.Random, pool: list[bytes]) -> bytes:
    data = bytearray(seed)
    mutations: list[Mutation] = [
        flip_bits,
        set_bytes,
        set_field,
        set_field,
        truncate,
        delete_run,
        insert_run,
        duplicate_block,
        lambda d, r: splice(d, r, pool),
    ]
    for _ in range(rng.randint(1, 4)):
        if not data:
            break
        rng.choice(mutations)(data, rng)
    return bytes(data)


def _alarm(signum: int, frame: FrameType | None) -> None:
    raise Timeout


def run_one(data: bytes) -> str | None:
    """Run the readers on one input. Returns the format read, or None if no reader claims it."""
    fmt = sniff.sniff(data[: sniff.HEAD_BYTES])
    reader = headers.READERS.get(fmt or "")
    if reader is None:
        return None
    signal.alarm(PER_INPUT_SECONDS)
    try:
        reader(io.BytesIO(data), len(data), MAX_PAGES)
    except HeaderError:
        pass
    finally:
        signal.alarm(0)
    return fmt


def record_finding(data: bytes, error: BaseException, seed_used: int, iteration: int) -> Path:
    FINDINGS.mkdir(exist_ok=True)
    digest = hashlib.sha256(data).hexdigest()[:16]
    path = FINDINGS / f"{digest}.bin"
    path.write_bytes(data)
    note = FINDINGS / f"{digest}.txt"
    note.write_text(
        f"seed {seed_used}, iteration {iteration}, {len(data)} bytes\n\n"
        + "".join(traceback.format_exception(error))
    )
    return path


def fuzz(seconds: float, iterations: int | None, seed_used: int, quiet: bool) -> int:
    # Mutations, not secrets: the generator is seeded so a run can be repeated.
    rng = random.Random(seed_used)  # noqa: S311
    pool = seeds()
    counts: dict[str, int] = {}
    findings = 0
    started = time.monotonic()
    n = 0
    signal.signal(signal.SIGALRM, _alarm)
    while (time.monotonic() - started) < seconds and (iterations is None or n < iterations):
        n += 1
        data = mutate(rng.choice(pool), rng, pool)
        try:
            fmt = run_one(data)
        except Exception as error:
            findings += 1
            path = record_finding(data, error, seed_used, n)
            print(f"FINDING {type(error).__name__}: {error} -> {path}", file=sys.stderr)
            continue
        counts[fmt or "none"] = counts.get(fmt or "none", 0) + 1
    elapsed = time.monotonic() - started
    if not quiet:
        read = ", ".join(f"{k} {v:,}" for k, v in sorted(counts.items()))
        print(f"seed {seed_used}: {n:,} inputs in {elapsed:.0f}s ({read}); {findings} finding(s)")
    return 1 if findings else 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--seconds", type=float, default=60, help="time budget (default 60)")
    parser.add_argument("--iterations", type=int, help="stop after this many inputs instead")
    parser.add_argument("--seed", type=int, help="make the run reproducible")
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    seed_used = args.seed if args.seed is not None else random.SystemRandom().randrange(2**32)
    return fuzz(args.seconds, args.iterations, seed_used, args.quiet)


if __name__ == "__main__":
    sys.exit(main())
