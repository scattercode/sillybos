# Decoding in a box

The check removes the files a decoder should never see: the wrong format,
the lying name, the size that would exhaust memory, the codings a scanner
never writes, the PDF features a book never has. What it cannot remove is
a flaw in the reader you *do* allow, reached by a file of a sensible size
in a format you meant to read. The README says so under [what it does not
do](index.md#what-it-does-not-do). This page is the recipe for the next
line of defence: run the decoder where a flaw costs one file and not the
process that opened it.

Written for Linux, where the operating system will hold a process to a
memory allowance. macOS will not, and the page says what that leaves.
Nothing here is a dependency of sillybos; it is a pattern, in two short
files, that we ran before writing it up.

## The shape

Two processes. The parent checks the file with sillybos, then starts a
worker in a fresh Python with no environment, a scratch directory as its
working directory, nothing on its standard input and a wall-clock limit.
The worker's first act is to set limits on itself: how much memory it may
address, how much processor time it may use, how large a file it may
write, and no core dump. Then it opens the file with only the allowed
readers, decodes it, and writes the pixels out as a PNG of its own making.

Whatever happens in the worker, the parent gets one of two things: the
PNG, or a sentence saying why not. A decoder that reads past a buffer, or
allocates until the machine swaps, or loops, does so inside an allowance
and dies alone.

## The worker

```python
"""The worker: set the limits on itself, then open, decode and write. Nothing else.

Run only by boxed.py. The limits are set here, in the child, rather than
with `preexec_fn` in the parent, which is unsafe in a program with threads.
On Linux `RLIMIT_AS` bounds what the process may address, so an allocation
beyond it fails instead of growing; macOS does not enforce it, and there
the wall-clock limit is the one that holds.
"""

from __future__ import annotations

import argparse
import resource
import sys


def limit(kind: int, value: int) -> None:
    soft, hard = resource.getrlimit(kind)
    if hard != resource.RLIM_INFINITY:
        value = min(value, hard)
    resource.setrlimit(kind, (value, value))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("destination")
    parser.add_argument("--memory", type=int, required=True)
    parser.add_argument("--cpu-seconds", type=int, required=True)
    parser.add_argument("--max-output", type=int, required=True)
    parser.add_argument("--formats", required=True)
    args = parser.parse_args()

    limit(resource.RLIMIT_AS, args.memory)
    limit(resource.RLIMIT_CPU, args.cpu_seconds)
    limit(resource.RLIMIT_FSIZE, args.max_output)
    limit(resource.RLIMIT_CORE, 0)

    from PIL import Image

    Image.MAX_IMAGE_PIXELS = None  # the check already judged the size; the box is what holds it
    with Image.open(args.source, formats=args.formats.split(",")) as image:
        image.load()  # the decode: this is the line the box exists for
        image.save(args.destination, format="PNG")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

The limits are set in the child, not with `preexec_fn` in the parent,
which is unsafe in any program with threads. `RLIMIT_AS` is what makes the
box a box on Linux: an allocation beyond it fails, so a decoder that wants
more than the allowance gets a `MemoryError` or a kill instead of the
machine's memory. `RLIMIT_FSIZE` stops a worker writing an output the size
of a disk; `RLIMIT_CPU` is a second clock in case the parent's is
defeated. `Image.MAX_IMAGE_PIXELS` is lifted because the check has already
judged the size against your policy; inside the box, the allowance is what
holds.

## The parent

```python
"""Decode an image in a boxed subprocess, after the check, so a flaw in the decoder costs one file.

The parent checks the file with sillybos and then runs the worker below in
a fresh process with the memory, CPU and output limits set inside it,
a wall-clock limit from outside, no environment, a scratch directory as
its working directory and nothing on standard input. The worker opens the
file with only the allowed readers, decodes it, and writes the pixels out
as a PNG of its own making. Whatever happens in the worker, the parent
gets either that PNG or a sentence saying why not.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from sillybos import DEFAULT, Policy, Refused, require
from sillybos.pillow import pillow_formats

WORKER = Path(__file__).with_name("boxed_worker.py")
BASELINE_BYTES = 256 * 2**20  # the interpreter, Pillow and its codecs, with room
BYTES_PER_PIXEL = 8  # the decoded image and one working copy, four channels each
SECONDS_PER_MEGAPIXEL = 1.0


class DecodeRefused(Exception):
    """The box refused the file: the limit it hit and, where there is one, the decoder's own words."""


def memory_limit(policy: Policy) -> int:
    """What the worker may address, from the policy's pixel ceiling. Measure yours and adjust."""
    return BASELINE_BYTES + BYTES_PER_PIXEL * policy.max_pixels


def decode_in_box(
    path: Path, out: Path, policy: Policy = DEFAULT, *, memory: int | None = None
) -> Path:
    """Check `path`, then decode it in a limited subprocess, writing a PNG to `out`.

    `memory` is the worker's address-space limit in bytes; by default it is
    sized from the policy with `memory_limit`.
    """
    verdict = require(path, policy)  # Refused, with the reasons, before anything decodes
    assert verdict.facts is not None
    wall_seconds = (
        5 + SECONDS_PER_MEGAPIXEL * verdict.facts.max_pixels / 1_000_000
        if verdict.facts.max_pixels
        else 30
    )
    with tempfile.TemporaryDirectory() as scratch:
        try:
            done = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(WORKER),
                    str(path.resolve()),
                    str(out.resolve()),
                    "--memory",
                    str(memory if memory is not None else memory_limit(policy)),
                    "--cpu-seconds",
                    str(int(wall_seconds) + 1),
                    "--max-output",
                    str(64 * 2**20),
                    "--formats",
                    ",".join(pillow_formats(policy)),
                ],
                cwd=scratch,
                env={"PATH": os.defpath},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=wall_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise DecodeRefused(
                f"the decoder did not finish within {wall_seconds:.0f} seconds"
            ) from None
    if done.returncode == 0:
        return out
    if done.returncode < 0:
        name = signal.Signals(-done.returncode).name
        why = {
            "SIGKILL": "was killed, which is what running out of memory looks like",
            "SIGXCPU": "used more processor time than it was allowed",
            "SIGXFSZ": "tried to write more output than it was allowed",
            "SIGSEGV": "crashed",
        }.get(name, f"ended with {name}")
        raise DecodeRefused(f"the decoder {why}")
    last = (done.stderr.strip().splitlines() or ["no message"])[-1]
    raise DecodeRefused(f"the decoder failed: {last}")
```

Three things to notice. The check runs first, so the box only ever sees
files that passed; its job is the flaws the check cannot know about. The
allowance is sized from the policy: a baseline for the interpreter and its
libraries, plus so many bytes a pixel for the decoded image and a working
copy. Measure yours with a few real files and adjust the two constants;
they are starting points, not a specification. And a dead worker is turned
into a sentence: the signal that ended it says what happened, and a Python
exception's last line is passed through.

## What it looks like

We ran the two files on Linux (a `python:3.12-slim` container with Pillow
and sillybos installed) against a normal scan and a small PNG that decodes
to 12,000 by 12,000 pixels in RGB: 445 KB on disk, 432 MB decoded.

```text
1. a normal scan: /tmp/box/page.png (1200, 1600)
2. the bomb under the default policy: refused before decoding:
   ('a page of 144,000,000 pixels; the limit is 89,478,485',)
3. the bomb under a policy that allows it, so only the box stands in the
   way (the policy's own allowance would be 1782 MiB; the box is given
   512 MiB): refused by the box: the decoder failed: MemoryError after 0.1s
4. a normal scan under the same 512 MiB box: page2.png
```

The second line is the check doing its job. The third is the box doing
its own: the policy was loosened to let the file through, as a flaw in a
decoder effectively does, and the worker failed in a tenth of a second
inside its allowance, with the parent, and the machine, untouched. The
fourth shows the same box is no obstacle to a real scan.

## Going further on Linux

The two files use what Python's standard library offers. The system has
more, and each is one line in the parent's command:

- **`systemd-run`** puts the worker in its own control group, where
  `MemoryMax=` is enforced against everything the process and its
  children allocate, not only the address space, and `CPUQuota=` bounds
  the processor: `systemd-run --user --scope -p MemoryMax=512M -p
  CPUQuota=100% python boxed_worker.py …`.
- **`bwrap`** (bubblewrap) gives the worker a filesystem with only what it
  needs and no network: `bwrap --unshare-all --ro-bind /usr /usr --ro-bind
  /lib /lib --bind "$scratch" /work --chdir /work python …`. A decoder
  that is made to run a command finds nothing to run it on.
- **A container** does both, at the cost of starting one per file or
  keeping one running. If the pipeline is already in a container, the
  worker can be too, with `--memory`, `--cpus`, `--network none` and
  `--read-only`.

Pick the first that fits where the pipeline runs. All of them keep the
same two-process shape and the same parent; only the command changes.

## What macOS leaves you

`RLIMIT_AS` is accepted and ignored on macOS, and `RLIMIT_CPU` is honoured
only loosely. What remains is the wall-clock limit, the output limit, the
scrubbed environment and the separate process, which still means a crash
is one file's failure rather than the pipeline's. A pipeline that runs on
a laptop for development and on Linux in production gets the full box
where it matters. If the files are from outside and the machine is a Mac,
run the worker in a Linux container.

## What the box is not

It is not a sandbox against a determined attacker: a process with the
same user can still read what that user can read, and `RLIMIT_AS` is a
memory allowance, not a security boundary. For that, the tools above
(`bwrap`, a container, or a dedicated sandbox such as `firejail` or a
virtual machine) are the ones to reach for. And it is no reason to skip
updating the decoders: the first line of every entry in the [security
watch](https://tetrak.dev/security/) is the fixed version.
