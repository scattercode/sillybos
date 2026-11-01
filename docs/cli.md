# Command line reference

Every flag of the `sillybos` command, as its own `--help` prints them,
generated from the parser at build time. The [README](index.md#the-command)
shows what a run looks like.

::: sillybos.cli
    options:
      members: false
      show_root_heading: false
      show_root_toc_entry: false

```python exec="true" result="text"
from sillybos.cli import build_parser

print(build_parser().format_help())
```
