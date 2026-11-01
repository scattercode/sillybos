"""Sphinx configuration for the sillybos reference.

Published to GitHub Pages at https://scattercode.github.io/sillybos/ by
.github/workflows/docs.yml on every push to main. The site is the README
(what the library is, how to install and use it, the policy table, what it
does and does not do), included rather than copied, followed by the API and
command line reference generated from the code. The docstrings are the one
place the API is described; this file only arranges them.

Same arrangement as the Tetrak reference (scattercode/tetrak, docs/conf.py):
furo, autodoc with napoleon, MyST for the Markdown pages, sphinx-argparse for
the command.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sphinx.pycode import ModuleAnalyzer

if TYPE_CHECKING:
    from sphinx.application import Sphinx

project = "sillybos"
copyright = "2026, Stephen Masters, Yvette Mankerian"
author = "Stephen Masters, Yvette Mankerian"

try:
    from sillybos._version import version as release
except ImportError:  # a bare checkout, not yet built with hatch-vcs
    release = "0.0.0"

# Sphinx's default page title is "{project} {release} documentation", and
# hatch-vcs derives `release` from git describe -- so on any commit that is
# not exactly a tag it carries PEP 440 build metadata: "2.0.1.dev2+g9f4085a".
# The segment after "+" is the commit hash, which is noise in a browser tab.
#
# Stripped for display only. The `.devN` part stays: it is the honest signal
# that a build came from an untagged commit, and hiding it would let the docs
# claim a version that was never released. A release build has neither part
# and reads simply "sillybos 2.0.0 documentation".
version = release.split("+", 1)[0]
html_title = f"{project} {version} documentation"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinxarg.ext",
    "myst_parser",
]

autodoc_member_order = "bysource"
# Show a default as the source spells it. Every function takes
# ``policy: Policy = DEFAULT``, and the evaluated default is the whole
# Policy(...) repr, twenty fields long, in every signature.
autodoc_preserve_defaults = True
napoleon_google_docstring = True
napoleon_numpy_docstring = True

source_suffix = {".rst": "restructuredtext", ".md": "markdown"}
# The pages link to headings on other pages (`index.md#the-policy`). MyST
# only resolves those when it generates anchors for headings; three levels
# covers every heading the README has.
myst_heading_anchors = 3
root_doc = "index"
exclude_patterns = ["_build"]

html_theme = "furo"
html_logo = "logo.png"
html_theme_options = {
    "source_repository": "https://github.com/scattercode/sillybos",
    "source_branch": "main",
    "source_directory": "docs/",
}

# The name tuples (FORMATS, JPEG_FRAMES, ...) and the presets DEFAULT and
# STRICT are defined in sillybos.policy, with their docstrings beside the
# assignments, and re-exported from the package. api.md documents them under
# the name a reader imports, sillybos.FORMATS, which is also what the
# cross-references in the docstrings use. autodoc, though, looks for an
# attribute's docstring only in the module named in the directive, finds
# nothing in sillybos/__init__.py, and falls back to the docstring of the
# value's type ("Built-in immutable sequence ..."). This reads it from where
# it is written instead.
_DATA_DEFINED_IN = {"sillybos": "sillybos.policy"}


def _data_docstring(
    app: Sphinx, what: str, name: str, obj: object, options: Any, lines: list[str]
) -> None:
    modname, _, attr = name.rpartition(".")
    defined_in = _DATA_DEFINED_IN.get(modname)
    if what != "data" or defined_in is None:
        return
    analyzer = ModuleAnalyzer.for_module(defined_in)
    analyzer.analyze()
    doc = analyzer.attr_docs.get(("", attr))
    if doc is not None:
        lines[:] = list(doc)


def setup(app: Sphinx) -> None:
    app.connect("autodoc-process-docstring", _data_docstring)
