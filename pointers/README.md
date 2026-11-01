# Pointer packages

Three names on PyPI that exist only to point at `sillybos`: the Latin
spelling, `sittybos`, and the two likely misspellings, `sittybus` and
`sillybus`. Each is an empty package whose one dependency is `sillybos`,
so `pip install sittybos` installs the real thing, and whose project page
says what happened.

They are held so that nobody else can register them: once a library has
users, a misspelling of its name with something unpleasant inside is a
cheap attack, and PyPI keeps no name without a release behind it.

They are published once, by hand, and never again:

```bash
cd pointers/sittybos && uv build && uv publish   # with a PyPI token
```

They are deliberately outside the release pipeline, the tests and the
package build: nothing here ever changes version with `sillybos`.
