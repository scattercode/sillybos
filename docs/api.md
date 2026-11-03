# API reference

Everything the package exports, generated from the docstrings. The
[policy table](index.md#the-policy) says what each limit bounds and why.

::: sillybos
    options:
      members: false
      show_root_heading: false
      show_root_toc_entry: false

## The check

<!-- sillybos.check is both the function and the module it is defined in;
     griffe keeps the module under that name, so the function is addressed
     by where it is defined. -->
::: sillybos.check.check

::: sillybos.require

::: sillybos.Verdict

::: sillybos.Facts

::: sillybos.Refused

::: sillybos.pdf.PdfInfoMissing

## The policy

::: sillybos.Policy

::: sillybos.DEFAULT

::: sillybos.STRICT

## The names

What a policy's fields and a verdict's facts are spelt with. Each tuple is
every name the library knows, in the order the reasons list them; a policy
chooses from it.

::: sillybos.FORMATS

::: sillybos.JPEG_FRAMES

::: sillybos.PDF_FEATURES

::: sillybos.PDF_IMAGE_CODECS

::: sillybos.PNG_COLOUR_TYPES

::: sillybos.TIFF_COMPRESSIONS

::: sillybos.TIFF_PHOTOMETRICS

::: sillybos.TIFF_SUBSAMPLINGS

::: sillybos.TIFF_TAGS

## With Pillow

::: sillybos.pillow
    options:
      show_root_heading: false
      show_root_toc_entry: false
