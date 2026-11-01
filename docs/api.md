# API reference

Everything the package exports, generated from the docstrings. The
[policy table](index.md#the-policy) says what each limit bounds and why.

```{eval-rst}
.. automodule:: sillybos
```

## The check

```{eval-rst}
.. autofunction:: sillybos.check

.. autofunction:: sillybos.require

.. autoclass:: sillybos.Verdict
   :members:

.. autoclass:: sillybos.Facts

.. autoexception:: sillybos.Refused

.. autoexception:: sillybos.pdf.PdfInfoMissing
```

## The policy

```{eval-rst}
.. autoclass:: sillybos.Policy
   :members:

.. autodata:: sillybos.DEFAULT
   :no-value:

.. autodata:: sillybos.STRICT
   :no-value:
```

## The names

What a policy's fields and a verdict's facts are spelt with. Each tuple is
every name the library knows, in the order the reasons list them; a policy
chooses from it.

```{eval-rst}
.. autodata:: sillybos.FORMATS

.. autodata:: sillybos.JPEG_FRAMES

.. autodata:: sillybos.PNG_COLOUR_TYPES

.. autodata:: sillybos.TIFF_COMPRESSIONS

.. autodata:: sillybos.TIFF_PHOTOMETRICS

.. autodata:: sillybos.TIFF_SUBSAMPLINGS
```

## With Pillow

```{eval-rst}
.. automodule:: sillybos.pillow
   :members:
```
