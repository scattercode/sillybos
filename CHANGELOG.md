# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.2.0] - 2026-11-03

### Changed

- Refresh the apt index before installing poppler
- Confirm CVE-2024-13978, tiff2pdf is a tool, not a library call
- Promote rewrites the note that says a proposal is unconfirmed
- Confirm CVE-2024-56826, an opj_decompress option, not a library call
- Confirm CVE-2024-56827, the second opj_decompress option report
- Confirm CVE-2025-8176, tiffmedian is a tool, not a library call
- Confirm CVE-2025-8177, the thumbnail tool, not a library call
- Confirm CVE-2025-8534, tiff2ps is a tool, not a library call
- Confirm CVE-2025-8851, tiffcrop is a tool, not a library call
- Confirm CVE-2025-8961, tiffcrop again, not a library call
- Confirm CVE-2025-9165, tiffcmp is a tool, not a library call
- Confirm CVE-2025-27363, an embedded font reaches FreeType, nothing filtered
- Confirm the five other embedded-font records, nothing filtered
- Confirm CVE-2025-28162, libpng's test program, not a library call
- Confirm CVE-2025-28164, a setup leak under a sanitiser, not file-triggered
- Confirm CVE-2025-32364, a function stream only the renderer evaluates
- Confirm CVE-2025-32365, a JBIG2 stream refusable by name
- Confirm CVE-2025-43718, pdfinfo crashes and the check fails closed
- Confirm CVE-2025-43903, signature checking is a call rendering never makes
- Confirm CVE-2025-48379, Pillow's DDS save path, not Image.open
- Confirm CVE-2025-50420, pdfseparate is a tool, not a library call
- Confirm CVE-2025-50952, JPEG 2000 refused by name; JPX in a PDF by setting
- Confirm CVE-2025-52885, the structure tree, pdfinfo fails closed
- Confirm CVE-2025-52886, shared reference counting, pdfinfo fails closed
- Confirm CVE-2025-54874, JPEG 2000 refused by name; JPX in a PDF by setting
- Confirm CVE-2025-61143, in TIFFOpen's setup, before any tag
- Confirm CVE-2025-61145, tiffcrop again, not a library call
- Confirm CVE-2025-61144, tiffcrop again, not a library call
- Confirm CVE-2025-64505, a palette PNG, refused by setting
- Confirm CVE-2025-64506, libpng's write path, not a read
- Confirm CVE-2026-3713, a contributed tool, not a library call
- Confirm CVE-2026-6192, OpenJPEG's encoder, never run on a read
- Confirm CVE-2026-10118, a tiling pattern only the renderer sees
- Confirm CVE-2026-18495, tiff2pdf on a BigTIFF, not a library call
- Confirm CVE-2026-22801, libpng's write path, not a read
- Confirm CVE-2026-22184, a zlib demonstration, not a library call
- Confirm CVE-2026-25646, quantizing is a call Pillow never makes
- Confirm CVE-2026-25990, a Photoshop file refused by name
- Confirm CVE-2026-27171, a zlib helper that inflating never calls
- Confirm CVE-2026-33416, setter APIs that reading never calls
- Confirm CVE-2026-34757, a caller's misuse of the setter API
- Confirm CVE-2026-40192, a FITS file refused as unknown
- Confirm CVE-2026-40930, the push-mode APNG reader, not a header field
- Confirm CVE-2026-42308, text drawing, which Image.open never runs
- Confirm CVE-2026-42309, the drawing APIs, which Image.open never runs
- Confirm CVE-2026-42310, PdfParser runs only on append
- Confirm CVE-2026-42311, a Photoshop file refused by name
- Confirm CVE-2026-52490, tiffcrop's options, not a library call
- Confirm CVE-2026-52491, the thumbnail tool, not a library call
- Confirm CVE-2026-52492, rgb2ycbcr is a tool, not a library call
- Confirm CVE-2026-54058, a McIdas file refused as unknown
- Confirm CVE-2026-54059, font loading, not Image.open
- Confirm CVE-2026-54060, font handling, which Image.open never runs
- Confirm CVE-2026-55379, font loading, not Image.open
- Say how the three bitmap-font records are kept from Image.open
- Confirm CVE-2026-55380, GdImageFile is not registered with Image.open
- Confirm CVE-2026-55798, ImageShow, which opening a file never runs
- Say what reaches ImageShow in CVE-2026-55798
- Confirm CVE-2026-59197, a filter size the program chooses
- Bucket N means the check is not in the path, not "we never call it"
- Say what rides across in CVE-2026-59198, the TGA run-length encoder
- Confirm CVE-2026-59198, the program's choice of run-length TGA
- Say what the check bounds in CVE-2026-59199, coordinates near the limit
- Confirm CVE-2026-59199, a box the program chooses; the check bounds the geometry
- Confirm CVE-2026-59200, a stream's expansion is in the object graph
- Confirm CVE-2026-59203, a PostScript file refused by name
- Confirm CVE-2026-59204, a JPEG 2000 file refused by name
- CVE-2026-59205, show that a file cannot cause the mode mismatch
- Confirm CVE-2026-59205, a mode mismatch between two objects the program builds
- CVE-2026-85091, nothing in the image stack calls zlib's gz write layer
- Confirm CVE-2026-85091, zlib's gz write layer, which no image library calls
- Confirm CVE-2026-93311, a function dictionary only the renderer evaluates
- Confirm CVE-2026-93312, a JBIG2 stream refusable by name
- Confirm CVE-2026-93313, the last JBIG2 stream record
- Confirm CVE-2026-93653, a tiling pattern only the renderer sees
- Confirm CVE-2026-96638, a BMP refused by name
- Confirm CVE-2026-96640, a repeated page-tree child is in the object graph
- CVE-2026-96641, the carrier is a font file, not an image
- CVE-2026-96641 is fixed in Pillow 13.0.0, and how to detect it before that
- N is never "ignore": a font or archive that carries a trigger is A
- Confirm CVE-2026-96641, a PILfont refused as unknown
- Confirm CVE-2026-96642, a tar archive refused as unknown
- Confirm CVE-2026-96644, a Windows metafile refused as unknown
- Confirm CVE-2026-96778, the profile that fills the JPEG encoder's buffer
- Confirm CVE-2026-102621, a clipping path only the renderer sees
- Confirm CVE-2026-107080, OpenJPEG's encoder, which no file reaches
- Confirm CVE-2026-107705 as A, an encrypted PDF is refused by default
- CVE-2026-107705 is A after all, with the encrypted-PDF test named
- CVE-2026-112392 is A, a zero dimension is refused under every policy
- Confirm CVE-2026-112392, a zero dimension refused under every policy
- Confirm CVE-2026-112394 as A by setting, a palette image refused under a scans-only policy
- CVE-2026-112396 confirmed as B; promotion waits for the TIFF tag policy
- Confirm CVE-2026-112397, a PPM refused as unknown, a zero width refused anyway
- Confirm CVE-2026-112400, a GIF refused by name
- Confirm CVE-2026-112401, a GIF refused by name
- CVE-2026-112402, no file carries the transform size; what the check bounds
- Confirm CVE-2026-112402, a transform size the program chooses
- Confirm CVE-2026-112405, a headerless file refused as unknown
- Confirm CVE-2026-112406, a page-tree cycle is in the object graph
- Confirm CVE-2026-112891, a long comment bounded by the metadata ceiling
- Confirm CVE-2026-112892, an MSP file refused as unknown
- Confirm CVE-2026-112893, a malformed font refused as unknown
- Confirm CVE-2026-112894, a frame count bounded by max_pages
- Confirm CVE-2026-112895, a Kids cycle or Prev chain is in the object graph
- CVE-2026-112896 confirmed as B; promotion waits for the TIFF tag policy
- Confirm CVE-2026-112897 as A by setting, JPEG-in-TIFF refused by tiff_compressions
- CVE-2026-112897 is A by setting after all, with the compression test named
- CVE-2026-112898 is A by setting, a file can carry the empty palette
- Confirm CVE-2026-112898 as A by setting, an empty palette refused under a scans-only policy
- Confirm CVE-2026-112899, a PostScript file refused by name
- CVE-2026-112902 confirmed as B; promotion waits for the TIFF tag policy
- Confirm CVE-2026-114501, an Arrow export leak that no file reaches
- Confirm GHSA-78g4-xqwv-q3g8, a JPEG 2000 file refused by name
- A policy on a TIFF's tags, and on tags that contradict each other

### Fixed

- A JPEG-compressed TIFF is refused under a policy without jpeg, for CVE-2026-112897

## [4.1.0] - 2026-11-03

### Changed

- Say what the max_side default is measured against
- A policy on the codecs a PDF's images may use, found by filter name
- Promote CVE-2025-9900, now that max_side holds every side

## [4.0.0] - 2026-11-01

### Changed

- Hold sittybos, sittybus and sillybus on PyPI as pointers at sillybos
- Tidy the pointer packages before their one-off upload
- The recipe for decoding in a box
- Propose records for the 101 advisories since 2025, for a person to confirm
- Allow the advisory record's key field through gitleaks
- Hold every page, frame and tile to max_side on its longest side

### Fixed

- Fuzz the header readers, briefly on every pull request and for ten minutes a week

## [3.0.0] - 2026-11-01

### Changed

- Three tutorials, each a complete programme we ran
- Format the tutorials' code blocks as ruff does
- Refuse the PDF features a scanned book never has

### Fixed

- Look for JavaScript by name too, since poppler before 26 does not report an open action's script

## [2.1.0] - 2026-11-01

### Changed

- Build the reference with Sphinx and publish it to GitHub Pages
- Move the reference from Sphinx to Zensical
- Commit the triage record, one file per advisory, with the test that proves each refusal

### Fixed

- Fill the five libpng records from OSV

## [2.0.0] - 2026-11-01

### Changed

- Header checks for TIFF compression, layout, tiles and colour, PNG kind, and metadata size

## [1.1.0] - 2026-11-01

### Changed

- Weekly advisory fetch for the watchlist

## [1.0.0] - 2026-11-01

### Changed

- Refuse rare JPEG frame codings and read every picture of an MPF file

## [0.1.0] - 2026-11-01

### Changed

- The check, the policy, the header readers and the command

