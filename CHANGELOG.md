# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

