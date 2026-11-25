# Security-Scanner

A Python utility that automates a manual review step: it checks downloaded files against rule-based indicators and flags anything that needs a closer look.

> Work in progress. Planned checks: SHA256 hash matching, suspicious extensions, misleading double extensions, and risk summaries.

## Requirements

- Python 3.10+
- No third-party dependencies

## Usage

```bash
python -m scanner <file-or-directory>
python -m scanner ~/Downloads --no-recursive
python -m scanner ~/Downloads --hash-list my_hashes.txt
```

Exit codes: `0` nothing flagged, `1` at least one file flagged, `2` usage or input error.

## Checks

### SHA256 hash matching

Every file is hashed with SHA256, reading 1 MiB at a time so large files stay out of memory. The hash is then compared against a known-bad list. The bundled list is [scanner/data/known_bad_hashes.txt](scanner/data/known_bad_hashes.txt), and you can pass your own with `--hash-list`. List format, one entry per line:

```
# comments are allowed
<sha256> <label>
```
