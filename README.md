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
```
