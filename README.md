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
python -m scanner ~/Downloads --min-severity high   # only high and critical
python -m scanner ~/Downloads -v                    # every finding, full hashes, clean files
```

Example output, sorted highest risk first:

```
Scanned 10 file(s): 5 critical, 0 high, 3 medium, 0 low, 2 clean

CRITICAL   85  Downloads\invoice.pdf.exe
               Looks like '.pdf' but is really '.exe' (executable)
               -> Quarantine now. Do not open.

MEDIUM     30  Downloads\budget.xlsm
               Risky file type '.xlsm' (macro-enabled-document)
               -> Confirm the source is expected before use.
```

Exit codes: `0` nothing flagged, `1` at least one file flagged, `2` usage or input error.

## Checks

### SHA256 hash matching

Every file is hashed with SHA256, reading 1 MiB at a time so large files stay out of memory. The hash is then compared against a known-bad list. The bundled list is [scanner/data/known_bad_hashes.txt](scanner/data/known_bad_hashes.txt), and you can pass your own with `--hash-list`. List format, one entry per line:

```
# comments are allowed
<sha256> <label>
```

### Suspicious extensions

The file's final extension is matched case-insensitively against the categories below. The rules live in [scanner/extensions.py](scanner/extensions.py).

| Category | Weight | Examples |
|---|---|---|
| executable | 40 | `.exe` `.scr` `.com` `.pif` `.msi` `.dll` |
| script | 40 | `.bat` `.ps1` `.vbs` `.js` `.hta` `.jar` |
| shortcut-or-config | 35 | `.lnk` `.url` `.reg` `.inf` |
| macro-enabled-document | 30 | `.docm` `.xlsm` `.pptm` |
| disk-image | 25 | `.iso` `.img` `.vhd` |
| archive | 10 | `.zip` `.rar` `.7z` |

Windows silently drops trailing dots and spaces from filenames, so a file named `setup.exe. ` runs as `setup.exe`. The scanner treats it as `.exe` and also flags it with `EXT_TRAILING_CHARS`.

### Misleading names

Rules live in [scanner/double_ext.py](scanner/double_ext.py).

| Rule | Weight | Example | Why it matters |
|---|---|---|---|
| `NAME_BIDI_OVERRIDE` | 60 | `invoice‮fdp.exe` | Displays as `invoiceexe.pdf` |
| `NAME_DOUBLE_EXTENSION` | 45 | `invoice.pdf.exe` | Windows hides known extensions, so it shows as `invoice.pdf` |
| `NAME_WHITESPACE_PADDING` | 25 | `invoice.pdf         .exe` | Pushes the real extension out of view |
| `NAME_DOUBLE_EXTENSION_ARCHIVE` | 15 | `report.pdf.zip` | Lower risk on its own, but often wraps a payload |

A double extension is flagged only when the second-to-last extension is a commonly trusted type (document, image, media or web page) and the final one is risky. Normal names like `archive.tar.gz`, `jquery.min.js` and `setup-1.2.3.exe` are not flagged by this rule.

Hidden characters in filenames are printed as escape codes, such as `‮`, so the terminal output can't be visually spoofed.

## Risk scoring

A file's score is the sum of its finding weights, capped at 100. Each rule counts once. The score sets the severity, and each severity comes with a recommended action:

| Severity | Score | Action |
|---|---|---|
| CRITICAL | 80–100 | Quarantine now. Do not open. |
| HIGH | 50–79 | Review before opening; verify the sender and the file's purpose. |
| MEDIUM | 25–49 | Confirm the source is expected before use. |
| LOW | 1–24 | Low priority; spot-check if time allows. |
| CLEAN | 0 | No action needed. |

For example, `invoice.pdf.exe` scores 40 for its `.exe` extension plus 45 for the double extension, for 85 (CRITICAL). A known-bad hash match alone scores 100.

Each flagged file gets a one-line summary of its strongest reasons, so a reviewer can triage without reading every finding. When one finding already covers another, the summary shows only the more specific one, while the score still counts both. Run with `-v` to see every finding and its weight.

Thresholds, weights and actions are defined in [scanner/scoring.py](scanner/scoring.py).
