# Security-Scanner

![tests](../../actions/workflows/tests.yml/badge.svg)

A Python utility that automates a manual review step. It checks downloaded files against rule-based indicators, flags the exceptions, and generates short risk summaries so reviewers can deal with the riskiest files first.

**What it checks**
- **SHA256 hash matching** against a known-bad hash list
- **Suspicious extensions**: executables, scripts, shortcuts, macro-enabled documents, disk images, archives
- **Misleading filenames**: double extensions (`invoice.pdf.exe`), whitespace padding, hidden Unicode text-direction characters
- **Risk scoring**: a 0–100 score, a severity level, a one-line summary and a recommended action for every file
- **Reports**: JSON and CSV output for audit trails, spreadsheets or ticket imports

It does not open or execute any file it scans. It only reads bytes to compute hashes.

## Requirements

- Python 3.10+
- No third-party dependencies

## Install

```bash
git clone https://github.com/areyesca13/Security-Scanner.git
cd Security-Scanner
pip install .              # optional: adds a `security-scanner` command
```

You can also skip installing and run it in place with `python -m scanner`.

## Usage

```bash
python -m scanner ~/Downloads
python -m scanner ~/Downloads --min-severity high            # only high and critical
python -m scanner ~/Downloads -v                             # every finding, full hashes, clean files
python -m scanner ~/Downloads --json reports/scan.json --csv reports/scan.csv
python -m scanner ~/Downloads --hash-list my_hashes.txt      # your own threat intel
python -m scanner ~/Downloads --no-recursive                 # top level only
```

Example output, sorted highest risk first:

```
Scanned 10 file(s): 5 critical, 0 high, 3 medium, 0 low, 2 clean

CRITICAL  100  Downloads\payload.bin
               SHA256 matches known-bad hash (Test-Sample); risky file type '.bin' (executable)
               -> Quarantine now. Do not open.

CRITICAL   85  Downloads\invoice.pdf.exe
               Looks like '.pdf' but is really '.exe' (executable)
               -> Quarantine now. Do not open.

MEDIUM     30  Downloads\budget.xlsm
               Risky file type '.xlsm' (macro-enabled-document)
               -> Confirm the source is expected before use.
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing at or above `--min-severity` |
| `1` | At least one file flagged at or above `--min-severity` |
| `2` | Usage or input error, such as a missing target, a bad hash list or an unwritable report path |

Because of these codes, the scanner can gate a script or CI step, for example `python -m scanner incoming/ --min-severity high || exit 1`.

## Checks

### SHA256 hash matching

Every file is hashed with SHA256, reading 1 MiB at a time so large files stay out of memory. The hash is compared against a known-bad list. The bundled list is [scanner/data/known_bad_hashes.txt](scanner/data/known_bad_hashes.txt), and you can pass your own with `--hash-list`.

```
# comments are allowed
<sha256> <label>
```

A match scores 100 (CRITICAL). The bundled list includes the hash of the harmless [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/), so you can check that detection works.

### Suspicious extensions

The final extension is matched case-insensitively. Rules are defined in [scanner/extensions.py](scanner/extensions.py).

| Category | Weight | Examples |
|---|---|---|
| executable | 40 | `.exe` `.scr` `.com` `.pif` `.msi` `.dll` |
| script | 40 | `.bat` `.ps1` `.vbs` `.js` `.hta` `.jar` |
| shortcut-or-config | 35 | `.lnk` `.url` `.reg` `.inf` |
| macro-enabled-document | 30 | `.docm` `.xlsm` `.pptm` |
| disk-image | 25 | `.iso` `.img` `.vhd` |
| archive | 10 | `.zip` `.rar` `.7z` |

Windows silently drops trailing dots and spaces from filenames, so a file named `setup.exe. ` runs as `setup.exe`. The scanner treats it as `.exe` and also flags it with `EXT_TRAILING_CHARS` (+15).

### Misleading filenames

Rules are defined in [scanner/double_ext.py](scanner/double_ext.py).

| Rule | Weight | Example | Why it matters |
|---|---|---|---|
| `NAME_BIDI_OVERRIDE` | 60 | `invoice` + U+202E + `fdp.exe` | Displays as `invoiceexe.pdf` |
| `NAME_DOUBLE_EXTENSION` | 45 | `invoice.pdf.exe` | Windows hides known extensions, so it shows as `invoice.pdf` |
| `NAME_WHITESPACE_PADDING` | 25 | `invoice.pdf          .exe` | Pushes the real extension out of view |
| `NAME_DOUBLE_EXTENSION_ARCHIVE` | 15 | `report.pdf.zip` | Lower risk on its own, but often wraps a payload |

A double extension is flagged only when the second-to-last extension is a commonly trusted type (document, image, media or web page) and the final one is risky. Normal names like `archive.tar.gz`, `jquery.min.js` and `setup-1.2.3.exe` are not flagged by this rule.

## Risk scoring

A file's score is the sum of its finding weights, capped at 100. Each rule counts once.

| Severity | Score | Recommended action |
|---|---|---|
| CRITICAL | 80–100 | Quarantine now. Do not open. |
| HIGH | 50–79 | Review before opening; verify the sender and the file's purpose. |
| MEDIUM | 25–49 | Confirm the source is expected before use. |
| LOW | 1–24 | Low priority; spot-check if time allows. |
| CLEAN | 0 | No action needed. |

For example, `invoice.pdf.exe` scores 40 for the `.exe` extension plus 45 for the double extension, for 85 (CRITICAL).

The one-line summary lists the two strongest reasons. When one finding already covers another, the summary shows only the more specific one, while the score still counts both. Run with `-v` to see every finding with its weight.

Thresholds, weights and actions are defined in [scanner/scoring.py](scanner/scoring.py).

## Reports

- **`--json PATH`** writes the scanner version, a timestamp, totals by severity, and every file with its hash, score, summary and full findings.
- **`--csv PATH`** writes one row per file with the columns `severity, score, path, name, size, sha256, summary, action, rules`. The file is encoded as UTF-8 with a BOM so Excel opens it correctly.

Both reports include every scanned file, clean ones included, and are sorted highest risk first. `--min-severity` only filters the terminal output.

## Hardening

Filenames come from whoever sent the file, so the scanner treats them as hostile input:

- **Terminal output:** hidden characters are printed as escape codes like `\u202e`, so the output itself can't be visually spoofed.
- **JSON and CSV output:** hidden characters are escaped as `\u` sequences, so a name can't display reversed in a viewer or in Excel.
- **CSV formula injection:** cells starting with `=`, `+`, `-` or `@` are prefixed with `'`, so a file named `=HYPERLINK(...).exe` can't run as a formula in Excel.
- **Symlinks** are skipped, so a scan can't be pointed outside the target folder.

## Development

```bash
python -m unittest discover -s tests -t . -v
```

The tests run on GitHub Actions for Windows and Linux on every push ([.github/workflows/tests.yml](.github/workflows/tests.yml)).

```
scanner/
  cli.py          command line and terminal output
  engine.py       runs every check on a file
  walker.py       file discovery and the FileRecord type
  hashing.py      SHA256 hashing and the known-bad list
  extensions.py   suspicious extension rules
  double_ext.py   misleading filename rules
  scoring.py      score, severity, summary, action
  reports.py      JSON and CSV writers
  findings.py     the Finding type shared by all checks
  data/known_bad_hashes.txt
tests/            unit and end-to-end tests
```

### Adding a rule

1. Write a `check_*(...) -> list[Finding]` function and give each finding a `rule_id`, a message and a weight.
2. Call it from `scan_record` in [scanner/engine.py](scanner/engine.py).
3. Add tests and a row to the tables above.

## Limitations

This is a triage aid, not an antivirus. It goes by names and known hashes, not file contents. A renamed executable such as `photo.jpg`, or malware whose hash isn't on your list, will not be flagged. Use it to decide which files a person reviews first, not as proof that a file is safe.

## License

[MIT](LICENSE)
