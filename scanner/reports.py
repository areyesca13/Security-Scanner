"""Write scan results to JSON or CSV for tracking and hand-off."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .double_ext import escape_hidden
from .scoring import Severity
from .walker import FileRecord

CSV_COLUMNS = ("severity", "score", "path", "name", "size", "sha256", "summary", "action", "rules")

# A cell starting with one of these is treated as a formula by Excel/Sheets.
# Filenames are attacker-controlled, so "=HYPERLINK(...).exe" must not execute.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def record_to_dict(record: FileRecord) -> dict:
    risk = record.risk
    return {
        "path": str(record.path),
        "name": record.name,
        "size": record.size,
        "sha256": record.sha256,
        "severity": risk.severity.name,
        "score": risk.score,
        "summary": risk.summary,
        "action": risk.action,
        "findings": [
            {"rule_id": f.rule_id, "message": f.message, "weight": f.weight}
            for f in record.findings
        ],
    }


def build_report(records: list[FileRecord], target: Path) -> dict:
    counts = Counter(r.risk.severity for r in records)
    return {
        "scanner_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": str(target),
        "totals": {
            "files": len(records),
            **{s.name.lower(): counts[s] for s in sorted(Severity, reverse=True)},
        },
        "files": [record_to_dict(r) for r in records],
    }


def write_json(records: list[FileRecord], target: Path, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as handle:
        # ensure_ascii keeps hidden characters like U+202E visible as \u202e.
        json.dump(build_report(records, target), handle, indent=2, ensure_ascii=True)
        handle.write("\n")


def csv_safe(value: object) -> object:
    """Make a text cell safe to open in a spreadsheet.

    Escapes hidden direction characters (so names can't display reversed) and
    neutralizes formula injection.
    """
    if not isinstance(value, str):
        return value
    value = escape_hidden(value)
    if value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def write_csv(records: list[FileRecord], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # utf-8-sig so Excel detects the encoding and non-ASCII names display correctly.
    with open(out_path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for record in records:
            row = record_to_dict(record)
            row["rules"] = ";".join(f["rule_id"] for f in row.pop("findings"))
            writer.writerow({k: csv_safe(row[k]) for k in CSV_COLUMNS})
