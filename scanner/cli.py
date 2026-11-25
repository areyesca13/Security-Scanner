"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .double_ext import BIDI_CONTROL_CHARS
from .engine import scan_record
from .hashing import DEFAULT_HASH_LIST, load_hash_list
from .scoring import Severity
from .walker import FileRecord, iter_files

SEVERITY_CHOICES = [s.name.lower() for s in Severity if s is not Severity.CLEAN]


def safe_display(path: Path | str) -> str:
    """Render a path for the terminal with hidden/control characters escaped.

    Printing a raw right-to-left override would reverse the text on screen and
    hide the very trick being reported, so show it as ``\\u202e`` instead.
    """
    return "".join(
        f"\\u{ord(ch):04x}" if ch in BIDI_CONTROL_CHARS or not ch.isprintable() else ch
        for ch in str(path)
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-scanner",
        description="Check downloaded files against rule-based indicators and flag exceptions.",
    )
    parser.add_argument("target", type=Path, help="File or directory to scan")
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Only scan the top level of the target directory",
    )
    parser.add_argument(
        "--hash-list",
        type=Path,
        default=DEFAULT_HASH_LIST,
        help="Known-bad SHA256 list (default: bundled list)",
    )
    parser.add_argument(
        "--min-severity",
        choices=SEVERITY_CHOICES,
        default="low",
        help="Only report files at or above this severity (default: low)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show every finding, full hashes, and clean files",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def print_record(record: FileRecord, verbose: bool) -> None:
    risk = record.risk
    print(f"{risk.severity.name:<9}{risk.score:>4}  {safe_display(record.path)}")
    print(f"{'':15}{risk.summary}")
    print(f"{'':15}-> {risk.action}")
    if verbose:
        print(f"{'':15}sha256 {record.sha256}")
        for finding in record.findings:
            print(f"{'':15}  [{finding.rule_id} +{finding.weight}] {finding.message}")
    print()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.target.exists():
        print(f"error: {args.target} does not exist", file=sys.stderr)
        return 2

    try:
        known_bad = load_hash_list(args.hash_list)
    except (OSError, ValueError) as exc:
        print(f"error: could not load hash list: {exc}", file=sys.stderr)
        return 2

    scanned: list[FileRecord] = []
    errors = 0
    for record in iter_files(args.target, recursive=not args.no_recursive):
        try:
            scanned.append(scan_record(record, known_bad))
        except OSError as exc:
            errors += 1
            print(f"warning: could not read {safe_display(record.path)}: {exc}", file=sys.stderr)

    # Highest risk first so reviewers start at the top.
    scanned.sort(key=lambda r: (-r.risk.score, str(r.path).lower()))

    threshold = Severity[args.min_severity.upper()]
    reported = [r for r in scanned if r.risk.severity >= threshold]
    shown = scanned if args.verbose else reported

    counts = Counter(r.risk.severity for r in scanned)
    breakdown = ", ".join(f"{counts[s]} {s.name.lower()}" for s in sorted(Severity, reverse=True))
    print(f"Scanned {len(scanned)} file(s): {breakdown}")
    if errors:
        print(f"{errors} file(s) could not be read (see warnings)")
    print()

    for record in shown:
        print_record(record, args.verbose)

    if not reported:
        print(f"Nothing at or above '{args.min_severity}' severity.")
    return 1 if reported else 0


if __name__ == "__main__":
    raise SystemExit(main())
