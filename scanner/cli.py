"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .double_ext import BIDI_CONTROL_CHARS
from .engine import scan_record
from .hashing import DEFAULT_HASH_LIST, load_hash_list
from .walker import iter_files


def safe_display(path: Path) -> str:
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
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


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

    records = list(iter_files(args.target, recursive=not args.no_recursive))
    flagged = 0
    for record in records:
        try:
            scan_record(record, known_bad)
        except OSError as exc:
            print(f"warning: could not read {safe_display(record.path)}: {exc}", file=sys.stderr)
            continue

        marker = "FLAG" if record.findings else "ok  "
        print(f"[{marker}] {record.sha256[:16]}  {safe_display(record.path)}")
        for finding in record.findings:
            print(f"         - {finding.rule_id}: {finding.message}")
        flagged += bool(record.findings)

    print(f"\n{len(records)} file(s) scanned, {flagged} flagged")
    return 1 if flagged else 0


if __name__ == "__main__":
    raise SystemExit(main())
