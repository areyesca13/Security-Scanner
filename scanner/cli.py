"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .hashing import DEFAULT_HASH_LIST, check_hash, load_hash_list, sha256_file
from .walker import iter_files


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
            record.sha256 = sha256_file(record.path)
        except OSError as exc:
            print(f"warning: could not read {record.path}: {exc}", file=sys.stderr)
            continue
        record.findings.extend(check_hash(record.sha256, known_bad))

        marker = "FLAG" if record.findings else "ok  "
        print(f"[{marker}] {record.sha256[:16]}  {record.path}")
        for finding in record.findings:
            print(f"         - {finding.rule_id}: {finding.message}")
        flagged += bool(record.findings)

    print(f"\n{len(records)} file(s) scanned, {flagged} flagged")
    return 1 if flagged else 0


if __name__ == "__main__":
    raise SystemExit(main())
