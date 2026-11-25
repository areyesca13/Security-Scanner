"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
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
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.target.exists():
        print(f"error: {args.target} does not exist", file=sys.stderr)
        return 2

    records = list(iter_files(args.target, recursive=not args.no_recursive))
    for record in records:
        print(f"{record.size:>12,}  {record.path}")
    print(f"\n{len(records)} file(s) found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
