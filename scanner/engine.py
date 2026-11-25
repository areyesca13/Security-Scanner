"""Runs every check against a file record."""

from __future__ import annotations

from .double_ext import check_double_extension
from .extensions import check_extension
from .hashing import check_hash, sha256_file
from .scoring import assess
from .walker import FileRecord


def scan_record(record: FileRecord, known_bad: dict[str, str]) -> FileRecord:
    """Hash the file, apply all rule checks, and score the result.

    Fills in ``record.sha256``, ``record.findings`` and ``record.risk``.
    Raises OSError if the file can't be read.
    """
    record.sha256 = sha256_file(record.path)
    record.findings.extend(check_hash(record.sha256, known_bad))
    record.findings.extend(check_extension(record.name))
    record.findings.extend(check_double_extension(record.name))
    record.risk = assess(record.findings)
    return record
