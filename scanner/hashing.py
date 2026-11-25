"""SHA256 hashing and known-bad hash lookups."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .findings import Finding

CHUNK_SIZE = 1024 * 1024  # 1 MiB, so large downloads don't get loaded into memory
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

DEFAULT_HASH_LIST = Path(__file__).parent / "data" / "known_bad_hashes.txt"


def sha256_file(path: Path) -> str:
    """Return the hex SHA256 digest of a file, reading it in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_hash_list(path: Path) -> dict[str, str]:
    """Load a known-bad hash list.

    One entry per line: ``<sha256> [label]``. Blank lines and lines starting
    with ``#`` are ignored. Returns a mapping of hash -> label.
    """
    hashes: dict[str, str] = {}
    with open(path, encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            digest, _, label = line.partition(" ")
            digest = digest.lower()
            if not _SHA256_RE.match(digest):
                raise ValueError(f"{path}:{line_no}: not a valid SHA256 hash: {digest!r}")
            hashes[digest] = label.strip() or "known-bad"
    return hashes


def check_hash(digest: str, known_bad: dict[str, str]) -> list[Finding]:
    """Flag a file whose hash appears in the known-bad list."""
    label = known_bad.get(digest)
    if label is None:
        return []
    return [
        Finding(
            rule_id="HASH_KNOWN_BAD",
            message=f"SHA256 matches known-bad hash ({label})",
            weight=100,
        )
    ]
