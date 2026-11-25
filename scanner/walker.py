"""Discover files to be scanned."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .findings import Finding
from .scoring import RiskAssessment


@dataclass
class FileRecord:
    """A single file discovered during a scan, plus anything learned about it."""

    path: Path
    size: int
    sha256: str | None = None
    findings: list[Finding] = field(default_factory=list)
    risk: RiskAssessment | None = None

    @property
    def name(self) -> str:
        return self.path.name


def iter_files(root: Path, recursive: bool = True) -> Iterator[FileRecord]:
    """Yield a FileRecord for every regular file under ``root``.

    Symlinks are skipped so a scan can't be redirected outside the target folder.
    """
    root = Path(root)
    if root.is_file():
        yield FileRecord(path=root, size=root.stat().st_size)
        return

    pattern = "**/*" if recursive else "*"
    for path in sorted(root.glob(pattern)):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        yield FileRecord(path=path, size=size)
