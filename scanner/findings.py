"""Shared types for things the scanner flags."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    """One rule that matched a file.

    ``weight`` is how much this finding adds to the file's risk score (0-100).
    """

    rule_id: str
    message: str
    weight: int
