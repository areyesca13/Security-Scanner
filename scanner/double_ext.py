"""Detect filenames built to disguise their real file type.

Covers three common tricks:
  * double extensions:     ``invoice.pdf.exe`` (Windows hides the ``.exe`` by default)
  * whitespace padding:    ``invoice.pdf                  .exe``
  * bidi override chars:   ``invoice‮fdp.exe`` displays as ``invoiceexe.pdf``
"""

from __future__ import annotations

import re

from .extensions import classify_extension, normalize_name
from .findings import Finding

# Extensions people trust at a glance, so attackers put them in front of the real one.
DECOY_EXTENSIONS = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "rtf", "txt", "csv",
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic",
    "mp3", "mp4", "wav", "avi", "mov", "mkv", "wmv",
    "htm", "html", "eml", "msg",
})

# Unicode characters that reorder or hide text when a filename is displayed.
BIDI_CONTROL_CHARS = {
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
    "‎": "LEFT-TO-RIGHT MARK",
    "‏": "RIGHT-TO-LEFT MARK",
}

# Three or more spaces/tabs right before the final dot.
_PADDING_RE = re.compile(r"[ \t]{3,}\.[^.]+$")

# Weight at or above which a final extension counts as "runnable" for the decoy check.
_RUNNABLE_WEIGHT = 25


def split_extensions(name: str) -> list[str]:
    """Return every extension in a filename, e.g. ``a.tar.gz`` -> ``["tar", "gz"]``."""
    # Drop a leading dot so dotfiles like ".bashrc" are treated as a stem, not an extension.
    stem, *exts = normalize_name(name).lstrip(".").split(".")
    # Strip padding so "invoice.pdf     .exe" still yields ["pdf", "exe"].
    return [ext.strip() for ext in exts if ext.strip()]


def check_double_extension(name: str) -> list[Finding]:
    findings: list[Finding] = []

    bidi = sorted({BIDI_CONTROL_CHARS[ch] for ch in name if ch in BIDI_CONTROL_CHARS})
    if bidi:
        findings.append(
            Finding(
                rule_id="NAME_BIDI_OVERRIDE",
                message=f"filename contains hidden text-direction characters ({', '.join(bidi)})"
                " that can make it display a fake extension",
                weight=60,
            )
        )

    if _PADDING_RE.search(normalize_name(name)):
        findings.append(
            Finding(
                rule_id="NAME_WHITESPACE_PADDING",
                message="run of spaces before the final extension, likely to push it out of view",
                weight=25,
            )
        )

    exts = split_extensions(name)
    if len(exts) >= 2:
        decoy, real = exts[-2], exts[-1]
        rule = classify_extension(real)
        if decoy in DECOY_EXTENSIONS and rule is not None:
            if rule.weight >= _RUNNABLE_WEIGHT:
                findings.append(
                    Finding(
                        rule_id="NAME_DOUBLE_EXTENSION",
                        message=f"looks like '.{decoy}' but is really '.{real}' ({rule.category})",
                        weight=45,
                    )
                )
            else:
                findings.append(
                    Finding(
                        rule_id="NAME_DOUBLE_EXTENSION_ARCHIVE",
                        message=f"'.{decoy}' name wrapped in a '.{real}' {rule.category}",
                        weight=15,
                    )
                )

    return findings
