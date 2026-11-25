"""Rule-based checks on a file's extension."""

from __future__ import annotations

from dataclasses import dataclass

from .findings import Finding


@dataclass(frozen=True)
class ExtensionRule:
    category: str
    weight: int
    extensions: frozenset[str]


# Ordered highest risk first. Each extension should appear in exactly one rule.
EXTENSION_RULES: tuple[ExtensionRule, ...] = (
    ExtensionRule(
        category="executable",
        weight=40,
        extensions=frozenset({
            "exe", "scr", "com", "pif", "cpl", "msi", "msp", "dll", "sys",
            "app", "elf", "bin", "run",
        }),
    ),
    ExtensionRule(
        category="script",
        weight=40,
        extensions=frozenset({
            "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf",
            "wsh", "hta", "sh", "py", "jar",
        }),
    ),
    ExtensionRule(
        category="shortcut-or-config",
        weight=35,
        extensions=frozenset({"lnk", "url", "scf", "reg", "inf", "library-ms", "settingcontent-ms"}),
    ),
    ExtensionRule(
        category="macro-enabled-document",
        weight=30,
        extensions=frozenset({"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm"}),
    ),
    ExtensionRule(
        category="disk-image",
        weight=25,
        extensions=frozenset({"iso", "img", "vhd", "vhdx"}),
    ),
    ExtensionRule(
        category="archive",
        weight=10,
        extensions=frozenset({"zip", "rar", "7z", "cab", "gz", "tar", "tgz", "ace", "arj"}),
    ),
)

_LOOKUP: dict[str, ExtensionRule] = {
    ext: rule for rule in EXTENSION_RULES for ext in rule.extensions
}


def normalize_name(name: str) -> str:
    """Lower-case a filename and strip the trailing dots and spaces Windows ignores.

    ``"Setup.EXE. "`` runs as ``setup.exe`` on Windows, so it should be judged as one.
    """
    return name.rstrip(" .").lower()


def final_extension(name: str) -> str:
    """Return the last extension of a filename (without the dot), or ``""``."""
    name = normalize_name(name)
    stem, dot, ext = name.rpartition(".")
    if not dot or not stem:  # no dot, or a dotfile like ".bashrc"
        return ""
    return ext


def classify_extension(ext: str) -> ExtensionRule | None:
    return _LOOKUP.get(ext.lower())


def check_extension(name: str) -> list[Finding]:
    """Flag files whose final extension falls into a risky category."""
    ext = final_extension(name)
    rule = classify_extension(ext)
    if rule is None:
        return []
    findings = [
        Finding(
            rule_id="EXT_SUSPICIOUS",
            message=f"risky file type '.{ext}' ({rule.category})",
            weight=rule.weight,
        )
    ]
    if normalize_name(name) != name.lower():
        findings.append(
            Finding(
                rule_id="EXT_TRAILING_CHARS",
                message="filename ends in dots or spaces, which Windows silently drops",
                weight=15,
            )
        )
    return findings
