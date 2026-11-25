"""Turn a file's findings into a risk score, severity and short summary."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from .findings import Finding


class Severity(IntEnum):
    CLEAN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# (minimum score, severity), checked top-down.
SEVERITY_THRESHOLDS: tuple[tuple[int, Severity], ...] = (
    (80, Severity.CRITICAL),
    (50, Severity.HIGH),
    (25, Severity.MEDIUM),
    (1, Severity.LOW),
)

RECOMMENDED_ACTIONS: dict[Severity, str] = {
    Severity.CRITICAL: "Quarantine now. Do not open.",
    Severity.HIGH: "Review before opening; verify the sender and the file's purpose.",
    Severity.MEDIUM: "Confirm the source is expected before use.",
    Severity.LOW: "Low priority; spot-check if time allows.",
    Severity.CLEAN: "No action needed.",
}

MAX_SCORE = 100
MAX_REASONS_IN_SUMMARY = 2

# Findings whose message already says what another rule says. Both still count
# toward the score; only the more specific one is shown in the summary.
SUMMARY_SUPERSEDES: dict[str, frozenset[str]] = {
    "NAME_DOUBLE_EXTENSION": frozenset({"EXT_SUSPICIOUS"}),
    "NAME_DOUBLE_EXTENSION_ARCHIVE": frozenset({"EXT_SUSPICIOUS"}),
}


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    severity: Severity
    summary: str
    action: str


def score_findings(findings: list[Finding]) -> int:
    """Add up finding weights, capped at MAX_SCORE.

    Each rule counts once, so a rule can't inflate the score by firing twice.
    """
    by_rule: dict[str, int] = {}
    for finding in findings:
        by_rule[finding.rule_id] = max(by_rule.get(finding.rule_id, 0), finding.weight)
    return min(MAX_SCORE, sum(by_rule.values()))


def severity_for(score: int) -> Severity:
    for threshold, severity in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return Severity.CLEAN


def summarize(findings: list[Finding]) -> str:
    """One line naming the strongest reasons, e.g. ``"a; b (+1 more)"``."""
    if not findings:
        return "No indicators matched."
    present = {f.rule_id for f in findings}
    hidden = set().union(*(SUMMARY_SUPERSEDES.get(rule, ()) for rule in present))
    ranked = sorted(
        (f for f in findings if f.rule_id not in hidden),
        key=lambda f: f.weight,
        reverse=True,
    )
    reasons = [f.message for f in ranked[:MAX_REASONS_IN_SUMMARY]]
    extra = len(ranked) - len(reasons)
    text = "; ".join(reasons)
    if extra:
        text += f" (+{extra} more)"
    return text[0].upper() + text[1:]


def assess(findings: list[Finding]) -> RiskAssessment:
    score = score_findings(findings)
    severity = severity_for(score)
    return RiskAssessment(
        score=score,
        severity=severity,
        summary=summarize(findings),
        action=RECOMMENDED_ACTIONS[severity],
    )
