import unittest

from scanner.findings import Finding
from scanner.scoring import Severity, assess, score_findings, severity_for, summarize


def f(rule_id, weight, message=None):
    return Finding(rule_id=rule_id, message=message or rule_id.lower(), weight=weight)


class ScoreTests(unittest.TestCase):
    def test_sums_weights(self):
        self.assertEqual(score_findings([f("A", 10), f("B", 20)]), 30)

    def test_capped_at_100(self):
        self.assertEqual(score_findings([f("A", 100), f("B", 60)]), 100)

    def test_same_rule_counts_once(self):
        self.assertEqual(score_findings([f("A", 30), f("A", 30)]), 30)

    def test_no_findings(self):
        self.assertEqual(score_findings([]), 0)


class SeverityTests(unittest.TestCase):
    def test_thresholds(self):
        cases = {0: Severity.CLEAN, 1: Severity.LOW, 24: Severity.LOW, 25: Severity.MEDIUM,
                 49: Severity.MEDIUM, 50: Severity.HIGH, 79: Severity.HIGH,
                 80: Severity.CRITICAL, 100: Severity.CRITICAL}
        for score, expected in cases.items():
            with self.subTest(score=score):
                self.assertIs(severity_for(score), expected)

    def test_severities_are_ordered(self):
        self.assertGreater(Severity.CRITICAL, Severity.HIGH)
        self.assertGreater(Severity.LOW, Severity.CLEAN)


class SummaryTests(unittest.TestCase):
    def test_strongest_reasons_first(self):
        text = summarize([f("A", 10, "weak"), f("B", 50, "strong")])
        self.assertEqual(text, "Strong; weak")

    def test_extra_reasons_are_counted(self):
        text = summarize([f("A", 10), f("B", 20), f("C", 30)])
        self.assertTrue(text.endswith("(+1 more)"))

    def test_superseded_finding_is_hidden_but_still_scored(self):
        findings = [
            f("EXT_SUSPICIOUS", 40, "risky file type '.exe'"),
            f("NAME_DOUBLE_EXTENSION", 45, "looks like '.pdf' but is really '.exe'"),
        ]
        risk = assess(findings)
        self.assertEqual(risk.summary, "Looks like '.pdf' but is really '.exe'")
        self.assertEqual(risk.score, 85)

    def test_clean(self):
        risk = assess([])
        self.assertIs(risk.severity, Severity.CLEAN)
        self.assertEqual(risk.summary, "No indicators matched.")


if __name__ == "__main__":
    unittest.main()
