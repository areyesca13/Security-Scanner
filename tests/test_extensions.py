import unittest

from scanner.extensions import EXTENSION_RULES, check_extension, final_extension


def rule_ids(name):
    return [f.rule_id for f in check_extension(name)]


class FinalExtensionTests(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(final_extension("report.PDF"), "pdf")

    def test_no_extension(self):
        self.assertEqual(final_extension("Makefile"), "")

    def test_dotfile_is_not_an_extension(self):
        self.assertEqual(final_extension(".bashrc"), "")

    def test_trailing_dots_and_spaces_are_ignored(self):
        self.assertEqual(final_extension("setup.exe. . "), "exe")


class CheckExtensionTests(unittest.TestCase):
    def test_risky_types_are_flagged(self):
        for name in ["setup.exe", "run.PS1", "macro.xlsm", "disk.iso", "link.lnk", "a.zip"]:
            with self.subTest(name=name):
                self.assertEqual(rule_ids(name), ["EXT_SUSPICIOUS"])

    def test_safe_types_are_not_flagged(self):
        for name in ["report.pdf", "photo.jpg", "notes.txt", "data.csv", "README", ".gitignore"]:
            with self.subTest(name=name):
                self.assertEqual(rule_ids(name), [])

    def test_trailing_characters_add_a_finding(self):
        self.assertEqual(rule_ids("setup.exe. "), ["EXT_SUSPICIOUS", "EXT_TRAILING_CHARS"])

    def test_weight_comes_from_category(self):
        [finding] = check_extension("a.zip")
        self.assertEqual(finding.weight, 10)
        self.assertIn("archive", finding.message)

    def test_each_extension_is_in_only_one_rule(self):
        seen = {}
        for rule in EXTENSION_RULES:
            for ext in rule.extensions:
                self.assertNotIn(ext, seen, f".{ext} is in both {seen.get(ext)} and {rule.category}")
                seen[ext] = rule.category


if __name__ == "__main__":
    unittest.main()
