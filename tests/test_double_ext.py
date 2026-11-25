import unittest

from scanner.double_ext import check_double_extension, split_extensions


def rule_ids(name):
    return [f.rule_id for f in check_double_extension(name)]


class SplitExtensionsTests(unittest.TestCase):
    def test_multiple(self):
        self.assertEqual(split_extensions("a.tar.gz"), ["tar", "gz"])

    def test_padding_is_stripped(self):
        self.assertEqual(split_extensions("invoice.pdf     .exe"), ["pdf", "exe"])

    def test_dotfile(self):
        self.assertEqual(split_extensions(".bashrc"), [])


class DoubleExtensionTests(unittest.TestCase):
    def test_decoy_then_runnable_is_flagged(self):
        for name in ["invoice.pdf.exe", "Invoice.PDF.Exe", "photo.jpg.js", "resume.docx.lnk",
                     "song.mp3.scr", "movie.mp4.scr. "]:
            with self.subTest(name=name):
                self.assertEqual(rule_ids(name), ["NAME_DOUBLE_EXTENSION"])

    def test_decoy_inside_archive_is_lower_risk(self):
        [finding] = check_double_extension("report.pdf.zip")
        self.assertEqual(finding.rule_id, "NAME_DOUBLE_EXTENSION_ARCHIVE")
        self.assertLess(finding.weight, 25)

    def test_normal_names_are_not_flagged(self):
        for name in ["archive.tar.gz", "jquery.min.js", "setup-1.2.3.exe", "scan.pdf.txt",
                     "report.pdf", "notes", ".bashrc", "my.backup.exe"]:
            with self.subTest(name=name):
                self.assertEqual(rule_ids(name), [])

    def test_whitespace_padding(self):
        self.assertEqual(
            rule_ids("invoice.pdf          .exe"),
            ["NAME_WHITESPACE_PADDING", "NAME_DOUBLE_EXTENSION"],
        )

    def test_one_or_two_spaces_are_not_padding(self):
        self.assertNotIn("NAME_WHITESPACE_PADDING", rule_ids("my file .txt"))

    def test_right_to_left_override(self):
        # Displays as "invoiceexe.pdf"
        [finding] = check_double_extension("invoice\u202efdp.exe")
        self.assertEqual(finding.rule_id, "NAME_BIDI_OVERRIDE")
        self.assertIn("RIGHT-TO-LEFT OVERRIDE", finding.message)

    def test_other_bidi_characters(self):
        self.assertEqual(rule_ids("report\u2067.txt"), ["NAME_BIDI_OVERRIDE"])


if __name__ == "__main__":
    unittest.main()
