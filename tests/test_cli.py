"""End-to-end tests: real files on disk through the CLI and report writers."""

import contextlib
import csv
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scanner.cli import main, safe_display
from scanner.reports import csv_safe


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.target = self.root / "downloads"
        self.target.mkdir()
        for name in ["invoice.pdf.exe", "budget.xlsm", "notes.txt"]:
            (self.target / name).touch()
        (self.target / "sub").mkdir()
        (self.target / "sub" / "payload.dat").write_bytes(b"pretend malware")

        digest = hashlib.sha256(b"pretend malware").hexdigest()
        self.hash_list = self.root / "hashes.txt"
        self.hash_list.write_text(f"{digest} Test-Sample\n")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([str(self.target), "--hash-list", str(self.hash_list), *args])
        return code, out.getvalue(), err.getvalue()

    def test_flags_and_orders_by_risk(self):
        code, out, _ = self.run_cli()
        self.assertEqual(code, 1)
        self.assertIn("Scanned 4 file(s): 2 critical, 0 high, 1 medium, 0 low, 1 clean", out)
        order = [out.index(n) for n in ["payload.dat", "invoice.pdf.exe", "budget.xlsm"]]
        self.assertEqual(order, sorted(order))
        self.assertNotIn("notes.txt", out)

    def test_verbose_shows_clean_files(self):
        _, out, _ = self.run_cli("-v")
        self.assertIn("notes.txt", out)
        self.assertIn("[NAME_DOUBLE_EXTENSION +45]", out)

    def test_min_severity_filters_and_sets_exit_code(self):
        code, out, _ = self.run_cli("--min-severity", "critical")
        self.assertEqual(code, 1)
        self.assertNotIn("budget.xlsm", out)

        (self.target / "invoice.pdf.exe").unlink()
        (self.target / "sub" / "payload.dat").unlink()
        code, out, _ = self.run_cli("--min-severity", "high")
        self.assertEqual(code, 0)
        self.assertIn("Nothing at or above 'high' severity.", out)

    def test_no_recursive(self):
        _, out, _ = self.run_cli("--no-recursive")
        self.assertIn("Scanned 3 file(s)", out)

    def test_missing_target(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.root / "nope")]), 2)

    def test_json_report(self):
        out_path = self.root / "reports" / "scan.json"
        self.run_cli("--json", str(out_path))
        report = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(report["totals"]["files"], 4)
        self.assertEqual(report["totals"]["critical"], 2)
        top = report["files"][0]
        self.assertEqual(top["name"], "payload.dat")
        self.assertEqual(top["severity"], "CRITICAL")
        self.assertEqual(top["findings"][0]["rule_id"], "HASH_KNOWN_BAD")

    def test_csv_report(self):
        out_path = self.root / "scan.csv"
        self.run_cli("--csv", str(out_path))
        with open(out_path, encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 4)
        by_name = {row["name"]: row for row in rows}
        self.assertEqual(by_name["invoice.pdf.exe"]["rules"], "EXT_SUSPICIOUS;NAME_DOUBLE_EXTENSION")
        self.assertEqual(by_name["notes.txt"]["severity"], "CLEAN")


class SafetyTests(unittest.TestCase):
    def test_bidi_is_escaped_for_display(self):
        self.assertEqual(safe_display("invoice\u202efdp.exe"), "invoice\\u202efdp.exe")

    def test_csv_formula_injection_is_neutralized(self):
        self.assertEqual(csv_safe("=HYPERLINK(\"x\").exe"), "'=HYPERLINK(\"x\").exe")
        self.assertEqual(csv_safe("-cmd.exe"), "'-cmd.exe")
        self.assertEqual(csv_safe("normal.exe"), "normal.exe")
        self.assertEqual(csv_safe(42), 42)

    def test_csv_escapes_hidden_characters(self):
        self.assertEqual(csv_safe("invoice\u202efdp.exe"), "invoice\\u202efdp.exe")


if __name__ == "__main__":
    unittest.main()
