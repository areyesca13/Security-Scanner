import hashlib
import tempfile
import unittest
from pathlib import Path

from scanner import hashing
from scanner.hashing import check_hash, load_hash_list, sha256_file


class Sha256FileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_matches_hashlib(self):
        path = self.dir / "sample.bin"
        path.write_bytes(b"hello world")
        self.assertEqual(sha256_file(path), hashlib.sha256(b"hello world").hexdigest())

    def test_empty_file(self):
        path = self.dir / "empty"
        path.touch()
        self.assertEqual(sha256_file(path), hashlib.sha256(b"").hexdigest())

    def test_file_larger_than_one_chunk(self):
        data = b"x" * (hashing.CHUNK_SIZE * 2 + 123)
        path = self.dir / "big.bin"
        path.write_bytes(data)
        self.assertEqual(sha256_file(path), hashlib.sha256(data).hexdigest())


class HashListTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.list_path = Path(self.tmp.name) / "hashes.txt"

    def tearDown(self):
        self.tmp.cleanup()

    def test_parses_comments_blanks_and_labels(self):
        good = "a" * 64
        self.list_path.write_text(f"# header\n\n{good.upper()} Some-Malware\n{'b' * 64}\n")
        hashes = load_hash_list(self.list_path)
        self.assertEqual(hashes, {good: "Some-Malware", "b" * 64: "known-bad"})

    def test_rejects_invalid_hash(self):
        self.list_path.write_text("not-a-hash label\n")
        with self.assertRaisesRegex(ValueError, ":1:"):
            load_hash_list(self.list_path)

    def test_bundled_list_loads(self):
        self.assertTrue(load_hash_list(hashing.DEFAULT_HASH_LIST))


class CheckHashTests(unittest.TestCase):
    def test_match_is_flagged_with_max_weight(self):
        [finding] = check_hash("a" * 64, {"a" * 64: "Test"})
        self.assertEqual(finding.rule_id, "HASH_KNOWN_BAD")
        self.assertEqual(finding.weight, 100)
        self.assertIn("Test", finding.message)

    def test_no_match(self):
        self.assertEqual(check_hash("c" * 64, {"a" * 64: "Test"}), [])


if __name__ == "__main__":
    unittest.main()
