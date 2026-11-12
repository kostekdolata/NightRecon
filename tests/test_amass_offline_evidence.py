"""Offline Amass import contract and negative scope tests."""
import hashlib
import json
import unittest

from nightrecon_red_engine.amass_offline_evidence import AmassEvidenceError, import_amass_jsonl


def rows(*names):
    return b"\\n".join(json.dumps({"name": name, "sources": ["untrusted"]}).encode() for name in names)


class AmassOfflineEvidenceTests(unittest.TestCase):
    def test_deterministic_redacted_observations(self):
        raw = rows("A.Example.test", "a.example.test", "example.test")
        result = import_amass_jsonl(raw, approved_domain="example.test")
        self.assertEqual(result["record_count"], 3)
        self.assertEqual(result["unique_observation_count"], 2)
        self.assertEqual(result["source_report_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["authority"], "evidence_only_not_authorization")
        self.assertNotIn("a.example.test", str(result["observations"]))
        self.assertEqual(result["observations"][0]["reachability"], "not_established")

    def test_scope_and_malformed_records_fail_closed(self):
        for raw in (rows("example.test.evil.test"), rows("notexample.test"),
                    rows("evil.test"), rows("localhost"), rows("a..example.test"),
                    b'{"name": "ok.example.test"}\\nnot json', b"[]", b"", b"\\xff"):
            with self.subTest(raw=raw), self.assertRaises(AmassEvidenceError):
                import_amass_jsonl(raw, approved_domain="example.test")
        with self.assertRaises(AmassEvidenceError):
            import_amass_jsonl(rows("a.example.test"), approved_domain="example")

    def test_budget_fail_closed(self):
        raw = rows("a.example.test", "b.example.test")
        with self.assertRaises(AmassEvidenceError):
            import_amass_jsonl(raw, approved_domain="example.test", max_records=1)
        for budget in (0, True, 2001):
            with self.assertRaises(AmassEvidenceError):
                import_amass_jsonl(raw, approved_domain="example.test", max_records=budget)
        with self.assertRaises(AmassEvidenceError):
            import_amass_jsonl(b"x" * 2_000_001, approved_domain="example.test")


if __name__ == "__main__":
    unittest.main()
