"""Offline httpx evidence importer scope and provenance regression tests."""
import hashlib
import json
import unittest

from nightrecon_red_engine.httpx_offline_evidence import (
    HttpxEvidenceError, import_httpx_jsonl,
)


def rows(*items):
    return b"\n".join(json.dumps({"url": url, "status_code": status}).encode()
                      for url, status in items)


class HttpxOfflineEvidenceTests(unittest.TestCase):
    def test_redacted_deterministic_evidence(self):
        raw = rows(("https://a.example.test", 200),
                   ("https://a.example.test/", 200),
                   ("https://a.example.test", 404))
        result = import_httpx_jsonl(raw, approved_origins=("https://a.example.test",))
        self.assertEqual(result["record_count"], 3)
        self.assertEqual(result["unique_observation_count"], 2)
        self.assertEqual(result["source_report_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["authority"], "evidence_only_not_authorization")
        self.assertNotIn("a.example.test", str(result["observations"]))

    def test_exact_scope_and_untrusted_records_fail_closed(self):
        invalid = [
            rows(("https://a.example.test.evil.test", 200)),
            rows(("http://a.example.test", 200)),
            rows(("https://b.example.test", 200)),
            rows(("https://a.example.test:8443", 200)),
            rows(("https://a.example.test/path", 200)),
            rows(("https://a.example.test/?secret=1", 200)),
            rows(("https://user:pass@a.example.test", 200)),
            rows(("https://a.example.test", True)),
            rows(("https://a.example.test", 999)),
            b'{"url":"https://a.example.test","status_code":200}\nnot-json',
            b"[]", b"", b"\xff",
        ]
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(HttpxEvidenceError):
                import_httpx_jsonl(raw, approved_origins=("https://a.example.test",))

    def test_scope_and_budget_validation(self):
        raw = rows(("https://a.example.test", 200), ("https://a.example.test", 201))
        for scope in ((), ("https://a.example.test/path",), ("https://evil.test",)):
            with self.subTest(scope=scope), self.assertRaises(HttpxEvidenceError):
                import_httpx_jsonl(raw, approved_origins=scope)
        for budget in (0, True, 2001, 1):
            with self.subTest(budget=budget), self.assertRaises(HttpxEvidenceError):
                import_httpx_jsonl(raw, approved_origins=("https://a.example.test",),
                                  max_records=budget)
        with self.assertRaises(HttpxEvidenceError):
            import_httpx_jsonl(b"x" * 2_000_001,
                              approved_origins=("https://a.example.test",))


if __name__ == "__main__":
    unittest.main()
