"""Synthetic, network-free ProjectDiscovery httpx import contract tests."""
import json
import unittest

from nightrecon_red_engine.httpx_offline_jsonl_import import (
    HttpxOfflineImportError, import_httpx_jsonl,
)


def record(url="https://example.org/", status=200):
    return json.dumps({"url": url, "status_code": status,
                       "title": "SECRET: never persist", "body": "sensitive"}).encode()


class HttpxOfflineImportTests(unittest.TestCase):
    def test_deterministic_provenance_and_redaction(self):
        payload = record() + b"\n" + record("https://example.org/health", 404)
        scope = ("https://example.org/", "https://example.org/health")
        result = import_httpx_jsonl(payload, allowed_urls=scope)
        self.assertEqual(result, import_httpx_jsonl(payload, allowed_urls=scope))
        self.assertEqual(result["record_count"], 2)
        self.assertEqual(result["authority"], "untrusted_offline_import")
        self.assertEqual(len(result["sha256"]), 64)
        self.assertEqual(result["observations"][1]["status_code"], 404)
        self.assertNotIn("title", result["observations"][0])
        self.assertNotIn("body", result["observations"][0])

    def test_scope_is_exact_not_origin_or_subdomain(self):
        for url in ("https://example.org/admin", "https://evil.example.org/",
                    "http://example.org/", "https://example.org:443/",
                    "https://example.org.evil.test/", "https://example.org/#fragment",
                    "https://user:secret@example.org/"):
            with self.subTest(url=url), self.assertRaises(HttpxOfflineImportError):
                import_httpx_jsonl(record(url), allowed_urls=("https://example.org/",))

    def test_malformed_and_budget_fail_closed(self):
        for payload in (b"", b"{}", b"{", b"[]", record(status=True),
                        record(status=0), record(status=600),
                        record() + b"\n\n" + record()):
            with self.subTest(payload=payload), self.assertRaises(HttpxOfflineImportError):
                import_httpx_jsonl(payload, allowed_urls=("https://example.org/",))
        for opts in ({"allowed_urls": ()},
                     {"allowed_urls": ("https://example.org/",), "max_bytes": 1},
                     {"allowed_urls": ("https://example.org/",), "max_records": 0},
                     {"allowed_urls": ("https://example.org/", "https://example.org/")}):
            with self.subTest(opts=opts), self.assertRaises(HttpxOfflineImportError):
                import_httpx_jsonl(record(), **opts)
        with self.assertRaises(HttpxOfflineImportError):
            import_httpx_jsonl(record() + b"\n" + record(),
                              allowed_urls=("https://example.org/",), max_records=1)


if __name__ == "__main__":
    unittest.main()
