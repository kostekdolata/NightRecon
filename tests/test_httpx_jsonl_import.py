import hashlib
import json
import unittest

from nightrecon_red_engine.httpx_jsonl_import import HttpxEvidenceError, import_httpx_jsonl


def payload(*records):
    return b"\n".join(json.dumps(item).encode("utf-8") for item in records)


def imported(data, **kwargs):
    return import_httpx_jsonl(
        data, source_name="httpx.jsonl", allowed_hosts=("example.org", "192.0.2.1"),
        **kwargs,
    )


class TestHttpxJsonlImport(unittest.TestCase):
    def test_valid_offline_evidence_and_digest(self):
        data = payload(
            {"url": "https://EXAMPLE.org:443/path?q=1", "status_code": 200,
             "title": "Welcome", "tech": ["nginx"]},
            {"url": "http://192.0.2.1/", "status_code": 404},
        )
        result = imported(data)
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["record_count"], 2)
        self.assertEqual(result["authority"], "untrusted_offline_import")
        self.assertEqual(result["observations"][0]["host"], "example.org")
        self.assertEqual(result["observations"][0]["technologies"], ["nginx"])
        self.assertEqual(
            result["observations"][0]["classification"], "unverified_tool_observation"
        )

    def test_exact_scope_and_scheme_restrictions(self):
        for url in (
            "https://badexample.org/", "https://sub.example.org/",
            "https://example.org.attacker.test/", "https://user@example.org/",
            "file:///etc/passwd", "https://example.org:99999/",
            "https://example.org:0/", "https://[::1]/",
        ):
            with self.subTest(url=url), self.assertRaises(HttpxEvidenceError):
                imported(payload({"url": url}))
        with self.assertRaises(HttpxEvidenceError):
            import_httpx_jsonl(payload({"url": "https://example.org/"}),
                               source_name="fixture", allowed_hosts=())

    def test_malformed_and_budget_fail_closed(self):
        cases = (
            b"", b"{", b"[]", b"\xff", b"\n",
            payload({"url": "https://example.org/", "status_code": True}),
            payload({"url": "https://example.org/", "status_code": 700}),
            payload({"url": "https://example.org/", "tech": "nginx"}),
            payload({"url": "https://example.org/", "title": 10}),
            payload({"url": "https://example.org/", "tech": ["x"] * 101}),
        )
        for data in cases:
            with self.subTest(data=data[:80]), self.assertRaises(HttpxEvidenceError):
                imported(data)
        data = payload({"url": "https://example.org/"}, {"url": "http://192.0.2.1/"})
        with self.assertRaises(HttpxEvidenceError):
            imported(data, max_records=1)
        with self.assertRaises(HttpxEvidenceError):
            imported(data, max_bytes=4)


if __name__ == "__main__":
    unittest.main()
