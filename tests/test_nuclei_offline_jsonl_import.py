import json
import unittest

from nightrecon_red_engine.nuclei_offline_jsonl_import import (
    NucleiOfflineImportError, import_nuclei_jsonl,
)


def record(url="https://example.org/login", severity="high"):
    return json.dumps({"template-id": "sample-check", "matched-at": url,
                       "info": {"severity": severity}}).encode()


class NucleiOfflineImportTests(unittest.TestCase):
    def test_offline_evidence_is_deterministic_and_not_a_verdict(self):
        payload = record() + b"\\n" + record("https://example.org/other", "info")
        result = import_nuclei_jsonl(payload, allowed_hosts=("example.org",))
        self.assertEqual(result, import_nuclei_jsonl(payload, allowed_hosts=("example.org",)))
        self.assertEqual(result["record_count"], 2)
        self.assertEqual(result["observations"][0]["classification"], "unverified_tool_observation")
        self.assertEqual(result["observations"][0]["reported_severity"], "high")
        self.assertEqual(len(result["sha256"]), 64)
        self.assertEqual(result["authority"], "untrusted_offline_import")

    def test_exact_scope_rejects_subdomain_and_lookalike(self):
        for url in ("https://sub.example.org/", "https://badexample.org/",
                    "https://example.org.evil.test/", "https://example.org@evil.test/"):
            with self.subTest(url=url), self.assertRaises(NucleiOfflineImportError):
                import_nuclei_jsonl(record(url), allowed_hosts=("example.org",))

    def test_malformed_url_and_json_fail_closed(self):
        for payload in (b"{}", b"{", b"[]", record("file:///etc/passwd"),
                        record("https://example.org/#fragment"), record("https://example.org:99999/"),
                        record(severity="confirmed_exploitable")):
            with self.subTest(payload=payload), self.assertRaises(NucleiOfflineImportError):
                import_nuclei_jsonl(payload, allowed_hosts=("example.org",))

    def test_budgets_and_scope_are_mandatory(self):
        for options in ({"allowed_hosts": ()},
                        {"allowed_hosts": ("example.org",), "max_records": 0},
                        {"allowed_hosts": ("example.org",), "max_bytes": 1}):
            with self.subTest(options=options), self.assertRaises(NucleiOfflineImportError):
                import_nuclei_jsonl(record(), **options)
        with self.assertRaises(NucleiOfflineImportError):
            import_nuclei_jsonl(record() + b"\\n" + record(),
                                allowed_hosts=("example.org",), max_records=1)


if __name__ == "__main__":
    unittest.main()
