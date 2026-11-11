"""Offline Nuclei import safety contracts, no network or subprocess."""
import json
import unittest

from nightrecon_red_engine.nuclei_offline_evidence import (
    NucleiEvidenceError, import_nuclei_jsonl,
)


def record(url="https://example.test/a", severity="medium"):
    return {"template-id": "sample-template", "matched-at": url,
            "info": {"severity": severity}, "request": "SECRET_DO_NOT_EXPORT"}


def encoded(*rows):
    return ("\n".join(json.dumps(row) for row in rows)).encode()


class NucleiOfflineEvidenceTests(unittest.TestCase):
    def parse(self, payload, **changes):
        args = dict(engagement_id="lab", authorized_hosts=("example.test",))
        args.update(changes)
        return import_nuclei_jsonl(payload, **args)

    def test_bounded_unverified_provenance_and_redaction(self):
        result = self.parse(encoded(record(), record("https://example.test/b")))
        self.assertEqual(result["observation_count"], 2)
        self.assertEqual(result["confirmed_findings"], 0)
        self.assertFalse(result["external_execution"])
        self.assertFalse(result["integration_verified"])
        self.assertEqual(len(result["source_sha256"]), 64)
        self.assertNotIn("SECRET_DO_NOT_EXPORT", str(result))
        self.assertEqual(result["observations"][0]["host"], "example.test")

    def test_out_of_scope_and_unsafe_urls_fail_closed(self):
        for url in ("https://outside.test/", "https://example.test.evil/",
                    "https://user:pass@example.test/", "file:///tmp/a",
                    "https://example.test/a#fragment", "https://example.test:99999/"):
            with self.subTest(url=url), self.assertRaises(NucleiEvidenceError):
                self.parse(encoded(record(url)))

    def test_malformed_and_budgets_fail_closed(self):
        for raw in (b"{", b"[]", b"", b"\xff", b"\n", encoded({"template-id": "x"})):
            with self.subTest(raw=raw), self.assertRaises(NucleiEvidenceError):
                self.parse(raw)
        with self.assertRaises(NucleiEvidenceError):
            self.parse(encoded(record(), record()), max_records=1)
        with self.assertRaises(NucleiEvidenceError):
            self.parse(encoded(record()), max_bytes=1)
        with self.assertRaises(NucleiEvidenceError):
            self.parse(encoded(record(severity="unknown")))


if __name__ == "__main__":
    unittest.main()
