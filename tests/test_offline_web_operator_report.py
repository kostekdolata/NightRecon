"""Offline report acceptance and evidence-honesty regression tests."""
import json
import unittest

from nightrecon_red_engine.offline_web_operator_report import (
    build_offline_web_operator_report,
)


class OfflineWebOperatorReportTests(unittest.TestCase):
    def setUp(self):
        self.amass = json.dumps({"name": "example.org", "secret": "never-export"}).encode()
        self.httpx = json.dumps({"url": "https://example.org/", "status_code": 200,
                                 "body": "never-export"}).encode()
        self.kwargs = dict(allowed_hosts=("example.org",),
                           allowed_urls=("https://example.org/",),
                           engagement_id="lab-001")

    def test_deterministic_review_artifact_with_provenance(self):
        report = build_offline_web_operator_report(self.amass, self.httpx, **self.kwargs)
        self.assertEqual(report, build_offline_web_operator_report(
            self.amass, self.httpx, **self.kwargs))
        self.assertEqual(len(report["report_sha256"]), 64)
        self.assertEqual(len(report["sources"]["amass"]["sha256"]), 64)
        self.assertEqual(report["summary"]["correlated_associations"], 1)
        self.assertEqual(report["summary"]["confirmed_findings"], 0)
        self.assertEqual(report["authorization"], "not_established_by_import")
        self.assertTrue(report["review"]["required"])
        self.assertNotIn("never-export", str(report))

    def test_out_of_scope_input_never_becomes_report(self):
        with self.assertRaises(ValueError):
            build_offline_web_operator_report(
                self.amass,
                json.dumps({"url": "https://evil.example.org/", "status_code": 200}).encode(),
                **self.kwargs,
            )

    def test_rejects_untrusted_engagement_labels_and_budgets(self):
        for label in ("", "../secret", "engagement\\nspoof", "x" * 129):
            with self.subTest(label=label), self.assertRaises(ValueError):
                build_offline_web_operator_report(
                    self.amass, self.httpx, **{**self.kwargs, "engagement_id": label})
        with self.assertRaises(ValueError):
            build_offline_web_operator_report(
                self.amass, self.httpx, **self.kwargs, max_links=0)


if __name__ == "__main__":
    unittest.main()
