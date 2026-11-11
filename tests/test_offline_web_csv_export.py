"""Offline report CSV export safety and reproducibility tests."""
import csv
import io
import json
import unittest

from nightrecon_red_engine.offline_web_operator_report import build_offline_web_operator_report
from nightrecon_red_engine.offline_web_csv_export import (
    OfflineWebCsvExportError, export_offline_web_report_csv,
)


def report():
    return build_offline_web_operator_report(
        json.dumps({"name": "example.org", "secret": "NEVER-EXPORT"}).encode(),
        json.dumps({"url": "https://example.org/", "status_code": 200,
                    "body": "NEVER-EXPORT"}).encode(),
        allowed_hosts=("example.org",),
        allowed_urls=("https://example.org/",),
        engagement_id="lab-001",
    )


class OfflineWebCsvExportTests(unittest.TestCase):
    def test_deterministic_projection_and_provenance(self):
        item = report()
        payload = export_offline_web_report_csv(item)
        self.assertEqual(payload, export_offline_web_report_csv(item))
        rows = list(csv.DictReader(io.StringIO(payload.decode())))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["url"], "https://example.org/")
        self.assertEqual(rows[0]["report_sha256"], item["report_sha256"])
        self.assertEqual(rows[0]["amass_sha256"], item["sources"]["amass"]["sha256"])
        self.assertEqual(rows[0]["httpx_sha256"], item["sources"]["httpx"]["sha256"])
        self.assertEqual(rows[0]["confirmed_findings"], "0")
        self.assertEqual(rows[0]["authorization"], "not_established_by_import")
        self.assertNotIn(b"NEVER-EXPORT", payload)

    def test_tampering_and_budget_fail_closed(self):
        item = report()
        item["associations"][0]["http_status"] = 500
        with self.assertRaises(OfflineWebCsvExportError):
            export_offline_web_report_csv(item)
        with self.assertRaises(OfflineWebCsvExportError):
            export_offline_web_report_csv(report(), max_associations=0)

    def test_invalid_and_formula_like_records_fail_closed(self):
        for item in (None, {}, {"report_sha256": "0" * 64}):
            with self.subTest(item=item), self.assertRaises(OfflineWebCsvExportError):
                export_offline_web_report_csv(item)
        item = report()
        item["associations"][0]["url"] = "=HYPERLINK(1)"
        with self.assertRaises(OfflineWebCsvExportError):
            export_offline_web_report_csv(item)


if __name__ == "__main__":
    unittest.main()
