"""Offline retest delta contract tests; synthetic evidence only."""
import json
import unittest

from nightrecon_red_engine.offline_web_operator_report import build_offline_web_operator_report
from nightrecon_red_engine.offline_web_evidence_delta import (
    OfflineWebRetestError, compare_offline_web_reports,
)


def report(status=200, engagement="lab-1"):
    return build_offline_web_operator_report(
        json.dumps({"name": "example.org"}).encode(),
        json.dumps({"url": "https://example.org/", "status_code": status}).encode(),
        allowed_hosts=("example.org",),
        allowed_urls=("https://example.org/",),
        engagement_id=engagement,
    )


class OfflineWebEvidenceDeltaTests(unittest.TestCase):
    def test_status_change_is_observation_delta_not_remediation(self):
        delta = compare_offline_web_reports(report(200), report(404))
        self.assertEqual(len(delta["added_observations"]), 1)
        self.assertEqual(len(delta["removed_observations"]), 1)
        self.assertEqual(delta["unchanged_count"], 0)
        self.assertFalse(delta["remediation_verified"])
        self.assertEqual(delta["confirmed_findings"], 0)
        self.assertEqual(delta, compare_offline_web_reports(report(200), report(404)))

    def test_unchanged_report_and_source_provenance(self):
        before = report()
        delta = compare_offline_web_reports(before, before)
        self.assertEqual(delta["unchanged_count"], 1)
        self.assertEqual(delta["before_report_sha256"], before["report_sha256"])
        self.assertEqual(delta["added_observations"], [])

    def test_rejects_tampering_cross_engagement_and_budget(self):
        tampered = report()
        tampered["associations"][0]["http_status"] = 500
        for before, after, kwargs in (
            (tampered, report(), {}),
            (report(), report(engagement="other"), {}),
            (report(), report(), {"max_associations": 0}),
        ):
            with self.assertRaises(OfflineWebRetestError):
                compare_offline_web_reports(before, after, **kwargs)


if __name__ == "__main__":
    unittest.main()
