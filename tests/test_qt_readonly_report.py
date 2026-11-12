"""Offline contract tests for the non-authoritative Qt reporting preview."""
import hashlib
import json
import unittest

from red_night_app.operations_read_model import OperationsSnapshot
from red_night_app.qt_operations_bridge import QtOperationsView, present_operations
from red_night_app.qt_readonly_report import build_readonly_report, render_readonly_report
from red_night_app.qt_workspace_views import workspace_summary


class QtReadonlyReportTests(unittest.TestCase):
    def test_disconnected_data_is_unknown_not_zero(self):
        view = present_operations(None)
        report = build_readonly_report(view)
        self.assertIsNone(report["remaining_authorized_actions"])
        self.assertIsNone(report["recorded_audit_events"])
        self.assertIsNone(report["recorded_review_findings"])
        self.assertEqual(report["finding_status"], "not_assessed")
        self.assertIn("Unavailable", workspace_summary(5, view))

    def test_deterministic_digest_and_no_raw_evidence_leak(self):
        snapshot = OperationsSnapshot(
            "engagement-secret", "ACTIVE", 3,
            ("Authorization: Bearer sensitive-token",),
            ("secret-host | secret-rule | review | private-evidence",),
            ("private warning content",),
        )
        view = present_operations(snapshot)
        report = build_readonly_report(view, warning_count=len(snapshot.warnings))
        digest = report.pop("report_sha256")
        canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self.assertEqual(digest, hashlib.sha256(canonical).hexdigest())
        report["report_sha256"] = digest
        self.assertEqual(report["recorded_audit_events"], 1)
        self.assertEqual(report["recorded_review_findings"], 1)
        self.assertEqual(report["snapshot_limitation_count"], 1)
        self.assertEqual(report, build_readonly_report(view, warning_count=1))
        rendered = workspace_summary(5, view, warnings=snapshot.warnings)
        for secret in ("engagement-secret", "sensitive-token", "secret-host",
                       "secret-rule", "private-evidence", "private warning content"):
            self.assertNotIn(secret, json.dumps(report) + rendered)
        self.assertIn("not authenticity", rendered)
        self.assertIn("Not a final professional report", rendered)

    def test_invalid_unredacted_views_fail_closed(self):
        safe = present_operations(None)
        for changed in (
            {"engagement_label": "secret-engagement-id"},
            {"authority_label": "ROOT"},
            {"events_label": "secret-audit-body"},
            {"findings_label": "-1"},
            {"actions_label": "1"},
        ):
            view = QtOperationsView(**(vars(safe) | changed))
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                build_readonly_report(view)
        for value in (-1, True, 100001, "1"):
            with self.assertRaises(ValueError):
                build_readonly_report(safe, warning_count=value)
        with self.assertRaises(TypeError):
            render_readonly_report(object())

    def test_no_execution_or_export_side_effects(self):
        view = present_operations(None)
        text = render_readonly_report(view)
        self.assertIn("No export, scan, approval or modification", text)
        self.assertIn("READ-ONLY", workspace_summary(5, view))


if __name__ == "__main__":
    unittest.main()
