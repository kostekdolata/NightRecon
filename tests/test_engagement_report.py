"""Tests for professional Red engagement reports."""

import unittest

from nightrecon_shared_core.contracts import (
    EngagementEnvelope,
    EngagementMetadata,
    EvidenceRecord,
)
from nightrecon_red_engine.engagement_report import (
    build_engagement_professional_report,
)


class EngagementProfessionalReportTests(unittest.TestCase):
    def test_report_is_secret_safe_and_evidence_honest(self):
        envelope = EngagementEnvelope(
            engagement_id="eng-1",
            metadata=EngagementMetadata(
                engagement_id="eng-1",
                name="Assessment",
                created_at="2026-10-02T12:00:00+00:00",
                authorization_reference="AUTH-1",
                status="active",
            ),
            records=(
                EvidenceRecord(
                    engagement_id="eng-1",
                    evidence_id="e1",
                    source_night="red",
                    evidence_type="network",
                    observed_at="2026-10-02T12:01:00+00:00",
                    provenance="scanner",
                    data={"internal_detail": "not-for-report"},
                    limitations=("UDP response ambiguity remains.",),
                ),
            ),
        )

        report = build_engagement_professional_report(envelope)
        payload = report.to_dict()

        self.assertEqual(report.name, "Assessment")
        self.assertEqual(report.status, "active")
        self.assertIn("1 record", report.executive_summary)
        self.assertNotIn("internal_detail", str(payload))
        self.assertNotIn("not-for-report", str(payload))
        self.assertIn("does not convert inferred relationships", report.interpretation)

    def test_empty_evidence_is_explicitly_incomplete(self):
        report = build_engagement_professional_report(
            EngagementEnvelope(engagement_id="eng-1", records=())
        )

        self.assertIn("No engagement evidence records", report.executive_summary)


if __name__ == "__main__":
    unittest.main()
