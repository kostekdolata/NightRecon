"""Tests for secret-safe engagement evidence review."""

import unittest

from nightrecon_shared_core.contracts import EngagementEnvelope, EvidenceRecord
from nightrecon_red_engine.engagement_review import build_engagement_evidence_review


def record(evidence_id, source_night, evidence_type, limitations=()):
    return EvidenceRecord(
        engagement_id="eng-1",
        evidence_id=evidence_id,
        source_night=source_night,
        evidence_type=evidence_type,
        observed_at="2026-10-02T12:00:00+00:00",
        provenance="fixture",
        data={"summary": "safe"},
        limitations=limitations,
    )


class EngagementEvidenceReviewTests(unittest.TestCase):
    def test_review_filters_and_omits_raw_payloads(self):
        envelope = EngagementEnvelope(
            engagement_id="eng-1",
            records=(
                record("e1", "red", "network", ("partial coverage",)),
                record("e2", "white", "governance"),
            ),
        )

        result = build_engagement_evidence_review(
            envelope,
            source_night="red",
        )
        payload = result.to_dict()

        self.assertEqual(result.total_records, 1)
        self.assertEqual(result.records_with_limitations, 1)
        self.assertEqual(result.items[0].evidence_id, "e1")
        self.assertNotIn("data", payload["items"][0])
        self.assertNotIn("safe", str(payload))

    def test_review_is_bounded(self):
        envelope = EngagementEnvelope(
            engagement_id="eng-1",
            records=(record("e1", "red", "network"),),
        )

        with self.assertRaisesRegex(ValueError, "max_items"):
            build_engagement_evidence_review(envelope, max_items=0)


if __name__ == "__main__":
    unittest.main()
