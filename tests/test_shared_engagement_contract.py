"""Tests for portable cross-Night engagement evidence contracts."""

from __future__ import annotations

import json
import unittest

from nightrecon_shared_core.contracts import EngagementEnvelope, EvidenceRecord


class SharedEngagementContractTests(unittest.TestCase):
    def record(self, *, evidence_id: str = "ev-1", source_night: str = "red") -> EvidenceRecord:
        return EvidenceRecord(
            engagement_id="eng-1",
            evidence_id=evidence_id,
            source_night=source_night,
            evidence_type="asset.observation",
            observed_at="2026-09-27T22:45:00+00:00",
            provenance="lab://fixture/asset-1",
            data={"asset_id": "asset-1", "state": "observed"},
            limitations=("lab fixture only",),
        )

    def test_record_serializes_deterministically(self) -> None:
        payload = json.loads(self.record().to_json())
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["source_night"], "red")
        self.assertEqual(payload["provenance"], "lab://fixture/asset-1")
        self.assertEqual(payload["limitations"], ["lab fixture only"])

    def test_envelope_can_mix_nights_for_one_engagement(self) -> None:
        envelope = EngagementEnvelope(
            engagement_id="eng-1",
            records=(
                self.record(evidence_id="red-1", source_night="red"),
                self.record(evidence_id="blue-1", source_night="blue"),
            ),
        )
        payload = json.loads(envelope.to_json())
        self.assertEqual([item["source_night"] for item in payload["records"]], ["red", "blue"])

    def test_unknown_source_night_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "known Night"):
            self.record(source_night="orange")

    def test_cross_engagement_record_is_rejected(self) -> None:
        record = EvidenceRecord(
            engagement_id="other",
            evidence_id="ev-2",
            source_night="red",
            evidence_type="asset.observation",
            observed_at="2026-09-27T22:45:00+00:00",
            provenance="lab://fixture/asset-2",
            data={"asset_id": "asset-2"},
        )
        with self.assertRaisesRegex(ValueError, "envelope engagement"):
            EngagementEnvelope(engagement_id="eng-1", records=(record,))

    def test_duplicate_evidence_id_is_rejected(self) -> None:
        record = self.record()
        with self.assertRaisesRegex(ValueError, "unique"):
            EngagementEnvelope(engagement_id="eng-1", records=(record, record))

    def test_secret_like_fields_are_rejected_recursively(self) -> None:
        with self.assertRaisesRegex(ValueError, "secret-like"):
            EvidenceRecord(
                engagement_id="eng-1",
                evidence_id="ev-secret",
                source_night="red",
                evidence_type="http.observation",
                observed_at="2026-09-27T22:45:00+00:00",
                provenance="lab://fixture/http",
                data={"request": {"Authorization": "Bearer should-not-be-stored"}},
            )

    def test_schema_version_is_explicit(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported evidence schema"):
            EvidenceRecord(
                engagement_id="eng-1",
                evidence_id="ev-version",
                source_night="red",
                evidence_type="asset.observation",
                observed_at="2026-09-27T22:45:00+00:00",
                provenance="lab://fixture/version",
                data={},
                schema_version=2,
            )

    def test_envelope_round_trip_preserves_records(self) -> None:
        envelope = EngagementEnvelope(
            engagement_id="eng-1",
            records=(
                self.record(evidence_id="red-1", source_night="red"),
                self.record(evidence_id="blue-1", source_night="blue"),
            ),
        )
        self.assertEqual(EngagementEnvelope.from_json(envelope.to_json()), envelope)

    def test_deserializer_rejects_unknown_fields(self) -> None:
        payload = json.loads(self.record().to_json())
        payload["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "schema is not supported"):
            EvidenceRecord.from_dict(payload)


if __name__ == "__main__":
    unittest.main()
