"""Tests for portable cross-Night engagement evidence contracts."""

from __future__ import annotations

import json
import unittest

from nightrecon_shared_core.contracts import (
    EngagementEnvelope,
    EngagementMetadata,
    EvidenceRecord,
)


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

    def metadata(self) -> EngagementMetadata:
        return EngagementMetadata(
            engagement_id="eng-1",
            name="Lab engagement",
            created_at="2026-09-27T22:40:00+00:00",
            authorization_reference="approval://eng-1",
            status="active",
            description="Coordination metadata only.",
        )

    def test_record_serializes_deterministically(self) -> None:
        payload = json.loads(self.record().to_json())
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["source_night"], "red")

    def test_envelope_can_mix_nights_for_one_engagement(self) -> None:
        envelope = EngagementEnvelope(
            engagement_id="eng-1",
            metadata=self.metadata(),
            records=(
                self.record(evidence_id="red-1", source_night="red"),
                self.record(evidence_id="blue-1", source_night="blue"),
            ),
        )
        payload = json.loads(envelope.to_json())
        self.assertEqual(
            payload["metadata"]["authorization_reference"], "approval://eng-1"
        )
        self.assertEqual(
            [item["source_night"] for item in payload["records"]],
            ["red", "blue"],
        )

    def test_metadata_does_not_embed_authorization_material(self) -> None:
        metadata = self.metadata()
        self.assertEqual(metadata.authorization_reference, "approval://eng-1")
        self.assertFalse(hasattr(metadata, "scope"))
        self.assertFalse(hasattr(metadata, "approved"))

    def test_metadata_rejects_unknown_status(self) -> None:
        with self.assertRaisesRegex(ValueError, "status"):
            EngagementMetadata(
                engagement_id="eng-1",
                name="Lab",
                created_at="2026-09-27T22:40:00+00:00",
                authorization_reference="approval://eng-1",
                status="running-wild",
            )

    def test_unknown_source_night_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "known Night"):
            self.record(source_night="orange")

    def test_cross_engagement_metadata_is_rejected(self) -> None:
        metadata = EngagementMetadata(
            engagement_id="other",
            name="Other",
            created_at="2026-09-27T22:40:00+00:00",
            authorization_reference="approval://other",
        )
        with self.assertRaisesRegex(ValueError, "metadata"):
            EngagementEnvelope(
                engagement_id="eng-1",
                metadata=metadata,
                records=(),
            )

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

    def test_envelope_round_trip_preserves_metadata_and_records(self) -> None:
        envelope = EngagementEnvelope(
            engagement_id="eng-1",
            metadata=self.metadata(),
            records=(
                self.record(evidence_id="red-1", source_night="red"),
                self.record(evidence_id="blue-1", source_night="blue"),
            ),
        )
        self.assertEqual(EngagementEnvelope.from_json(envelope.to_json()), envelope)

    def test_legacy_v1_envelope_without_metadata_still_loads(self) -> None:
        legacy = {
            "schema_version": 1,
            "engagement_id": "eng-1",
            "records": [self.record().to_dict()],
        }
        loaded = EngagementEnvelope.from_dict(legacy)
        self.assertIsNone(loaded.metadata)
        self.assertEqual(loaded.records, (self.record(),))

    def test_deserializer_rejects_unknown_fields(self) -> None:
        payload = json.loads(self.record().to_json())
        payload["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "schema is not supported"):
            EvidenceRecord.from_dict(payload)


if __name__ == "__main__":
    unittest.main()
