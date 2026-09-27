"""Tests for the backend-neutral shared engagement store."""

from __future__ import annotations

import unittest

from nightrecon_shared_core.contracts import EngagementEnvelope, EvidenceRecord
from nightrecon_shared_core.store import EvidenceConflictError, InMemoryEngagementStore


def record(evidence_id: str, source_night: str, evidence_type: str) -> EvidenceRecord:
    return EvidenceRecord(
        engagement_id="eng-1",
        evidence_id=evidence_id,
        source_night=source_night,
        evidence_type=evidence_type,
        observed_at="2026-09-27T22:50:00+00:00",
        provenance=f"fixture://{evidence_id}",
        data={"reference": evidence_id},
    )


class EngagementStoreTests(unittest.TestCase):
    def test_append_is_idempotent_for_identical_immutable_record(self) -> None:
        store = InMemoryEngagementStore()
        item = record("ev-1", "red", "asset.observation")
        store.append(item)
        store.append(item)
        self.assertEqual(store.records("eng-1"), (item,))

    def test_conflicting_duplicate_is_rejected(self) -> None:
        store = InMemoryEngagementStore()
        store.append(record("ev-1", "red", "asset.observation"))
        conflicting = EvidenceRecord(
            engagement_id="eng-1",
            evidence_id="ev-1",
            source_night="red",
            evidence_type="asset.observation",
            observed_at="2026-09-27T22:50:00+00:00",
            provenance="fixture://changed",
            data={"reference": "changed"},
        )
        with self.assertRaises(EvidenceConflictError):
            store.append(conflicting)

    def test_envelope_append_is_atomic_on_conflict(self) -> None:
        store = InMemoryEngagementStore()
        original = record("ev-1", "red", "asset.observation")
        store.append(original)
        conflicting = EvidenceRecord(
            engagement_id="eng-1",
            evidence_id="ev-1",
            source_night="red",
            evidence_type="asset.observation",
            observed_at="2026-09-27T22:50:00+00:00",
            provenance="fixture://conflict",
            data={"reference": "conflict"},
        )
        later = record("ev-2", "blue", "alert.observation")
        envelope = EngagementEnvelope(
            engagement_id="eng-1",
            records=(conflicting, later),
        )
        with self.assertRaises(EvidenceConflictError):
            store.append_envelope(envelope)
        self.assertEqual(store.records("eng-1"), (original,))

    def test_reads_are_deterministic_and_filterable(self) -> None:
        store = InMemoryEngagementStore()
        blue = record("b-1", "blue", "alert.observation")
        red2 = record("r-2", "red", "identity.directory-snapshot")
        red1 = record("r-1", "red", "asset.observation")
        store.extend((red2, blue, red1))

        self.assertEqual(store.records("eng-1"), (blue, red1, red2))
        self.assertEqual(store.records("eng-1", source_night="red"), (red1, red2))
        self.assertEqual(
            store.records("eng-1", evidence_type="alert.observation"),
            (blue,),
        )
        self.assertEqual(store.engagements(), ("eng-1",))

    def test_blank_engagement_read_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "engagement_id"):
            InMemoryEngagementStore().records(" ")


if __name__ == "__main__":
    unittest.main()
