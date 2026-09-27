"""Tests for backend-neutral and portable shared engagement stores."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from nightrecon_shared_core.contracts import EngagementEnvelope, EvidenceRecord
from nightrecon_shared_core.file_store import FileEngagementStore
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

    def test_file_store_round_trips_and_filters(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-store-") as directory:
            path = Path(directory) / "engagements.json"
            store = FileEngagementStore(path)
            red = record("r-1", "red", "identity.directory-snapshot")
            blue = record("b-1", "blue", "alert.observation")
            store.append_envelope(EngagementEnvelope("eng-1", (red, blue)))

            reloaded = FileEngagementStore(path)
            self.assertEqual(reloaded.records("eng-1"), (blue, red))
            self.assertEqual(
                reloaded.records("eng-1", source_night="red"),
                (red,),
            )

    def test_file_store_identical_append_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-store-") as directory:
            path = Path(directory) / "engagements.json"
            item = record("r-1", "red", "identity.directory-snapshot")
            store = FileEngagementStore(path)
            store.append(item)
            first = path.read_bytes()
            store.append(item)
            self.assertEqual(path.read_bytes(), first)

    def test_file_store_rejects_conflicting_duplicate_after_reload(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-store-") as directory:
            path = Path(directory) / "engagements.json"
            FileEngagementStore(path).append(record("r-1", "red", "asset.observation"))
            reloaded = FileEngagementStore(path)
            conflicting = EvidenceRecord(
                engagement_id="eng-1",
                evidence_id="r-1",
                source_night="red",
                evidence_type="asset.observation",
                observed_at="2026-09-27T22:50:00+00:00",
                provenance="fixture://changed",
                data={"reference": "changed"},
            )
            with self.assertRaises(EvidenceConflictError):
                reloaded.append(conflicting)

    def test_file_store_rejects_corrupt_and_future_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-store-") as directory:
            path = Path(directory) / "engagements.json"
            path.write_text("{not-json", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "valid UTF-8 JSON"):
                FileEngagementStore(path)

            path.write_text(
                '{"schema_version":2,"engagements":[]}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "schema version"):
                FileEngagementStore(path)


if __name__ == "__main__":
    unittest.main()
