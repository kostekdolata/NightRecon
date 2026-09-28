"""Tests for backend-neutral and portable shared engagement stores."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from nightrecon_shared_core.contracts import (
    EngagementEnvelope,
    EngagementMetadata,
    EvidenceRecord,
)
from nightrecon_shared_core.file_store import FileEngagementStore
from nightrecon_shared_core.store import (
    EvidenceConflictError,
    InMemoryEngagementStore,
    MetadataConflictError,
)


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


def metadata(name: str = "Engagement One") -> EngagementMetadata:
    return EngagementMetadata(
        engagement_id="eng-1",
        name=name,
        created_at="2026-09-27T22:40:00+00:00",
        authorization_reference="approval://eng-1",
        status="active",
    )


class EngagementStoreTests(unittest.TestCase):
    def test_metadata_is_idempotent_and_conflict_safe(self) -> None:
        store = InMemoryEngagementStore()
        item = metadata()
        store.set_metadata(item)
        store.set_metadata(item)
        self.assertEqual(store.metadata("eng-1"), item)
        with self.assertRaises(MetadataConflictError):
            store.set_metadata(metadata("Changed"))

    def test_metadata_can_be_replaced_only_after_creation(self) -> None:
        store = InMemoryEngagementStore()
        with self.assertRaisesRegex(ValueError, "metadata not found"):
            store.replace_metadata(metadata())
        store.set_metadata(metadata())
        updated = EngagementMetadata(
            engagement_id="eng-1",
            name="Engagement One",
            created_at="2026-09-27T22:40:00+00:00",
            authorization_reference="approval://eng-1",
            status="completed",
        )
        store.replace_metadata(updated)
        self.assertEqual(store.metadata("eng-1"), updated)

    def test_file_store_metadata_replacement_persists(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-store-") as directory:
            path = Path(directory) / "engagements.json"
            store = FileEngagementStore(path)
            store.set_metadata(metadata())
            updated = EngagementMetadata(
                engagement_id="eng-1",
                name="Engagement One",
                created_at="2026-09-27T22:40:00+00:00",
                authorization_reference="approval://eng-1",
                status="paused",
            )
            store.replace_metadata(updated)
            self.assertEqual(FileEngagementStore(path).metadata("eng-1"), updated)

    def test_envelope_append_is_atomic_for_metadata_and_evidence_conflicts(self) -> None:
        store = InMemoryEngagementStore()
        original = record("ev-1", "red", "asset.observation")
        store.set_metadata(metadata())
        store.append(original)
        conflict = EvidenceRecord(
            engagement_id="eng-1",
            evidence_id="ev-1",
            source_night="red",
            evidence_type="asset.observation",
            observed_at="2026-09-27T22:50:00+00:00",
            provenance="fixture://changed",
            data={"reference": "changed"},
        )
        envelope = EngagementEnvelope(
            engagement_id="eng-1",
            metadata=metadata(),
            records=(conflict, record("ev-2", "blue", "alert.observation")),
        )
        with self.assertRaises(EvidenceConflictError):
            store.append_envelope(envelope)
        self.assertEqual(store.records("eng-1"), (original,))
        self.assertEqual(store.metadata("eng-1"), metadata())

    def test_file_store_round_trips_cross_night_metadata_and_filters(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-store-") as directory:
            path = Path(directory) / "engagements.json"
            red = record("r-1", "red", "identity.directory-snapshot")
            blue = record("b-1", "blue", "alert.observation")
            store = FileEngagementStore(path)
            store.append_envelope(EngagementEnvelope(
                engagement_id="eng-1",
                metadata=metadata(),
                records=(red, blue),
            ))

            reloaded = FileEngagementStore(path)
            self.assertEqual(reloaded.metadata("eng-1"), metadata())
            self.assertEqual(reloaded.records("eng-1"), (blue, red))
            self.assertEqual(
                reloaded.records("eng-1", source_night="red"), (red,)
            )

    def test_export_import_round_trip_preserves_provenance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-store-") as directory:
            source_path = Path(directory) / "source.json"
            target_path = Path(directory) / "target.json"
            red = record("r-1", "red", "identity.directory-snapshot")
            blue = record("b-1", "blue", "alert.observation")
            source = FileEngagementStore(source_path)
            source.append_envelope(EngagementEnvelope(
                engagement_id="eng-1",
                metadata=metadata(),
                records=(red, blue),
            ))
            exported = source.export_envelope("eng-1")
            target = FileEngagementStore(target_path)
            target.import_envelope(exported)
            self.assertEqual(target.export_envelope("eng-1"), exported)
            self.assertEqual(
                {item.provenance for item in target.records("eng-1")},
                {"fixture://r-1", "fixture://b-1"},
            )

    def test_empty_metadata_only_engagement_survives_reload(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-store-") as directory:
            path = Path(directory) / "engagements.json"
            FileEngagementStore(path).set_metadata(metadata())
            reloaded = FileEngagementStore(path)
            self.assertEqual(reloaded.engagements(), ("eng-1",))
            self.assertEqual(reloaded.records("eng-1"), ())
            self.assertEqual(reloaded.metadata("eng-1"), metadata())

    def test_file_store_identical_append_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-store-") as directory:
            path = Path(directory) / "engagements.json"
            item = record("r-1", "red", "identity.directory-snapshot")
            store = FileEngagementStore(path)
            store.append(item)
            first = path.read_bytes()
            store.append(item)
            self.assertEqual(path.read_bytes(), first)

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
