"""White Night Batch 6 evidence custody and manifest tests."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from nightrecon_shared_core.contracts import EvidenceRecord
from nightrecon_white_engine.engagement_domain import DataHandlingPolicy
from nightrecon_white_engine.evidence_custody import (
    CustodiedEvidence,
    CustodyEvent,
    EvidenceCustodyCase,
    EvidenceCustodyError,
    EvidenceExportBundle,
    FileCustodyStore,
    InMemoryCustodyStore,
    render_custody_summary,
)


BASE = datetime(2026, 9, 29, 16, 0, tzinfo=timezone.utc)


def when(minutes: int) -> str:
    return (BASE + timedelta(minutes=minutes)).isoformat()


def evidence(
    evidence_id: str,
    *,
    source_night: str = "red",
    evidence_type: str = "assessment.finding",
    data: dict | None = None,
) -> EvidenceRecord:
    return EvidenceRecord(
        engagement_id="eng-001",
        evidence_id=evidence_id,
        source_night=source_night,
        evidence_type=evidence_type,
        observed_at=when(0),
        provenance="authorized-test-fixture",
        data={"finding": evidence_id} if data is None else data,
        limitations=("fixture only",),
    )


def policy(
    *,
    classification: str = "confidential",
    retention_days: int = 30,
    export_allowed: bool = True,
) -> DataHandlingPolicy:
    return DataHandlingPolicy(
        classification=classification,
        retention_days=retention_days,
        export_allowed=export_allowed,
    )


def custody_case(
    *,
    data_handling: DataHandlingPolicy | None = None,
) -> EvidenceCustodyCase:
    return EvidenceCustodyCase.create(
        case_id="case-001",
        engagement_id="eng-001",
        data_handling=policy() if data_handling is None else data_handling,
        record=evidence("ev-001"),
        actor_id="collector",
        custodian_id="custodian-a",
        occurred_at=when(1),
        event_id="evt-ingest-1",
        reason="Initial evidence intake",
    )


class WhiteEvidenceCustodyTests(unittest.TestCase):
    def test_create_inherits_data_handling_and_fingerprints_record(self) -> None:
        case = custody_case()
        item = case.item("ev-001")
        self.assertEqual(item.classification, "confidential")
        self.assertTrue(item.export_allowed)
        self.assertEqual(len(item.record_fingerprint), 64)
        self.assertEqual(len(item.fingerprint), 64)
        self.assertEqual(len(case.data_handling_fingerprint), 64)
        self.assertEqual(len(case.fingerprint), 64)
        self.assertEqual(
            item.retention_status(when(2)),
            "retained",
        )

    def test_retention_window_is_derived_from_policy(self) -> None:
        case = custody_case(
            data_handling=policy(retention_days=1)
        )
        item = case.item("ev-001")
        self.assertEqual(
            item.retain_until,
            (BASE + timedelta(minutes=1, days=1)).isoformat(),
        )
        self.assertEqual(
            item.retention_status(
                (BASE + timedelta(minutes=1, days=1)).isoformat()
            ),
            "expired",
        )

    def test_classification_cannot_drop_below_engagement_floor(self) -> None:
        with self.assertRaisesRegex(
            EvidenceCustodyError,
            "below engagement policy",
        ):
            EvidenceCustodyCase.create(
                case_id="case-001",
                engagement_id="eng-001",
                data_handling=policy(classification="restricted"),
                record=evidence("ev-001"),
                actor_id="collector",
                custodian_id="custodian-a",
                occurred_at=when(1),
                event_id="evt-ingest-1",
                reason="Initial intake",
                classification="confidential",
            )

    def test_derived_evidence_requires_existing_parent_and_records_lineage(self) -> None:
        case = custody_case()
        case = case.add_record(
            evidence(
                "ev-002",
                source_night="white",
                evidence_type="white.analysis",
            ),
            actor_id="analyst",
            custodian_id="custodian-b",
            occurred_at=when(5),
            event_id="evt-derived",
            reason="Derived normalized analysis",
            parent_evidence_ids=("ev-001",),
        )
        item = case.item("ev-002")
        self.assertEqual(item.parent_evidence_ids, ("ev-001",))
        self.assertEqual(case.events[-1].event_type, "derived")
        self.assertEqual(
            json.loads(case.events[-1].detail("parent_evidence_ids")),
            ["ev-001"],
        )

        with self.assertRaisesRegex(
            EvidenceCustodyError,
            "unknown parents",
        ):
            case.add_record(
                evidence("ev-003"),
                actor_id="analyst",
                custodian_id="custodian-b",
                occurred_at=when(6),
                event_id="evt-bad-derived",
                reason="Invalid derivation",
                parent_evidence_ids=("ev-missing",),
            )

    def test_deserialized_derivation_cannot_reference_future_origin(self) -> None:
        source = custody_case().add_record(
            evidence(
                "ev-002",
                source_night="white",
                evidence_type="white.analysis",
            ),
            actor_id="analyst",
            custodian_id="custodian-b",
            occurred_at=when(5),
            event_id="evt-derived",
            reason="Derived analysis",
            parent_evidence_ids=("ev-001",),
        )
        ev1 = source.item("ev-001")
        ev2 = source.item("ev-002")

        derived_first = CustodyEvent(
            event_id="evt-derived-first",
            case_id="case-future",
            engagement_id="eng-001",
            sequence=0,
            event_type="derived",
            occurred_at=when(1),
            actor_id="analyst",
            reason="Impossible chronology",
            evidence_id="ev-002",
            details=(
                ("custodian_id", "custodian-b"),
                ("parent_evidence_ids", '["ev-001"]'),
            ),
        )
        origin_second = CustodyEvent(
            event_id="evt-parent-late",
            case_id="case-future",
            engagement_id="eng-001",
            sequence=1,
            event_type="ingested",
            occurred_at=when(2),
            actor_id="collector",
            reason="Parent arrives later",
            evidence_id="ev-001",
            details=(("custodian_id", "custodian-a"),),
            previous_event_fingerprint=derived_first.fingerprint,
        )
        ev2_early = CustodiedEvidence(
            record=ev2.record,
            classification=ev2.classification,
            retained_from=when(1),
            retain_until=ev2.retain_until,
            export_allowed=ev2.export_allowed,
            parent_evidence_ids=ev2.parent_evidence_ids,
        )
        ev1_late = CustodiedEvidence(
            record=ev1.record,
            classification=ev1.classification,
            retained_from=when(2),
            retain_until=ev1.retain_until,
            export_allowed=ev1.export_allowed,
        )
        with self.assertRaisesRegex(
            EvidenceCustodyError,
            "parents must already be in custody",
        ):
            EvidenceCustodyCase(
                case_id="case-future",
                engagement_id="eng-001",
                data_handling=policy(),
                items=(ev1_late, ev2_early),
                events=(derived_first, origin_second),
            )

    def test_transfer_requires_current_custodian_and_projects_history(self) -> None:
        case = custody_case()
        case = case.transfer(
            "ev-001",
            actor_id="custodian-a",
            to_custodian="custodian-b",
            occurred_at=when(10),
            event_id="evt-transfer",
            reason="Handoff",
        )
        self.assertEqual(
            case.current_custodian("ev-001", at=when(5)),
            "custodian-a",
        )
        self.assertEqual(
            case.current_custodian("ev-001", at=when(10)),
            "custodian-b",
        )
        with self.assertRaisesRegex(
            EvidenceCustodyError,
            "current custodian",
        ):
            case.transfer(
                "ev-001",
                actor_id="custodian-a",
                to_custodian="custodian-c",
                occurred_at=when(11),
                event_id="evt-invalid-transfer",
                reason="Invalid handoff",
            )

    def test_manifest_is_metadata_only_and_never_authorization(self) -> None:
        secret_marker = "nonsecret-evidence-value"
        case = EvidenceCustodyCase.create(
            case_id="case-001",
            engagement_id="eng-001",
            data_handling=policy(),
            record=evidence(
                "ev-001",
                data={"finding": secret_marker},
            ),
            actor_id="collector",
            custodian_id="custodian-a",
            occurred_at=when(1),
            event_id="evt-ingest-1",
            reason="Initial intake",
        )
        manifest = case.manifest(generated_at=when(2))
        serialized = json.dumps(manifest.to_dict(), sort_keys=True)
        self.assertEqual(manifest.authorization_effect, "none")
        self.assertNotIn(secret_marker, serialized)
        self.assertEqual(
            manifest.entries[0].record_fingerprint,
            case.item("ev-001").record_fingerprint,
        )

    def test_manifest_cannot_predate_latest_custody_event(self) -> None:
        case = custody_case().transfer(
            "ev-001",
            actor_id="custodian-a",
            to_custodian="custodian-b",
            occurred_at=when(10),
            event_id="evt-transfer",
            reason="Handoff",
        )
        with self.assertRaisesRegex(
            EvidenceCustodyError,
            "cannot predate",
        ):
            case.manifest(generated_at=when(9))

    def test_export_bundle_round_trip_and_explicit_non_authorization(self) -> None:
        case = custody_case()
        updated, bundle = case.export(
            actor_id="custodian-a",
            destination="offline-review",
            occurred_at=when(15),
            event_id="evt-export",
            reason="Approved evidence export",
        )
        self.assertEqual(updated.events[-1].event_type, "exported")
        self.assertEqual(bundle.authorization_effect, "none")
        self.assertEqual(bundle.manifest.authorization_effect, "none")
        self.assertEqual(
            bundle.manifest.case_fingerprint,
            updated.fingerprint,
        )
        rebuilt = EvidenceExportBundle.from_json(bundle.to_json())
        self.assertEqual(rebuilt, bundle)
        self.assertTrue(rebuilt.verify_integrity())

    def test_export_bundle_tamper_is_rejected(self) -> None:
        _, bundle = custody_case().export(
            actor_id="custodian-a",
            destination="offline-review",
            occurred_at=when(15),
            event_id="evt-export",
            reason="Approved evidence export",
        )
        tampered = copy.deepcopy(bundle.to_dict())
        tampered["records"][0]["data"]["finding"] = "tampered"
        with self.assertRaisesRegex(
            EvidenceCustodyError,
            "fingerprint",
        ):
            EvidenceExportBundle.from_dict(tampered)

    def test_export_respects_policy_and_retention(self) -> None:
        denied = custody_case(
            data_handling=policy(export_allowed=False)
        )
        with self.assertRaisesRegex(
            EvidenceCustodyError,
            "forbids export",
        ):
            denied.export(
                actor_id="custodian-a",
                destination="offline-review",
                occurred_at=when(2),
                event_id="evt-export-denied",
                reason="Must be denied",
            )

        short = custody_case(
            data_handling=policy(retention_days=1)
        )
        expired_at = (
            BASE + timedelta(days=1, minutes=1)
        ).isoformat()
        with self.assertRaisesRegex(
            EvidenceCustodyError,
            "expired evidence",
        ):
            short.export(
                actor_id="custodian-a",
                destination="offline-review",
                occurred_at=expired_at,
                event_id="evt-export-expired",
                reason="Expired evidence",
            )

    def test_case_round_trip_and_event_tamper_detection(self) -> None:
        case = custody_case().transfer(
            "ev-001",
            actor_id="custodian-a",
            to_custodian="custodian-b",
            occurred_at=when(10),
            event_id="evt-transfer",
            reason="Handoff",
        )
        rebuilt = EvidenceCustodyCase.from_json(case.to_json())
        self.assertEqual(rebuilt, case)

        tampered = copy.deepcopy(case.to_dict())
        tampered["events"][1]["reason"] = "Tampered"
        with self.assertRaisesRegex(
            EvidenceCustodyError,
            "fingerprint verification failed",
        ):
            EvidenceCustodyCase.from_dict(tampered)

    def test_store_accepts_only_append_only_case_advancement(self) -> None:
        store = InMemoryCustodyStore()
        original = custody_case()
        store.create(original)
        advanced = original.transfer(
            "ev-001",
            actor_id="custodian-a",
            to_custodian="custodian-b",
            occurred_at=when(10),
            event_id="evt-transfer",
            reason="Handoff",
        )
        store.advance(advanced)
        self.assertEqual(store.case("case-001"), advanced)

        alternative = EvidenceCustodyCase.create(
            case_id="case-001",
            engagement_id="eng-001",
            data_handling=policy(),
            record=evidence("ev-001"),
            actor_id="collector",
            custodian_id="custodian-x",
            occurred_at=when(1),
            event_id="evt-other-origin",
            reason="Alternate history",
        )
        with self.assertRaisesRegex(
            EvidenceCustodyError,
            "append-only",
        ):
            store.advance(alternative)

    def test_file_store_persists_and_revalidates_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "custody.json"
            store = FileCustodyStore(path)
            case = custody_case()
            store.create(case)
            advanced = case.transfer(
                "ev-001",
                actor_id="custodian-a",
                to_custodian="custodian-b",
                occurred_at=when(10),
                event_id="evt-transfer",
                reason="Handoff",
            )
            store.advance(advanced)

            reopened = FileCustodyStore(path)
            self.assertEqual(reopened.case("case-001"), advanced)
            self.assertEqual(reopened.cases(), ("case-001",))

            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["cases"][0]["events"][0]["reason"] = "Tampered"
            path.write_text(
                json.dumps(payload),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                EvidenceCustodyError,
                "fingerprint verification failed",
            ):
                FileCustodyStore(path)

    def test_summary_is_secret_safe_and_omits_evidence_data(self) -> None:
        marker = "sensitive-business-value-123"
        case = EvidenceCustodyCase.create(
            case_id="case-001",
            engagement_id="eng-001",
            data_handling=policy(),
            record=evidence(
                "ev-001",
                data={"finding": marker},
            ),
            actor_id="collector",
            custodian_id="custodian-a",
            occurred_at=when(1),
            event_id="evt-ingest-1",
            reason="Initial intake",
        )
        summary = render_custody_summary(case, at=when(2))
        self.assertNotIn(marker, summary)
        self.assertIn("Authorization effect: none", summary)
        self.assertIn("ev-001", summary)

    def test_shared_core_secret_like_evidence_fields_remain_rejected(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "secret-like evidence field",
        ):
            evidence(
                "ev-secret",
                data={"api_token": "must-not-be-stored"},
            )


if __name__ == "__main__":
    unittest.main()
