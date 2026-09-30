"""White Night Batch 6 tamper-evident audit tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from nightrecon_white_engine.audit_log import (
    AuditTrail,
    AuditTrailError,
    FileAuditStore,
    InMemoryAuditStore,
    render_audit_summary,
)


def trail() -> AuditTrail:
    return AuditTrail.create(
        trail_id="audit-001",
        engagement_id="eng-001",
        event_id="audit-event-001",
        event_type="evidence.ingested",
        occurred_at="2026-09-29T16:01:00+00:00",
        actor_id="collector",
        subject_type="evidence",
        subject_id="ev-001",
        outcome="success",
        reason_code="evidence_ingested",
        summary="Evidence entered White custody",
        details=(
            ("case_id", "case-001"),
            ("record_fingerprint", "1" * 64),
        ),
    )


class WhiteAuditTrailTests(unittest.TestCase):
    def test_create_append_and_round_trip(self) -> None:
        item = trail().append(
            event_id="audit-event-002",
            event_type="evidence.transferred",
            occurred_at="2026-09-29T16:10:00+00:00",
            actor_id="custodian-a",
            subject_type="evidence",
            subject_id="ev-001",
            outcome="success",
            reason_code="custody_transferred",
            summary="Evidence custody transferred",
            details=(
                ("from_custodian", "custodian-a"),
                ("to_custodian", "custodian-b"),
            ),
        )
        self.assertEqual(len(item.events), 2)
        self.assertEqual(
            item.events[1].previous_event_fingerprint,
            item.events[0].fingerprint,
        )
        self.assertEqual(len(item.fingerprint), 64)
        self.assertEqual(AuditTrail.from_json(item.to_json()), item)

    def test_tampered_event_is_rejected(self) -> None:
        item = trail()
        payload = copy.deepcopy(item.to_dict())
        payload["events"][0]["summary"] = "Tampered audit summary"
        with self.assertRaisesRegex(
            AuditTrailError,
            "fingerprint verification failed",
        ):
            AuditTrail.from_dict(payload)

    def test_hash_valid_but_broken_chain_is_rejected(self) -> None:
        item = trail().append(
            event_id="audit-event-002",
            event_type="policy.verified",
            occurred_at="2026-09-29T16:05:00+00:00",
            actor_id="reviewer",
            subject_type="policy",
            subject_id="policy-001",
            outcome="success",
            reason_code="integrity_valid",
            summary="Policy integrity verified",
        )
        payload = item.to_dict()
        second = payload["events"][1]
        second["previous_event_fingerprint"] = "2" * 64

        # Rebuild the event fingerprint so only chain validation can catch it.
        from nightrecon_white_engine.audit_log import AuditEvent
        rebuilt_second = AuditEvent(
            schema_version=second["schema_version"],
            event_id=second["event_id"],
            trail_id=second["trail_id"],
            engagement_id=second["engagement_id"],
            sequence=second["sequence"],
            event_type=second["event_type"],
            occurred_at=second["occurred_at"],
            actor_id=second["actor_id"],
            subject_type=second["subject_type"],
            subject_id=second["subject_id"],
            outcome=second["outcome"],
            reason_code=second["reason_code"],
            summary=second["summary"],
            details=tuple(tuple(pair) for pair in second["details"]),
            previous_event_fingerprint=second[
                "previous_event_fingerprint"
            ],
        )
        payload["events"][1] = rebuilt_second.to_dict()

        with self.assertRaisesRegex(
            AuditTrailError,
            "chain verification failed",
        ):
            AuditTrail.from_dict(payload)

    def test_event_chronology_is_monotonic(self) -> None:
        with self.assertRaisesRegex(
            AuditTrailError,
            "chronologically ordered",
        ):
            trail().append(
                event_id="audit-event-backdated",
                event_type="evidence.verified",
                occurred_at="2026-09-29T16:00:00+00:00",
                actor_id="reviewer",
                subject_type="evidence",
                subject_id="ev-001",
                outcome="success",
                reason_code="integrity_valid",
                summary="Backdated event",
            )

    def test_secret_like_detail_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            AuditTrailError,
            "secret-like audit field",
        ):
            AuditTrail.create(
                trail_id="audit-secret",
                engagement_id="eng-001",
                event_id="audit-secret-event",
                event_type="evidence.ingested",
                occurred_at="2026-09-29T16:01:00+00:00",
                actor_id="collector",
                subject_type="evidence",
                subject_id="ev-001",
                outcome="success",
                reason_code="evidence_ingested",
                summary="Invalid detail",
                details=(("api_token", "do-not-store"),),
            )

    def test_duplicate_detail_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            AuditTrailError,
            "detail keys must be unique",
        ):
            AuditTrail.create(
                trail_id="audit-dup",
                engagement_id="eng-001",
                event_id="audit-dup-event",
                event_type="evidence.ingested",
                occurred_at="2026-09-29T16:01:00+00:00",
                actor_id="collector",
                subject_type="evidence",
                subject_id="ev-001",
                outcome="success",
                reason_code="evidence_ingested",
                summary="Duplicate details",
                details=(
                    ("case_id", "case-001"),
                    ("case_id", "case-002"),
                ),
            )

    def test_in_memory_store_requires_append_only_extension(self) -> None:
        store = InMemoryAuditStore()
        original = trail()
        store.create(original)

        advanced = original.append(
            event_id="audit-event-002",
            event_type="evidence.verified",
            occurred_at="2026-09-29T16:05:00+00:00",
            actor_id="reviewer",
            subject_type="evidence",
            subject_id="ev-001",
            outcome="success",
            reason_code="integrity_valid",
            summary="Evidence verified",
        )
        store.advance(advanced)
        self.assertEqual(store.trail("audit-001"), advanced)

        alternate = AuditTrail.create(
            trail_id="audit-001",
            engagement_id="eng-001",
            event_id="audit-alternate",
            event_type="evidence.ingested",
            occurred_at="2026-09-29T16:01:00+00:00",
            actor_id="other",
            subject_type="evidence",
            subject_id="ev-001",
            outcome="success",
            reason_code="alternate_history",
            summary="Alternate history",
        )
        with self.assertRaisesRegex(
            AuditTrailError,
            "append-only",
        ):
            store.advance(alternate)

    def test_file_store_persists_and_revalidates(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "audit.json"
            store = FileAuditStore(path)
            original = trail()
            store.create(original)
            advanced = original.append(
                event_id="audit-event-002",
                event_type="evidence.verified",
                occurred_at="2026-09-29T16:05:00+00:00",
                actor_id="reviewer",
                subject_type="evidence",
                subject_id="ev-001",
                outcome="success",
                reason_code="integrity_valid",
                summary="Evidence verified",
            )
            store.advance(advanced)

            reopened = FileAuditStore(path)
            self.assertEqual(reopened.trail("audit-001"), advanced)
            self.assertEqual(reopened.trails(), ("audit-001",))

            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["trails"][0]["events"][0]["summary"] = "Tampered"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                AuditTrailError,
                "fingerprint verification failed",
            ):
                FileAuditStore(path)

    def test_summary_omits_event_details(self) -> None:
        marker = "internal-reference-not-for-summary"
        item = AuditTrail.create(
            trail_id="audit-summary",
            engagement_id="eng-001",
            event_id="audit-summary-event",
            event_type="evidence.ingested",
            occurred_at="2026-09-29T16:01:00+00:00",
            actor_id="collector",
            subject_type="evidence",
            subject_id="ev-001",
            outcome="success",
            reason_code="evidence_ingested",
            summary="Evidence entered custody",
            details=(("internal_reference", marker),),
        )
        summary = render_audit_summary(item)
        self.assertNotIn(marker, summary)
        self.assertIn("audit-summary", summary)
        self.assertIn(item.events[0].fingerprint, summary)


if __name__ == "__main__":
    unittest.main()
