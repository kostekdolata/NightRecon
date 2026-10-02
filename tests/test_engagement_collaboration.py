"""Tests for Red Night engagement collaboration metadata."""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from nightrecon_red_engine.engagement_collaboration import (
    CollaborationEventKind,
    CollaborationStore,
    ReviewState,
)


class EngagementCollaborationTests(unittest.TestCase):
    def test_assignment_review_and_handoff_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = CollaborationStore(Path(tmp) / "collaboration.json")
            now = datetime(2026, 10, 2, 20, 0, tzinfo=timezone.utc)

            store.record(
                event_id="evt-1",
                engagement_id="eng-1",
                actor_id="alice",
                kind=CollaborationEventKind.ASSIGNMENT,
                subject_kind="finding",
                subject_id="finding-1",
                assignee_id="bob",
                now=now,
            )
            store.record(
                event_id="evt-2",
                engagement_id="eng-1",
                actor_id="bob",
                kind=CollaborationEventKind.REVIEW_STATE,
                subject_kind="finding",
                subject_id="finding-1",
                review_state=ReviewState.IN_REVIEW,
                now=now,
            )
            store.record(
                event_id="evt-3",
                engagement_id="eng-1",
                actor_id="bob",
                kind=CollaborationEventKind.HANDOFF,
                subject_kind="finding",
                subject_id="finding-1",
                assignee_id="carol",
                note="Continue evidence review.",
                now=now,
            )

            summary = store.summary("eng-1")

            self.assertEqual(summary.total_events, 3)
            self.assertEqual(summary.handoffs, 1)
            self.assertEqual(
                summary.current_assignments,
                (("finding", "finding-1", "carol"),),
            )
            self.assertEqual(
                summary.current_review_states,
                (("finding", "finding-1", "in-review"),),
            )
            self.assertEqual(
                summary.participating_operators,
                ("alice", "bob", "carol"),
            )
            self.assertEqual(summary.authorization_effect, "none")

    def test_duplicate_event_is_idempotent_but_conflict_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = CollaborationStore(Path(tmp) / "collaboration.json")
            kwargs = dict(
                event_id="evt-1",
                engagement_id="eng-1",
                actor_id="alice",
                kind=CollaborationEventKind.ANNOTATION,
                subject_kind="evidence",
                subject_id="ev-1",
                note="Reviewed metadata only.",
                now=datetime(2026, 10, 2, 20, 0, tzinfo=timezone.utc),
            )
            first = store.record(**kwargs)
            second = store.record(**kwargs)
            self.assertEqual(first, second)
            with self.assertRaisesRegex(ValueError, "different content"):
                store.record(**{**kwargs, "note": "Different note."})

    def test_schema_rejects_authority_and_malformed_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "collaboration.json"
            path.write_text(json.dumps({
                "schema_version": 1,
                "events": [{
                    "event_id": "evt-1",
                    "engagement_id": "eng-1",
                    "occurred_at": "2026-10-02T20:00:00+00:00",
                    "actor_id": "alice",
                    "kind": "annotation",
                    "subject_kind": "evidence",
                    "subject_id": "ev-1",
                    "note": "Reviewed.",
                    "review_state": None,
                    "assignee_id": None,
                    "authorization_effect": "grant",
                }],
            }), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "cannot grant authorization"):
                CollaborationStore(path)


if __name__ == "__main__":
    unittest.main()
