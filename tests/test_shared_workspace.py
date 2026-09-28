"""Tests for shared NightRecon workspace coordination."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from nightrecon_shared_core.contracts import (
    EngagementEnvelope,
    EngagementMetadata,
    EvidenceRecord,
)
from nightrecon_shared_core.workspace import LocalWorkspace


def metadata(name: str = "Shared lab") -> EngagementMetadata:
    return EngagementMetadata(
        engagement_id="eng-1",
        name=name,
        created_at="2026-09-27T23:00:00+00:00",
        authorization_reference="approval://eng-1",
        status="active",
    )


def evidence(evidence_id: str, night: str, evidence_type: str) -> EvidenceRecord:
    return EvidenceRecord(
        engagement_id="eng-1",
        evidence_id=evidence_id,
        source_night=night,
        evidence_type=evidence_type,
        observed_at="2026-09-27T23:01:00+00:00",
        provenance=f"fixture://{night}/{evidence_id}",
        data={"reference": evidence_id},
        limitations=("fixture only",),
    )


class WorkspaceTests(unittest.TestCase):
    def test_engagement_lifecycle_create_status_and_timeline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-workspace-") as directory:
            workspace = LocalWorkspace(directory)
            created = workspace.create_engagement(EngagementMetadata(
                engagement_id="eng-life",
                name="Lifecycle lab",
                created_at="2026-09-27T23:00:00+00:00",
                authorization_reference="approval://eng-life",
                status="planned",
            ))
            self.assertEqual(created.status, "planned")
            self.assertEqual(workspace.update_status("eng-life", "active").status, "active")
            self.assertEqual(workspace.update_status("eng-life", "paused").status, "paused")
            self.assertEqual(workspace.update_status("eng-life", "active").status, "active")
            self.assertEqual(workspace.update_status("eng-life", "completed").status, "completed")
            self.assertEqual(workspace.update_status("eng-life", "archived").status, "archived")

    def test_invalid_status_transition_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-workspace-") as directory:
            workspace = LocalWorkspace(directory)
            workspace.create_engagement(EngagementMetadata(
                engagement_id="eng-life",
                name="Lifecycle lab",
                created_at="2026-09-27T23:00:00+00:00",
                authorization_reference="approval://eng-life",
                status="planned",
            ))
            with self.assertRaisesRegex(ValueError, "planned -> completed"):
                workspace.update_status("eng-life", "completed")
            self.assertEqual(workspace.summary("eng-life").status, "planned")

    def test_timeline_is_chronological_and_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-workspace-") as directory:
            workspace = LocalWorkspace(directory)
            first = evidence("z-later-id", "red", "asset.observation")
            second = EvidenceRecord(
                engagement_id="eng-1",
                evidence_id="a-earlier-id",
                source_night="red",
                evidence_type="service.observation",
                observed_at="2026-09-27T22:59:00+00:00",
                provenance="fixture://red/a-earlier-id",
                data={"reference": "a-earlier-id"},
                limitations=("fixture only",),
            )
            workspace.merge_envelope(EngagementEnvelope(
                "eng-1", (first, second), metadata()
            ))
            timeline = workspace.timeline("eng-1")
            self.assertEqual(
                tuple(item.evidence_id for item in timeline),
                ("a-earlier-id", "z-later-id"),
            )
            self.assertEqual(timeline[0].provenance, "fixture://red/a-earlier-id")

    def test_two_night_producers_compose_in_one_workspace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-workspace-") as directory:
            workspace = LocalWorkspace(directory)
            red = EngagementEnvelope(
                "eng-1",
                (evidence("red-1", "red", "identity.directory-snapshot"),),
                metadata(),
            )
            blue = EngagementEnvelope(
                "eng-1",
                (evidence("blue-1", "blue", "alert.observation"),),
                metadata(),
            )
            self.assertTrue(workspace.merge_envelope(red).applied)
            self.assertTrue(workspace.merge_envelope(blue).applied)

            summary = workspace.summary("eng-1")
            self.assertEqual(summary.source_nights, ("blue", "red"))
            self.assertEqual(summary.record_count, 2)
            self.assertEqual(
                summary.evidence_types,
                ("alert.observation", "identity.directory-snapshot"),
            )
            breakdown = workspace.evidence_breakdown("eng-1")
            self.assertEqual(
                breakdown.source_night_counts,
                (("blue", 1), ("red", 1)),
            )

    def test_workspace_reopens_without_night_runtime_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-workspace-") as directory:
            LocalWorkspace(directory).merge_envelope(EngagementEnvelope(
                "eng-1",
                (evidence("red-1", "red", "asset.observation"),),
                metadata(),
            ))
            reopened = LocalWorkspace(directory)
            self.assertEqual(reopened.summary("eng-1").record_count, 1)
            self.assertEqual(reopened.summary("eng-1").source_nights, ("red",))

    def test_conflicting_merge_reports_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-workspace-") as directory:
            workspace = LocalWorkspace(directory)
            original = evidence("shared-id", "red", "asset.observation")
            workspace.merge_envelope(EngagementEnvelope(
                "eng-1", (original,), metadata()
            ))
            conflict = EvidenceRecord(
                engagement_id="eng-1",
                evidence_id="shared-id",
                source_night="red",
                evidence_type="asset.observation",
                observed_at="2026-09-27T23:01:00+00:00",
                provenance="fixture://changed",
                data={"reference": "changed"},
            )
            report = workspace.merge_envelope(EngagementEnvelope(
                "eng-1", (conflict,), metadata()
            ))
            self.assertFalse(report.applied)
            self.assertEqual(report.evidence_conflicts, ("shared-id",))
            self.assertEqual(workspace.envelope("eng-1").records, (original,))

    def test_metadata_conflict_is_reported_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-workspace-") as directory:
            workspace = LocalWorkspace(directory)
            workspace.merge_envelope(EngagementEnvelope(
                "eng-1", (), metadata()
            ))
            report = workspace.merge_envelope(EngagementEnvelope(
                "eng-1", (), metadata("Changed")
            ))
            self.assertFalse(report.applied)
            self.assertTrue(report.metadata_conflict)
            self.assertEqual(workspace.envelope("eng-1").metadata, metadata())

    def test_export_import_file_round_trip(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-workspace-") as directory:
            root = Path(directory)
            source = LocalWorkspace(root / "source")
            target = LocalWorkspace(root / "target")
            source.merge_envelope(EngagementEnvelope(
                "eng-1",
                (
                    evidence("red-1", "red", "asset.observation"),
                    evidence("blue-1", "blue", "alert.observation"),
                ),
                metadata(),
            ))
            exported = root / "exchange" / "eng-1.json"
            source.export_file("eng-1", exported)
            report = target.import_file(exported)
            self.assertTrue(report.applied)
            self.assertEqual(
                target.envelope("eng-1"),
                source.envelope("eng-1"),
            )

    def test_unknown_engagement_read_and_export_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-workspace-") as directory:
            workspace = LocalWorkspace(directory)
            with self.assertRaisesRegex(ValueError, "engagement not found"):
                workspace.summary("missing")
            with self.assertRaisesRegex(ValueError, "engagement not found"):
                workspace.export_file("missing", Path(directory) / "missing.json")

    def test_workspace_root_cannot_be_a_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nightrecon-workspace-") as directory:
            path = Path(directory) / "not-a-directory"
            path.write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "directory"):
                LocalWorkspace(path)


if __name__ == "__main__":
    unittest.main()
