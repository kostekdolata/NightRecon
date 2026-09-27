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
