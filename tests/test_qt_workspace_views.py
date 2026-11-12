"""Offline tests for meaningful, redacted Qt workspace navigation."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "red-night"))

from red_night_app.operations_read_model import OperationsSnapshot
from red_night_app.qt_operations_bridge import present_operations
from red_night_app.qt_workspace_views import WORKSPACES, workspace_summary


class QtWorkspaceViewsTests(unittest.TestCase):
    def test_disconnected_views_are_explicitly_unavailable(self):
        view = present_operations(None)
        for index in range(len(WORKSPACES)):
            result = workspace_summary(index, view)
            self.assertIn("READ-ONLY", result)
            self.assertNotIn("Run scan", result)
        self.assertIn("UNAVAILABLE", workspace_summary(6, view))
        self.assertIn("—", workspace_summary(4, view))

    def test_authority_findings_and_audit_have_useful_separate_views(self):
        snapshot = OperationsSnapshot(
            "sensitive-engagement-123", "ACTIVE", 4,
            ("token=secret-value audit body",),
            ("private-host | rule | review | evidence-secret",),
            ("sensitive source warning",),
        )
        view = present_operations(snapshot)
        operations = workspace_summary(0, view, warnings=snapshot.warnings)
        findings = workspace_summary(4, view, warnings=snapshot.warnings)
        audit = workspace_summary(6, view, warnings=snapshot.warnings)
        self.assertIn("Remaining authorised actions: 4", operations)
        self.assertIn("Reviewed finding records: 1", findings)
        self.assertIn("Recorded events: 1", audit)
        self.assertIn("Snapshot limitations: 1", audit)
        for result in (operations, findings, audit):
            for secret in ("secret-value", "private-host", "sensitive-engagement-123", "sensitive source warning"):
                self.assertNotIn(secret, result)

    def test_unimplemented_workspaces_are_not_misrepresented(self):
        view = present_operations(None)
        for index in (1, 2, 3):
            self.assertIn("not connected", workspace_summary(index, view))
            self.assertIn("No live telemetry", workspace_summary(index, view))

    def test_reporting_workspace_is_readonly_preview_not_unimplemented(self):
        result = workspace_summary(5, present_operations(None))
        self.assertIn("READ-ONLY REPORT PREVIEW", result)
        self.assertIn("No export, scan, approval or modification", result)
        self.assertNotIn("not connected", result)

    def test_invalid_index_and_raw_snapshot_are_rejected(self):
        view = present_operations(None)
        for index in (-1, 7, 999):
            with self.assertRaises(ValueError):
                workspace_summary(index, view)
        with self.assertRaises(TypeError):
            workspace_summary(0, object())

    def test_qt_navigation_uses_presenter_not_placeholder(self):
        shell = (Path(__file__).resolve().parents[1] /
                 "packages/red-night/red_night_app/qt_operations_shell.py").read_text(encoding="utf-8")
        self.assertIn("workspace_summary(index, view, warnings=snapshot_warnings)", shell)
        self.assertIn("workspace_summary(0, view, warnings=snapshot_warnings)", shell)
        self.assertNotIn("No engagement connected.\\nNo live evidence has been loaded.", shell)
        self.assertIn("control.setEnabled(False)", shell)
