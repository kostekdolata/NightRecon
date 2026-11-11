"""Qt overview bridge regression tests; no Qt installation or execution needed."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "red-night"))
from red_night_app.operations_read_model import OperationsSnapshot
from red_night_app.qt_operations_bridge import present_operations
from red_night_app import qt_operations_shell


class QtReadOnlyBridgeTests(unittest.TestCase):
    def test_no_engagement_is_unknown_not_zero_or_active(self):
        view = present_operations(None)
        self.assertEqual(view.authority_label, "UNAVAILABLE")
        self.assertEqual(view.findings_label, "—")
        self.assertEqual(view.events_label, "—")
        self.assertEqual(view.actions_label, "Unknown")

    def test_snapshot_counts_without_disclosing_evidence_or_identifiers(self):
        snapshot = OperationsSnapshot(
            "private-engagement", "ACTIVE", 4,
            ("SECRET audit event", "another event"),
            ("sensitive finding",), ("warning",),
        )
        view = present_operations(snapshot)
        self.assertEqual(view.authority_label, "ACTIVE")
        self.assertEqual(view.actions_label, "4")
        self.assertEqual(view.events_label, "2")
        self.assertEqual(view.findings_label, "1")
        self.assertNotIn("SECRET", str(view))
        self.assertNotIn("private-engagement", str(view))
        self.assertNotIn("sensitive", str(view))

    def test_revoked_or_unrecognized_authority_never_claims_budget(self):
        for status in ("REVOKED", "UNAVAILABLE", "anything"):
            with self.subTest(status=status):
                view = present_operations(OperationsSnapshot(
                    "eng", status, 12, (), (), (),
                ))
                self.assertEqual(view.actions_label, "Unknown")
                self.assertNotEqual(view.authority_label, "ACTIVE")

    def test_invalid_input_fails_closed(self):
        with self.assertRaises(TypeError):
            present_operations({"status": "ACTIVE"})

    def test_shell_injects_snapshot_without_enabling_execution(self):
        source = Path(qt_operations_shell.__file__).read_text(encoding="utf-8")
        self.assertIn("view = present_operations(operations_snapshot)", source)
        self.assertIn("view.findings_label", source)
        self.assertIn("view.events_label", source)
        self.assertIn("control.setEnabled(False)", source)
        self.assertIn("button.setEnabled(False)", source)
        self.assertNotIn("subprocess", source)


if __name__ == "__main__":
    unittest.main()
