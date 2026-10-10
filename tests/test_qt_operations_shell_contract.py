"""Qt shell is optional and display-only; import requires no Qt installation."""
import ast
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "red-night"))
from red_night_app import qt_operations_shell as shell


class TestQtOperationsShell(unittest.TestCase):
    def test_shell_parses_and_exposes_professional_navigation(self):
        ast.parse(Path(shell.__file__).read_text(encoding="utf-8"))
        self.assertEqual(len(shell.NAVIGATION), 7)
        self.assertIn("Engine Console", shell.NAVIGATION)
        self.assertIn("Audit & Control", shell.NAVIGATION)

    def test_style_matches_locked_black_and_crimson_direction(self):
        self.assertEqual(shell.COLORS["background"], "#07080D")
        self.assertEqual(shell.COLORS["accent"], "#FF304D")
        self.assertIn("QSplitter::handle", shell.STYLESHEET)

    def test_execution_disallowed_and_panels_scrollable(self):
        source = Path(shell.__file__).read_text(encoding="utf-8")
        self.assertIn("start.setEnabled(False)", source)
        self.assertIn("scroller.setWidgetResizable(True)", source)
        self.assertIn("Qt.ScrollBarAsNeeded", source)
        self.assertIn("QSplitter(Qt.Horizontal)", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("execute_atomically_governed", source)
