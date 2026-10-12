"""Display-only desktop workspace contracts, including resize and scrolling."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
GUI = ROOT / "packages/red-night/red_night_app/assessment_desktop.py"
LAUNCHER = ROOT / "packages/red-night/red_night_app/windows_launcher.py"

class TestAssessmentDesktopContract(unittest.TestCase):
    def test_workspace_compiles_without_display(self):
        ast.parse(GUI.read_text(encoding="utf-8"))
    def test_window_resizable_and_scrollable(self):
        source = GUI.read_text(encoding="utf-8")
        self.assertIn('root.resizable(True, True)', source)
        self.assertIn('fill="both", expand=True', source)
        self.assertIn('create_window((0, 0)', source)
        self.assertIn('scrollregion=self.canvas.bbox("all")', source)
        self.assertIn('xscrollcommand=self.horizontal.set', source)
        self.assertIn('width=max(760, e.width)', source)
        self.assertNotIn('root.minsize(', source)
        self.assertIn('"<MouseWheel>"', source)
        self.assertIn('"<Button-4>"', source)
        self.assertIn('"<Button-5>"', source)
    def test_preview_never_launches_scan(self):
        source = GUI.read_text(encoding="utf-8")
        self.assertIn('state="disabled"', source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("execute_managed_nmap_discovery", source)
    def test_launcher_uses_non_elevated_workspace_and_preserves_cli(self):
        source = LAUNCHER.read_text(encoding="utf-8")
        self.assertLess(source.index('if not sys.argv[1:]:'), source.index('if not _is_windows_admin():'))
        self.assertIn('from . import main as run_red_night', source)
