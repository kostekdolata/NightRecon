import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "red-night"))
from red_night_app.assessment_preflight import plan_assessment


class TestAssessmentPreflight(unittest.TestCase):
    def test_run_all_is_explicitly_not_authorised(self):
        item = plan_assessment(engagement_id="lab-1", targets_text="192.0.2.4",
                               mode="all", selected_engines=())
        self.assertIn("NOT AUTHORISED", item.as_text())
        self.assertEqual(len(item.engines), 5)
        self.assertIn("Engagement authorisation and permitted capability not verified", item.issues)

    def test_custom_mode_does_not_include_unselected_engines(self):
        item = plan_assessment(engagement_id="lab", targets_text="192.0.2.1",
                               mode="custom", selected_engines=("Nmap",))
        self.assertEqual(item.engines, ("Nmap",))
        self.assertNotIn("Metasploit", item.as_text())

    def test_injection_cannot_be_treated_as_target(self):
        item = plan_assessment(engagement_id="lab", targets_text="192.0.2.1 --script unsafe",
                               mode="custom", selected_engines=("Nmap",))
        self.assertFalse(item.targets)
        self.assertTrue(any("Unsupported target" in x for x in item.issues))

    def test_unknown_engine_fails_closed(self):
        with self.assertRaises(ValueError):
            plan_assessment(engagement_id="lab", targets_text="192.0.2.1",
                            mode="custom", selected_engines=("shell",))

    def test_rejects_oversize_targets(self):
        with self.assertRaises(ValueError):
            plan_assessment(engagement_id="lab", targets_text="x" * 8193,
                            mode="all", selected_engines=())
