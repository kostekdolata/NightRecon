"""Tests for bounded Red Night update recovery planning."""

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
RED_APP_ROOT = ROOT / "packages" / "red-night"
if str(RED_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(RED_APP_ROOT))

from red_night_app.update_recovery import build_red_update_recovery_plan


class RedUpdateRecoveryTests(unittest.TestCase):
    def build(self, **overrides):
        values = {
            "current_version": "0.43.0",
            "target_version": "0.44.0",
            "signed_bundle_verified": True,
            "package_compatibility_verified": True,
            "workspace_locked": True,
            "rollback_artifact_verified": True,
        }
        values.update(overrides)
        return build_red_update_recovery_plan(**values)

    def test_verified_update_plan_preserves_workspace_and_rollback(self):
        plan = self.build()

        self.assertEqual(plan.workspace_policy, "preserve-encrypted-workspace")
        self.assertEqual(plan.max_unconfirmed_boots, 1)
        self.assertEqual(plan.authorization_effect, "none")
        self.assertIn("explicitly-confirm-new-image", plan.stage_steps)
        self.assertIn("select-previous-verified-image", plan.rollback_steps)

    def test_each_missing_prerequisite_fails_closed(self):
        for field in (
            "signed_bundle_verified",
            "package_compatibility_verified",
            "workspace_locked",
            "rollback_artifact_verified",
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.build(**{field: False})

    def test_same_version_update_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "differ"):
            self.build(target_version="0.43.0")


if __name__ == "__main__":
    unittest.main()
