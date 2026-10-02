"""Tests for Red deployment composition compatibility."""

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
RED_APP_ROOT = ROOT / "packages" / "red-night"
if str(RED_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(RED_APP_ROOT))

from red_night_app.composition import (
    RED_REQUIRED_PACKAGE_VERSIONS,
    evaluate_red_composition_compatibility,
)


class RedCompositionCompatibilityTests(unittest.TestCase):
    def test_current_red_stack_and_schema_are_compatible(self):
        result = evaluate_red_composition_compatibility(
            dict(RED_REQUIRED_PACKAGE_VERSIONS)
        )
        self.assertTrue(result.compatible)
        self.assertEqual(result.reason_code, "compatible")
        self.assertEqual(result.to_dict()["authorization_effect"], "none")

    def test_missing_required_distribution_fails_closed(self):
        versions = dict(RED_REQUIRED_PACKAGE_VERSIONS)
        versions.pop("nightrecon-red-engine")

        result = evaluate_red_composition_compatibility(versions)

        self.assertFalse(result.compatible)
        self.assertEqual(result.reason_code, "missing-red-package")

    def test_version_drift_fails_closed(self):
        versions = dict(RED_REQUIRED_PACKAGE_VERSIONS)
        versions["nightrecon-red-engine"] = "9.9.9"

        result = evaluate_red_composition_compatibility(versions)

        self.assertFalse(result.compatible)
        self.assertEqual(result.reason_code, "red-package-version-mismatch")

    def test_future_schema_fails_closed(self):
        result = evaluate_red_composition_compatibility(
            dict(RED_REQUIRED_PACKAGE_VERSIONS),
            engagement_schema_version=999,
        )

        self.assertFalse(result.compatible)
        self.assertEqual(result.reason_code, "unsupported-engagement-schema")

    def test_peer_packages_do_not_change_red_compatibility(self):
        versions = dict(RED_REQUIRED_PACKAGE_VERSIONS)
        versions["nightrecon-white-night"] = "0.1.0a6"

        self.assertTrue(
            evaluate_red_composition_compatibility(versions).compatible
        )


if __name__ == "__main__":
    unittest.main()
