"""Tests for Red release SBOM contracts."""

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
RED_APP_ROOT = ROOT / "packages" / "red-night"
if str(RED_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(RED_APP_ROOT))

from red_night_app.sbom import build_red_release_sbom


class RedReleaseSbomTests(unittest.TestCase):
    def test_required_red_components_are_deterministic(self):
        versions = {
            "nightrecon-shared-core": "0.43.0",
            "nightrecon-red-engine": "0.43.0",
            "nightrecon-red-night": "0.43.0",
        }
        digests = {name: "a" * 64 for name in versions}

        result = build_red_release_sbom(
            release_version="0.44.0-dev",
            package_versions=versions,
            package_sha256=digests,
        )

        self.assertEqual(
            tuple(item.name for item in result.components),
            tuple(sorted(versions)),
        )
        self.assertNotIn("secret", result.to_json().lower())

    def test_missing_required_component_fails_closed(self):
        versions = {
            "nightrecon-shared-core": "0.43.0",
            "nightrecon-red-engine": "0.43.0",
        }
        digests = {name: "b" * 64 for name in versions}

        with self.assertRaisesRegex(ValueError, "nightrecon-red-night"):
            build_red_release_sbom(
                release_version="0.44.0-dev",
                package_versions=versions,
                package_sha256=digests,
            )

    def test_digest_set_must_match_version_set(self):
        with self.assertRaisesRegex(ValueError, "component sets"):
            build_red_release_sbom(
                release_version="0.44.0-dev",
                package_versions={"nightrecon-shared-core": "0.43.0"},
                package_sha256={},
            )


if __name__ == "__main__":
    unittest.main()
