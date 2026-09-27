"""Release metadata consistency checks for NightRecon."""

from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.31.0"


class ReleaseMetadataTests(unittest.TestCase):
    def test_package_version_matches_release(self):
        with (ROOT / "pyproject.toml").open("rb") as handle:
            project = tomllib.load(handle)["project"]

        self.assertEqual(project["version"], EXPECTED_VERSION)

    def test_readme_current_version_matches_package(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn(f"**v{EXPECTED_VERSION}**", readme)
        self.assertIn("v0.31 Identity Graph Foundation", readme)

    def test_roadmap_marks_foundation_implementation_complete(self):
        roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")

        self.assertIn("### v0.31.0 — Identity Graph Foundation", roadmap)
        self.assertIn(
            "Status: implementation complete; release verification in progress.",
            roadmap,
        )
        self.assertIn("guarded release-tag allowlist", roadmap)


if __name__ == "__main__":
    unittest.main()
