"""Release metadata consistency checks for NightRecon."""

from pathlib import Path
import contextlib
import io
import sys
import tomllib
import unittest
from unittest.mock import patch

from nightrecon import __version__
from nightrecon.cli import main


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.31.0"


class ReleaseMetadataTests(unittest.TestCase):
    def test_package_version_matches_release(self):
        with (ROOT / "pyproject.toml").open("rb") as handle:
            project = tomllib.load(handle)["project"]

        self.assertEqual(project["version"], EXPECTED_VERSION)
        self.assertEqual(__version__, EXPECTED_VERSION)

    def test_cli_reports_package_version(self):
        output = io.StringIO()
        with patch.object(sys, "argv", ["nightrecon", "--version"]):
            with contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit) as result:
                    main()

        self.assertEqual(result.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), f"NightRecon {EXPECTED_VERSION}")

    def test_readme_current_version_matches_package(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn(f"**v{EXPECTED_VERSION}**", readme)
        self.assertIn("v0.31 Identity Graph Foundation", readme)

    def test_roadmap_marks_foundation_released(self):
        roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")

        self.assertIn("### v0.31.0 — Identity Graph Foundation", roadmap)
        self.assertIn(
            "Status: released, tagged, and verified stable.",
            roadmap,
        )
        self.assertIn("guarded release-tag allowlist", roadmap)


if __name__ == "__main__":
    unittest.main()
