from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from red_night_app import windows_launcher


REPOSITORY = Path(__file__).resolve().parents[1]
ISS = REPOSITORY / "installer" / "windows" / "red-night.iss"
BUILD = REPOSITORY / "installer" / "windows" / "build_installer.ps1"
RED_CLI = REPOSITORY / "packages" / "red-engine" / "nightrecon_red_engine" / "red_cli.py"
WORKFLOW = REPOSITORY / ".github" / "workflows" / "red-windows-installer.yml"
LAUNCHER = REPOSITORY / "installer" / "windows" / "launch-red-night.ps1"


class RedWindowsInstallerContractTests(unittest.TestCase):
    def test_installer_is_per_user_and_preserves_red_data(self) -> None:
        text = ISS.read_text(encoding="utf-8")
        self.assertIn("PrivilegesRequired=lowest", text)
        self.assertIn(r"DefaultDirName={localappdata}\Programs\Red Night", text)
        self.assertIn("uninsneveruninstall", text)
        self.assertIn(r"{localappdata}\NightRecon\RedNight\workspaces", text)
        self.assertNotIn(
            r'Name: "{localappdata}\NightRecon\RedNight"; Type: filesandordirs',
            text,
        )

    def test_installer_has_shortcuts(self) -> None:
        text = ISS.read_text(encoding="utf-8")
        self.assertIn(r"{autoprograms}\Red Night", text)
        self.assertIn(r"{autodesktop}\Red Night", text)
        self.assertIn('Name: "desktopicon"', text)
        self.assertIn(r'Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"', text)
        self.assertIn(r'launch-red-night.ps1', text)
        self.assertNotIn('Filename: "{cmd}"', text)

    def test_persistent_launcher_elevates_shell_and_keeps_it_open(self) -> None:
        text = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("Start-Process", text)
        self.assertIn("-Verb RunAs", text)
        self.assertIn("-NoExit", text)
        self.assertIn('RedNight.exe") --help', text)
        self.assertIn('Use: RedNight.exe <command> [options]', text)

    def test_red_cli_has_no_stale_packaging_unavailable_message(self) -> None:
        text = RED_CLI.read_text(encoding="utf-8")
        self.assertNotIn("Standalone edition packaging is not yet available.", text)

    def test_windows_installer_release_version_is_0_45_4(self) -> None:
        iss = ISS.read_text(encoding="utf-8")
        build = BUILD.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('#define MyAppVersion "0.46.8"', iss)
        self.assertIn("VersionInfoVersion=0.46.8.0", iss)
        self.assertIn('[string]$Version = "0.46.8"', build)
        self.assertIn('build_installer.ps1 -Version "0.46.8"', workflow)
        self.assertIn("RedNight-0.46.8-Windows-x64-Setup.exe", workflow)
        self.assertNotIn("RedNight-0.45.2-Windows-x64-Setup.exe", workflow)

    def test_build_uses_exact_red_package_set_and_integrity_outputs(self) -> None:
        text = BUILD.read_text(encoding="utf-8")
        for package in ("shared-core", "red-engine", "red-night"):
            self.assertIn(f"packages\\{package}", text)
        self.assertIn("--copy-metadata nightrecon-shared-core", text)
        self.assertIn("--copy-metadata nightrecon-red-engine", text)
        self.assertIn("--copy-metadata nightrecon-red-night", text)
        self.assertIn("cyclonedx_py environment", text)
        self.assertIn("create_manifest.py", text)
        self.assertIn("launch-red-night.ps1", text)
        self.assertIn("Red package set is mixed-version", text)

    def test_deployment_info_is_non_operational(self) -> None:
        with patch.object(
            windows_launcher.metadata,
            "version",
            side_effect=lambda _name: "0.43.0",
        ):
            payload = windows_launcher.deployment_info()
        self.assertEqual(payload["product"], "Red Night")
        self.assertEqual(payload["platform"], "windows")
        self.assertFalse(payload["operational"])
        self.assertEqual(payload["authorization_effect"], "none")
        self.assertTrue(payload["package_compatible"])

    def test_build_info_reader_rejects_non_object_json(self) -> None:
        original = windows_launcher._application_path
        try:
            with tempfile.TemporaryDirectory() as root:
                path = Path(root)
                (path / windows_launcher.BUILD_INFO_FILENAME).write_text(
                    json.dumps(["not", "an", "object"]),
                    encoding="utf-8",
                )
                windows_launcher._application_path = lambda: path
                self.assertEqual(
                    windows_launcher._build_info(),
                    {"available": False, "valid": False},
                )
        finally:
            windows_launcher._application_path = original


if __name__ == "__main__":
    unittest.main()
