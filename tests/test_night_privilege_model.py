"""Night privilege and Red platform privilege contract tests."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
RED_APP_ROOT = ROOT / "packages" / "red-night"
if str(RED_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(RED_APP_ROOT))

from red_night_app.privilege import (  # noqa: E402
    PRIVILEGE_POLICY,
    is_platform_privileged,
    require_platform_privilege,
)


class RedPlatformPrivilegeTests(unittest.TestCase):
    def test_policy_name_is_stable(self):
        self.assertEqual(PRIVILEGE_POLICY, "required-platform-privileged")

    def test_posix_root_is_privileged(self):
        with (
            patch("red_night_app.privilege.os.name", "posix"),
            patch("red_night_app.privilege.os.geteuid", return_value=0),
        ):
            self.assertTrue(is_platform_privileged())

    def test_posix_non_root_is_not_privileged(self):
        with (
            patch("red_night_app.privilege.os.name", "posix"),
            patch("red_night_app.privilege.os.geteuid", return_value=1000),
        ):
            self.assertFalse(is_platform_privileged())

    def test_windows_administrator_is_privileged(self):
        fake_shell32 = type("Shell32", (), {"IsUserAnAdmin": lambda self: 1})()
        fake_windll = type("Windll", (), {"shell32": fake_shell32})()
        with (
            patch("red_night_app.privilege.os.name", "nt"),
            patch("red_night_app.privilege.ctypes.windll", fake_windll, create=True),
        ):
            self.assertTrue(is_platform_privileged())

    def test_windows_non_administrator_is_not_privileged(self):
        fake_shell32 = type("Shell32", (), {"IsUserAnAdmin": lambda self: 0})()
        fake_windll = type("Windll", (), {"shell32": fake_shell32})()
        with (
            patch("red_night_app.privilege.os.name", "nt"),
            patch("red_night_app.privilege.ctypes.windll", fake_windll, create=True),
        ):
            self.assertFalse(is_platform_privileged())

    def test_active_runtime_fails_closed_without_privilege(self):
        with patch(
            "red_night_app.privilege.is_platform_privileged",
            return_value=False,
        ):
            with self.assertRaises(PermissionError):
                require_platform_privilege()

    def test_active_runtime_accepts_privileged_execution(self):
        with patch(
            "red_night_app.privilege.is_platform_privileged",
            return_value=True,
        ):
            require_platform_privilege()


class NightPrivilegeModelDocumentTests(unittest.TestCase):
    def test_policy_covers_all_current_and_future_nights(self):
        text = (ROOT / "NIGHT_PRIVILEGE_MODEL.md").read_text(encoding="utf-8")
        for name in (
            "Red Night",
            "White Night",
            "Blue Night",
            "Purple Night",
            "Black Night",
            "any future NightRecon specialist Night",
        ):
            self.assertIn(name, text)

    def test_policy_covers_every_deployment_shape(self):
        text = (ROOT / "NIGHT_PRIVILEGE_MODEL.md").read_text(encoding="utf-8")
        self.assertIn("installed and launched on its own", text)
        self.assertIn("composed/full-stack NightRecon", text)
        self.assertIn("Live/bootable appliance", text)

    def test_policy_separates_privilege_from_authorization(self):
        text = (ROOT / "NIGHT_PRIVILEGE_MODEL.md").read_text(encoding="utf-8")
        self.assertIn("Privilege is not authorization", text)
        self.assertIn("engagement and target scope", text)
        self.assertIn("revocation and emergency stop", text)
        self.assertIn("destructive/high-impact operation gates", text)


if __name__ == "__main__":
    unittest.main()
