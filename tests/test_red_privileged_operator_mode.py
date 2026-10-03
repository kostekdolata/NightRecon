from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import red_night_app
from nightrecon_red_engine import red_cli


class RedPrivilegedOperatorModeTests(unittest.TestCase):
    def test_successful_platform_privilege_sets_operator_mode_for_all_platforms(self) -> None:
        with (
            patch("red_night_app.privilege.require_platform_privilege") as require_privilege,
            patch("nightrecon_red_engine.red_cli.main") as run_red_night,
            patch.dict(os.environ, {}, clear=False),
        ):
            os.environ.pop("REDNIGHT_PRIVILEGED_OPERATOR_MODE", None)

            red_night_app.main()

            require_privilege.assert_called_once_with()
            self.assertEqual(
                os.environ.get("REDNIGHT_PRIVILEGED_OPERATOR_MODE"),
                "1",
            )
            run_red_night.assert_called_once_with()

    def test_operator_mode_bypasses_secondary_workspace_guard(self) -> None:
        with patch.dict(
            os.environ,
            {"REDNIGHT_PRIVILEGED_OPERATOR_MODE": "1"},
            clear=False,
        ):
            red_cli._authorize_guarded_execution(
                ("scan", "127.0.0.1", "--scope", "127.0.0.1"),
                workspace_root=None,
                engagement_id=None,
                approved=False,
            )

    def test_engine_guard_still_fails_closed_without_operator_mode(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("REDNIGHT_PRIVILEGED_OPERATOR_MODE", None)
            with self.assertRaises(SystemExit):
                red_cli._authorize_guarded_execution(
                    ("scan", "127.0.0.1", "--scope", "127.0.0.1"),
                    workspace_root=None,
                    engagement_id=None,
                    approved=False,
                )


if __name__ == "__main__":
    unittest.main()
