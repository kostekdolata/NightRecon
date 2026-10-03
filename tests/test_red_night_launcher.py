"""Red Night's public entry point retains the edition's command boundary."""

import contextlib
import io
import tempfile
import unittest
from unittest.mock import patch

from nightrecon.red_night import main
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_shared_core.workspace import LocalWorkspace


class RedNightLauncherTests(unittest.TestCase):
    def test_passive_allowed_command_routes_to_red(self):
        arguments = ("assets", "list")
        with patch("nightrecon_red_engine.red_cli._command_main") as command_main:
            main(arguments)
        command_main.assert_called_once_with(arguments)

    def test_active_command_requires_engagement_guard(self):
        error = io.StringIO()
        with patch("nightrecon_red_engine.red_cli._command_main") as command_main:
            with contextlib.redirect_stderr(error):
                with self.assertRaises(SystemExit) as exit_status:
                    main(("scan", "127.0.0.1", "--scope", "127.0.0.1"))
        self.assertEqual(exit_status.exception.code, 2)
        self.assertIn("requires --guard-workspace-root and --guard-engagement-id", error.getvalue())
        command_main.assert_not_called()

    def test_active_command_runs_only_after_authorized_guard(self):
        with tempfile.TemporaryDirectory(prefix="red-night-guard-") as directory:
            workspace = LocalWorkspace(directory)
            workspace.create_engagement(EngagementMetadata(
                engagement_id="eng-guard",
                name="Guarded execution",
                created_at="2026-09-28T00:00:00+00:00",
                authorization_reference="approval://eng-guard",
                status="active",
            ))
            workspace.set_execution_policy(EngagementExecutionPolicy(
                engagement_id="eng-guard",
                scope=("127.0.0.1",),
                valid_from="2026-01-01T00:00:00+00:00",
                valid_until="2030-01-01T00:00:00+00:00",
                max_actions=2,
                permitted_capabilities=("scan",),
            ))
            arguments = (
                "scan", "127.0.0.1", "--scope", "127.0.0.1",
                "--guard-workspace-root", directory,
                "--guard-engagement-id", "eng-guard",
            )
            with patch("nightrecon_red_engine.red_cli._command_main") as command_main:
                main(arguments)
            command_main.assert_called_once_with(
                ("scan", "127.0.0.1", "--scope", "127.0.0.1")
            )
            persisted = LocalWorkspace(directory)
            self.assertEqual(
                persisted.execution_policy("eng-guard").actions_used, 1
            )
            self.assertEqual(
                persisted.authorization_audit("eng-guard")[-1].reason_code,
                "authorized",
            )

    def test_process_arguments_are_used_by_default(self):
        output = io.StringIO()
        with patch("sys.argv", ["red-night", "--help"]):
            with contextlib.redirect_stdout(output):
                main()
        self.assertIn("NightRecon Red Night command boundary", output.getvalue())

    def test_unowned_commands_fail_before_command_execution(self):
        error = io.StringIO()
        with patch("nightrecon_red_engine.red_cli._command_main") as command_main:
            with contextlib.redirect_stderr(error):
                with self.assertRaises(SystemExit) as exit_status:
                    main(("unknown-command",))
        self.assertEqual(exit_status.exception.code, 2)
        self.assertIn("Command is not available in this edition", error.getvalue())
        command_main.assert_not_called()

    def test_no_arguments_show_only_red_owned_commands(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main(())
        self.assertIn("NightRecon Red Night command boundary", output.getvalue())
        self.assertNotIn("Standalone edition packaging is not yet available", output.getvalue())


if __name__ == "__main__":
    unittest.main()
