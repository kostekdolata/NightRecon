"""Red Night's public entry point retains the edition's command boundary."""

import contextlib
import io
import unittest
from unittest.mock import patch

from nightrecon.red_night import main


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
        self.assertIn("requires --workspace-root and --engagement-id", error.getvalue())
        command_main.assert_not_called()

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
        self.assertIn("Standalone edition packaging is not yet available", output.getvalue())


if __name__ == "__main__":
    unittest.main()
