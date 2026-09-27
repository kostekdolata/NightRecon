"""Red Night's public entry point retains the edition's command boundary."""

import contextlib
import io
import unittest
from unittest.mock import patch

from nightrecon.red_night import main


class RedNightLauncherTests(unittest.TestCase):
    def test_explicit_allowed_command_routes_to_red(self):
        with patch("nightrecon.red_night.run_edition_cli") as gateway:
            main(("scan", "127.0.0.1", "--scope", "127.0.0.1"))
        gateway.assert_called_once_with(
            "red", ("scan", "127.0.0.1", "--scope", "127.0.0.1")
        )

    def test_process_arguments_are_used_by_default(self):
        with patch("sys.argv", ["red-night", "--help"]):
            with patch("nightrecon.red_night.run_edition_cli") as gateway:
                main()
        gateway.assert_called_once_with("red", ["--help"])

    def test_unowned_commands_fail_before_reaching_legacy_cli(self):
        error = io.StringIO()
        with patch("nightrecon.edition_gateway.legacy_main") as legacy:
            with contextlib.redirect_stderr(error):
                with self.assertRaises(SystemExit) as exit_status:
                    main(("unknown-command",))
        self.assertEqual(exit_status.exception.code, 2)
        self.assertIn("Command is not available in this edition", error.getvalue())
        legacy.assert_not_called()

    def test_no_arguments_show_only_red_owned_commands(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main(())
        self.assertIn("NightRecon Red Night command boundary", output.getvalue())
        self.assertIn("Standalone edition packaging is not yet available", output.getvalue())


if __name__ == "__main__":
    unittest.main()
