"""Edition entry points fail closed before dispatching existing commands."""

import contextlib
import io
import json
import unittest
from unittest.mock import patch

from nightrecon.edition_catalog import EDITIONS
from nightrecon.edition_gateway import (
    EditionRouteError,
    available_commands,
    run_edition_cli,
)


class EditionGatewayTests(unittest.TestCase):
    def test_every_catalog_edition_has_an_explicit_route(self):
        for edition in EDITIONS:
            self.assertIn("editions", available_commands(edition.slug))

    def test_unknown_edition_fails_closed(self):
        with patch("nightrecon.edition_gateway.legacy_main") as legacy:
            with self.assertRaises(EditionRouteError):
                run_edition_cli("grey", ("discover",))
        legacy.assert_not_called()

    def test_unimplemented_editions_cannot_invoke_active_commands(self):
        with patch("nightrecon.edition_gateway.legacy_main") as legacy:
            for edition in ("white", "blue", "purple", "black"):
                for command in ("scan", "discover", "infra", "crawl", "api"):
                    with self.subTest(edition=edition, command=command):
                        with self.assertRaises(EditionRouteError):
                            run_edition_cli(edition, (command, "127.0.0.1"))
        legacy.assert_not_called()

    def test_black_boundary_cannot_reuse_generic_cidr_discovery(self):
        with patch("nightrecon.edition_gateway.legacy_main") as legacy:
            for command in ("discover", "scan", "infra", "crawl", "checks"):
                with self.assertRaises(EditionRouteError):
                    run_edition_cli("black", (command, "127.0.0.1"))
            legacy.assert_not_called()

    def test_red_boundary_dispatches_existing_assessment_command(self):
        with patch("nightrecon.edition_gateway.legacy_main") as legacy:
            run_edition_cli("red", ("scan", "127.0.0.1", "--scope", "127.0.0.1"))
        legacy.assert_called_once_with(
            ("scan", "127.0.0.1", "--scope", "127.0.0.1")
        )

    def test_read_only_catalog_reaches_real_cli_through_gateway(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            run_edition_cli("white", ("editions", "--json"))
        self.assertEqual(len(json.loads(output.getvalue())), 5)

    def test_unknown_or_prefixed_command_never_reaches_legacy_cli(self):
        with patch("nightrecon.edition_gateway.legacy_main") as legacy:
            for argv in (("sacn",), ("--scope", "127.0.0.1", "scan")):
                with self.assertRaises(EditionRouteError):
                    run_edition_cli("red", argv)
        legacy.assert_not_called()

    def test_help_lists_only_commands_owned_by_the_edition(self):
        output = io.StringIO()
        with patch("nightrecon.edition_gateway.legacy_main") as legacy:
            with contextlib.redirect_stdout(output):
                run_edition_cli("black", ("--help",))
        legacy.assert_not_called()
        self.assertIn("editions", output.getvalue())
        self.assertNotIn("discover", output.getvalue())
        self.assertNotIn("infra", output.getvalue())
        self.assertIn("not yet available", output.getvalue())


if __name__ == "__main__":
    unittest.main()
