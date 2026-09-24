"""CLI tests for the NightRecon assessment-check catalog."""

import contextlib
import io
import sys
import unittest
from unittest.mock import patch

from nightrecon.assessment_engine import (
    AssessmentCheckMetadata,
    CheckIntrusiveness,
)
from nightrecon.check_catalog import CheckCatalogResult
from nightrecon.cli import main


class _Check:
    def __init__(
        self,
        check_id,
        *,
        family,
        intrusiveness,
        tags=(),
        supported_services=(),
    ):
        self.metadata = AssessmentCheckMetadata(
            check_id=check_id,
            name=check_id,
            family=family,
            description="Test check.",
            intrusiveness=intrusiveness,
            tags=tags,
            supported_services=supported_services,
        )

    def run(self, context):
        return ()


class CliCheckCatalogTests(unittest.TestCase):
    def test_checks_list_displays_installed_check_metadata(self):
        discovery = CheckCatalogResult(
            checks=(
                _Check(
                    "web.headers",
                    family="web",
                    intrusiveness=CheckIntrusiveness.PASSIVE,
                    tags=("http", "headers"),
                    supported_services=("http", "https"),
                ),
            ),
        )

        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            ["nightrecon", "checks", "list"],
        ):
            with patch(
                "nightrecon.cli.load_check_catalog",
                return_value=discovery,
            ):
                with contextlib.redirect_stdout(stdout):
                    with contextlib.redirect_stderr(stderr):
                        main()

        output = stdout.getvalue()

        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("web.headers", output)
        self.assertIn("family=web", output)
        self.assertIn("intrusiveness=passive", output)
        self.assertIn("tags=http,headers", output)
        self.assertIn("services=http,https", output)

    def test_checks_list_filters_by_family(self):
        discovery = CheckCatalogResult(
            checks=(
                _Check(
                    "web.headers",
                    family="web",
                    intrusiveness=CheckIntrusiveness.PASSIVE,
                ),
                _Check(
                    "tls.certificate",
                    family="tls",
                    intrusiveness=CheckIntrusiveness.PASSIVE,
                ),
            ),
        )

        stdout = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "checks",
                "list",
                "--family",
                "web",
            ],
        ):
            with patch(
                "nightrecon.cli.load_check_catalog",
                return_value=discovery,
            ):
                with contextlib.redirect_stdout(stdout):
                    main()

        output = stdout.getvalue()

        self.assertIn("web.headers", output)
        self.assertNotIn("tls.certificate", output)

    def test_checks_list_reports_plugin_errors_without_failing(self):
        discovery = CheckCatalogResult(
            checks=(),
            errors=("broken: import failed",),
        )

        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            ["nightrecon", "checks", "list"],
        ):
            with patch(
                "nightrecon.cli.load_check_catalog",
                return_value=discovery,
            ):
                with contextlib.redirect_stdout(stdout):
                    with contextlib.redirect_stderr(stderr):
                        main()

        self.assertIn(
            "No assessment checks matched.",
            stdout.getvalue(),
        )
        self.assertIn(
            "Plugin error: broken: import failed",
            stderr.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
