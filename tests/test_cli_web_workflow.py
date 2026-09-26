"""CLI tests for NightRecon v0.25 workflow surface."""

import contextlib
import io
import sys
import unittest
from http.cookiejar import CookieJar
from pathlib import Path
from unittest.mock import patch

from nightrecon.cli import main
from nightrecon.web_crawl import (
    CrawlPage,
    CrawlResult,
    WebFormInput,
    WebFormObservation,
)
from nightrecon.web_workflow import WorkflowState
from nightrecon.web_workflow_execution import (
    WorkflowNavigationResult,
)


def _crawl_result():
    return CrawlResult(
        start_url="https://example.test/",
        origin="https://example.test",
        pages=(
            CrawlPage(
                url="https://example.test/",
                status=200,
                content_type="text/html",
                byte_count=128,
                links=(
                    "https://example.test/dashboard",
                ),
                forms=(
                    WebFormObservation(
                        action="https://example.test/session",
                        method="POST",
                        inputs=(
                            WebFormInput(
                                name="username",
                                input_type="text",
                            ),
                            WebFormInput(
                                name="csrf_token",
                                input_type="hidden",
                            ),
                        ),
                    ),
                ),
            ),
        ),
        max_pages=50,
        max_bytes_per_page=1_048_576,
    )


class CliWebWorkflowTests(unittest.TestCase):
    def run_cli(self, *args):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            ["nightrecon", *args],
        ):
            with contextlib.redirect_stdout(stdout):
                with contextlib.redirect_stderr(stderr):
                    try:
                        main()
                        code = 0
                    except SystemExit as exc:
                        code = exc.code

        return code, stdout.getvalue(), stderr.getvalue()

    def test_workflow_is_disabled_by_default(self):
        crawl = _crawl_result()

        with patch(
            "nightrecon.cli.crawl_site",
            return_value=crawl,
        ):
            with patch(
                "nightrecon.cli.execute_workflow_navigation"
            ) as execute:
                with patch(
                    "nightrecon.cli.ResultStore"
                ) as store_class:
                    store_class.return_value.save_web_crawl_report.return_value = (
                        Path("results/crawl.json")
                    )

                    with patch(
                        "nightrecon.cli.NightReconLogger"
                    ):
                        code, stdout, stderr = self.run_cli(
                            "crawl",
                            "https://example.test/",
                            "--scope",
                            "example.test",
                        )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertNotIn(
            "Workflow Summary:",
            stdout,
        )
        execute.assert_not_called()
        (
            store_class.return_value
            .save_web_workflow_report
            .assert_not_called()
        )

    def test_workflow_plan_is_opt_in_and_saved_separately(self):
        crawl = _crawl_result()

        with patch(
            "nightrecon.cli.crawl_site",
            return_value=crawl,
        ):
            with patch(
                "nightrecon.cli.execute_workflow_navigation"
            ) as execute:
                with patch(
                    "nightrecon.cli.ResultStore"
                ) as store_class:
                    store_class.return_value.save_web_crawl_report.return_value = (
                        Path("results/crawl.json")
                    )
                    store_class.return_value.save_web_workflow_report.return_value = (
                        Path("results/crawl-workflow.json")
                    )

                    with patch(
                        "nightrecon.cli.NightReconLogger"
                    ):
                        code, stdout, stderr = self.run_cli(
                            "crawl",
                            "https://example.test/",
                            "--scope",
                            "example.test",
                            "--workflow",
                            "--workflow-max-actions",
                            "5",
                        )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "Workflow Summary: planned=1 forms=1 executions=0 successful=0",
            stdout,
        )
        self.assertIn(
            "WORKFLOW PLAN GET https://example.test/dashboard",
            stdout,
        )
        self.assertIn(
            "WORKFLOW FORM method=POST action=https://example.test/session",
            stdout,
        )
        self.assertIn(
            "csrf_token:anti-csrf",
            stdout,
        )
        execute.assert_not_called()

        report = (
            store_class.return_value
            .save_web_workflow_report
            .call_args.args[0]
        )
        self.assertEqual(
            report.max_actions,
            5,
        )
        self.assertEqual(
            len(report.planned_actions),
            1,
        )
        self.assertEqual(
            len(report.forms),
            1,
        )
        self.assertEqual(
            len(report.executions),
            0,
        )

    def test_explicit_workflow_get_reuses_ephemeral_auth_context(self):
        crawl = _crawl_result()
        secret = "Bearer cli-workflow-secret"
        advanced_state = WorkflowState(
            current_url="https://example.test/dashboard",
            visited_urls=(
                "https://example.test/",
                "https://example.test/dashboard",
            ),
            actions_used=1,
            max_actions=3,
        )
        execution_result = WorkflowNavigationResult(
            success=True,
            reason="completed",
            page=CrawlPage(
                url="https://example.test/dashboard",
                status=200,
                content_type="text/html",
                byte_count=64,
                links=(),
            ),
            state=advanced_state,
        )

        with patch.dict(
            "os.environ",
            {
                "NIGHTRECON_WORKFLOW_AUTH": secret,
            },
            clear=False,
        ):
            with patch(
                "nightrecon.cli.crawl_site",
                return_value=crawl,
            ) as crawl_site:
                with patch(
                    "nightrecon.cli.execute_workflow_navigation",
                    return_value=execution_result,
                ) as execute:
                    with patch(
                        "nightrecon.cli.ResultStore"
                    ) as store_class:
                        store_class.return_value.save_web_crawl_report.return_value = (
                            Path("results/crawl.json")
                        )
                        store_class.return_value.save_web_workflow_report.return_value = (
                            Path("results/workflow.json")
                        )

                        with patch(
                            "nightrecon.cli.NightReconLogger"
                        ):
                            code, stdout, stderr = self.run_cli(
                                "crawl",
                                "https://example.test/",
                                "--scope",
                                "example.test",
                                "--workflow",
                                "--workflow-max-actions",
                                "3",
                                "--workflow-get",
                                "https://example.test/dashboard",
                                "--authorization-env",
                                "NIGHTRECON_WORKFLOW_AUTH",
                                "--session-cookies",
                            )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "Workflow Summary: planned=1 forms=1 executions=1 successful=1",
            stdout,
        )
        self.assertNotIn(
            secret,
            stdout,
        )

        crawl_cookie_jar = (
            crawl_site.call_args.kwargs["cookie_jar"]
        )
        self.assertIsInstance(
            crawl_cookie_jar,
            CookieJar,
        )
        self.assertEqual(
            execute.call_args.kwargs["authorization"],
            secret,
        )
        self.assertIs(
            execute.call_args.kwargs["cookie_jar"],
            crawl_cookie_jar,
        )
        self.assertEqual(
            execute.call_args.kwargs["origin"],
            "https://example.test",
        )
        self.assertTrue(
            execute.call_args.kwargs["authorized"]
        )

        report = (
            store_class.return_value
            .save_web_workflow_report
            .call_args.args[0]
        )
        self.assertNotIn(
            secret,
            repr(report),
        )
        self.assertNotIn(
            "CookieJar",
            repr(report),
        )

    def test_workflow_get_requires_workflow_flag(self):
        with patch(
            "nightrecon.cli.crawl_site"
        ) as crawl_site:
            code, stdout, stderr = self.run_cli(
                "crawl",
                "https://example.test/",
                "--scope",
                "example.test",
                "--workflow-get",
                "https://example.test/dashboard",
            )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "--workflow-get requires --workflow",
            stderr,
        )
        crawl_site.assert_not_called()

    def test_cross_origin_workflow_get_is_rejected_before_crawl(self):
        with patch(
            "nightrecon.cli.crawl_site"
        ) as crawl_site:
            code, stdout, stderr = self.run_cli(
                "crawl",
                "https://example.test/",
                "--scope",
                "example.test",
                "--workflow",
                "--workflow-get",
                "https://outside.test/dashboard",
            )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "must use the crawl's exact origin",
            stderr,
        )
        crawl_site.assert_not_called()

    def test_workflow_get_rejects_raw_cookie_env_mode(self):
        with patch.dict(
            "os.environ",
            {
                "NIGHTRECON_WORKFLOW_COOKIE": "session=secret",
            },
            clear=False,
        ):
            with patch(
                "nightrecon.cli.crawl_site"
            ) as crawl_site:
                code, stdout, stderr = self.run_cli(
                    "crawl",
                    "https://example.test/",
                    "--scope",
                    "example.test",
                    "--workflow",
                    "--workflow-get",
                    "https://example.test/dashboard",
                    "--cookie-env",
                    "NIGHTRECON_WORKFLOW_COOKIE",
                )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "does not accept raw --cookie-env context",
            stderr,
        )
        self.assertNotIn(
            "session=secret",
            stderr,
        )
        crawl_site.assert_not_called()

    def test_invalid_workflow_action_limit_is_rejected_before_crawl(self):
        with patch(
            "nightrecon.cli.crawl_site"
        ) as crawl_site:
            code, stdout, stderr = self.run_cli(
                "crawl",
                "https://example.test/",
                "--scope",
                "example.test",
                "--workflow",
                "--workflow-max-actions",
                "0",
            )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "workflow_max_actions must be at least 1",
            stderr,
        )
        crawl_site.assert_not_called()


if __name__ == "__main__":
    unittest.main()
