"""CLI tests for NightRecon authorized web crawling."""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon.cli import main
from nightrecon.web_active_assessment import (
    SafeActiveWebAssessmentResult,
)
from nightrecon.web_assessment import WebAssessmentFinding
from nightrecon.web_crawl import (
    CrawlPage,
    CrawlResult,
    WebFormInput,
    WebFormObservation,
)


def _crawl_result(
    *,
    start_url: str,
    max_pages: int = 50,
    max_bytes_per_page: int = 1_048_576,
) -> CrawlResult:
    origin = start_url.rstrip("/")

    if "/" in origin.split("://", 1)[1]:
        origin = (
            origin.split("://", 1)[0]
            + "://"
            + origin.split("://", 1)[1].split("/", 1)[0]
        )

    return CrawlResult(
        start_url=start_url,
        origin=origin,
        pages=(
            CrawlPage(
                url=start_url,
                status=200,
                content_type="text/html",
                byte_count=128,
                links=(),
                title="Example Page",
                forms=(
                    WebFormObservation(
                        action=f"{origin}/session",
                        method="POST",
                        inputs=(
                            WebFormInput(
                                name="username",
                                input_type="text",
                            ),
                        ),
                    ),
                ),
                script_sources=(
                    f"{origin}/app.js",
                ),
            ),
        ),
        max_pages=max_pages,
        max_bytes_per_page=max_bytes_per_page,
    )


class CliWebCrawlTests(unittest.TestCase):
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

    def test_exact_hostname_scope_is_authorized(self):
        crawl = _crawl_result(
            start_url="https://example.test/",
            max_pages=5,
            max_bytes_per_page=4096,
        )

        with patch(
            "nightrecon.cli.crawl_site",
            return_value=crawl,
        ) as crawl_site:
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
                        "https://example.test",
                        "--scope",
                        "example.test",
                        "--max-pages",
                        "5",
                        "--max-bytes-per-page",
                        "4096",
                    )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "Scope authorization: approved",
            stdout,
        )
        self.assertIn(
            "Pages fetched: 1",
            stdout,
        )
        self.assertIn(
            "Title: Example Page",
            stdout,
        )
        self.assertIn(
            "FORM method=POST",
            stdout,
        )
        self.assertIn(
            "SCRIPT https://example.test/app.js",
            stdout,
        )
        crawl_site.assert_called_once_with(
            start_url="https://example.test/",
            max_pages=5,
            max_bytes_per_page=4096,
            timeout=5.0,
            authorization=None,
            cookie=None,
        )
        store_class.return_value.save_web_crawl_report.assert_called_once()

    def test_passive_assessment_is_opt_in_and_reports_findings(self):
        crawl = CrawlResult(
            start_url="http://example.test/login",
            origin="http://example.test",
            pages=(
                CrawlPage(
                    url="http://example.test/login",
                    status=200,
                    content_type="text/html",
                    byte_count=128,
                    links=(),
                    forms=(
                        WebFormObservation(
                            action="http://example.test/session",
                            method="GET",
                            inputs=(
                                WebFormInput(
                                    name="password",
                                    input_type="password",
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            max_pages=50,
            max_bytes_per_page=1_048_576,
        )

        with patch(
            "nightrecon.cli.crawl_site",
            return_value=crawl,
        ):
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
                        "http://example.test/login",
                        "--scope",
                        "example.test",
                        "--assessment",
                    )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "Web Assessment Summary: findings=2",
            stdout,
        )
        self.assertIn(
            "web.password-form-over-http",
            stdout,
        )
        self.assertIn(
            "web.password-form-uses-get",
            stdout,
        )

        report = (
            store_class.return_value
            .save_web_crawl_report
            .call_args.args[0]
        )
        self.assertTrue(
            report.assessment_enabled
        )
        self.assertEqual(
            len(report.assessment_findings),
            2,
        )

    def test_passive_assessment_does_not_run_safe_active_probes(self):
        crawl = _crawl_result(
            start_url="https://example.test/",
        )

        with patch(
            "nightrecon.cli.crawl_site",
            return_value=crawl,
        ):
            with patch(
                "nightrecon.cli.assess_web_pages_safe_active"
            ) as safe_active:
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
                            "--assessment",
                        )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "Assessment intrusiveness: passive",
            stdout,
        )
        safe_active.assert_not_called()

    def test_safe_active_assessment_is_explicit_and_bounded(self):
        crawl = _crawl_result(
            start_url="https://example.test/",
        )
        active_result = SafeActiveWebAssessmentResult(
            findings=(
                WebAssessmentFinding(
                    check_id="web.risky-http-methods-advertised",
                    title="Potentially risky HTTP methods are advertised",
                    severity="low",
                    page_url="https://example.test/",
                    evidence="OPTIONS Allow header advertised: DELETE",
                ),
            ),
            requests_attempted=1,
            successful_probes=1,
            max_requests=3,
            errors=(),
        )

        with patch(
            "nightrecon.cli.crawl_site",
            return_value=crawl,
        ):
            with patch(
                "nightrecon.cli.assess_web_pages_safe_active",
                return_value=active_result,
            ) as safe_active:
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
                            "--assessment",
                            "--max-web-assessment-intrusiveness",
                            "safe-active",
                            "--max-web-assessment-requests",
                            "3",
                        )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "Assessment intrusiveness: safe-active",
            stdout,
        )
        self.assertIn(
            "Safe-active probes: attempted=1 successful=1 errors=0",
            stdout,
        )
        self.assertIn(
            "web.risky-http-methods-advertised",
            stdout,
        )
        safe_active.assert_called_once_with(
            pages=crawl.pages,
            origin=crawl.origin,
            authorized=True,
            timeout=5.0,
            max_requests=3,
            authorization=None,
            cookie=None,
        )

        report = (
            store_class.return_value
            .save_web_crawl_report
            .call_args.args[0]
        )
        self.assertEqual(
            report.assessment_intrusiveness,
            "safe-active",
        )
        self.assertEqual(
            report.safe_active_requests_attempted,
            1,
        )

    def test_invalid_safe_active_request_limit_is_rejected_before_crawl(self):
        with patch(
            "nightrecon.cli.crawl_site"
        ) as crawl_site:
            with patch(
                "nightrecon.cli.NightReconLogger"
            ) as logger_class:
                code, stdout, stderr = self.run_cli(
                    "crawl",
                    "https://example.test/",
                    "--scope",
                    "example.test",
                    "--assessment",
                    "--max-web-assessment-intrusiveness",
                    "safe-active",
                    "--max-web-assessment-requests",
                    "0",
                )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "max_web_assessment_requests must be at least 1",
            stderr,
        )
        crawl_site.assert_not_called()
        logger_class.assert_not_called()

    def test_assessment_is_disabled_by_default(self):
        crawl = _crawl_result(
            start_url="https://example.test/",
        )

        with patch(
            "nightrecon.cli.crawl_site",
            return_value=crawl,
        ):
            with patch(
                "nightrecon.cli.assess_web_pages"
            ) as assess:
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
            "Web Assessment Summary:",
            stdout,
        )
        assess.assert_not_called()

    def test_authenticated_crawl_reads_secrets_from_environment_only(self):
        crawl = _crawl_result(
            start_url="https://example.test/",
        )
        authorization = "Bearer super-secret-token"
        cookie = "session=super-secret-cookie"

        with patch.dict(
            "os.environ",
            {
                "NIGHTRECON_TEST_AUTH": authorization,
                "NIGHTRECON_TEST_COOKIE": cookie,
            },
            clear=False,
        ):
            with patch(
                "nightrecon.cli.crawl_site",
                return_value=crawl,
            ) as crawl_site:
                with patch(
                    "nightrecon.cli.ResultStore"
                ) as store_class:
                    store_class.return_value.save_web_crawl_report.return_value = (
                        Path("results/crawl.json")
                    )

                    with patch(
                        "nightrecon.cli.NightReconLogger"
                    ) as logger_class:
                        code, stdout, stderr = self.run_cli(
                            "crawl",
                            "https://example.test/",
                            "--scope",
                            "example.test",
                            "--authorization-env",
                            "NIGHTRECON_TEST_AUTH",
                            "--cookie-env",
                            "NIGHTRECON_TEST_COOKIE",
                        )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(
            crawl_site.call_args.kwargs["authorization"],
            authorization,
        )
        self.assertEqual(
            crawl_site.call_args.kwargs["cookie"],
            cookie,
        )
        self.assertNotIn(
            authorization,
            stdout,
        )
        self.assertNotIn(
            cookie,
            stdout,
        )
        self.assertNotIn(
            authorization,
            repr(
                logger_class.return_value.write.call_args_list
            ),
        )
        self.assertNotIn(
            cookie,
            repr(
                logger_class.return_value.write.call_args_list
            ),
        )

        report = (
            store_class.return_value
            .save_web_crawl_report
            .call_args.args[0]
        )
        self.assertNotIn(
            authorization,
            repr(report),
        )
        self.assertNotIn(
            cookie,
            repr(report),
        )

    def test_authenticated_safe_active_reuses_ephemeral_context(self):
        crawl = _crawl_result(
            start_url="https://example.test/",
        )
        active_result = SafeActiveWebAssessmentResult(
            findings=(),
            requests_attempted=1,
            successful_probes=1,
            max_requests=2,
            errors=(),
        )

        with patch.dict(
            "os.environ",
            {
                "NIGHTRECON_TEST_AUTH": "Bearer active-secret",
                "NIGHTRECON_TEST_COOKIE": "session=active-cookie",
            },
            clear=False,
        ):
            with patch(
                "nightrecon.cli.crawl_site",
                return_value=crawl,
            ):
                with patch(
                    "nightrecon.cli.assess_web_pages_safe_active",
                    return_value=active_result,
                ) as safe_active:
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
                                "--assessment",
                                "--max-web-assessment-intrusiveness",
                                "safe-active",
                                "--max-web-assessment-requests",
                                "2",
                                "--authorization-env",
                                "NIGHTRECON_TEST_AUTH",
                                "--cookie-env",
                                "NIGHTRECON_TEST_COOKIE",
                            )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        safe_active.assert_called_once_with(
            pages=crawl.pages,
            origin=crawl.origin,
            authorized=True,
            timeout=5.0,
            max_requests=2,
            authorization="Bearer active-secret",
            cookie="session=active-cookie",
        )
        self.assertNotIn(
            "active-secret",
            stdout,
        )
        self.assertNotIn(
            "active-cookie",
            stdout,
        )

    def test_missing_authentication_environment_variable_is_rejected(self):
        with patch.dict(
            "os.environ",
            {},
            clear=True,
        ):
            with patch(
                "nightrecon.cli.crawl_site"
            ) as crawl_site:
                with patch(
                    "nightrecon.cli.NightReconLogger"
                ) as logger_class:
                    code, stdout, stderr = self.run_cli(
                        "crawl",
                        "https://example.test/",
                        "--scope",
                        "example.test",
                        "--authorization-env",
                        "NIGHTRECON_MISSING_AUTH",
                    )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "NIGHTRECON_MISSING_AUTH",
            stderr,
        )
        crawl_site.assert_not_called()
        logger_class.assert_not_called()

    def test_ip_inside_cidr_scope_is_authorized(self):
        crawl = _crawl_result(
            start_url="https://192.0.2.10/",
        )

        with patch(
            "nightrecon.cli.crawl_site",
            return_value=crawl,
        ) as crawl_site:
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
                        "https://192.0.2.10/",
                        "--scope",
                        "192.0.2.0/24",
                    )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "Target type: ipv4",
            stdout,
        )
        crawl_site.assert_called_once()

    def test_out_of_scope_hostname_is_rejected_before_crawling(self):
        with patch(
            "nightrecon.cli.crawl_site"
        ) as crawl_site:
            with patch(
                "nightrecon.cli.ResultStore"
            ) as store_class:
                with patch(
                    "nightrecon.cli.NightReconLogger"
                ) as logger_class:
                    code, stdout, stderr = self.run_cli(
                        "crawl",
                        "https://api.example.test/",
                        "--scope",
                        "example.test",
                    )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "outside the authorized scope",
            stderr,
        )
        crawl_site.assert_not_called()
        store_class.assert_not_called()
        logger_class.return_value.write.assert_called_once_with(
            "crawl.rejected",
            url="https://api.example.test/",
            target="api.example.test",
            target_type="hostname",
            scope=["example.test"],
            reason="outside_authorized_scope",
        )

    def test_invalid_crawl_limit_is_reported_and_not_saved(self):
        with patch(
            "nightrecon.cli.crawl_site",
            side_effect=ValueError(
                "max_pages must be at least 1."
            ),
        ):
            with patch(
                "nightrecon.cli.ResultStore"
            ) as store_class:
                with patch(
                    "nightrecon.cli.NightReconLogger"
                ):
                    code, stdout, stderr = self.run_cli(
                        "crawl",
                        "https://example.test/",
                        "--scope",
                        "example.test",
                        "--max-pages",
                        "0",
                    )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "max_pages must be at least 1",
            stderr,
        )
        store_class.assert_not_called()


if __name__ == "__main__":
    unittest.main()
