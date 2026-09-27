"""CLI tests for NightRecon v0.28 safe-active DAST."""

import contextlib
import io
import os
import sys
import unittest
from http.cookiejar import CookieJar
from pathlib import Path
from unittest.mock import patch

from nightrecon.cli import main
from nightrecon.dast_cors import (
    DastCorsAssessmentResult,
)
from nightrecon.dast_findings import DastFinding
from nightrecon.dast_policy import (
    DastBudgetState,
)
from nightrecon.web_active_assessment import (
    SafeActiveWebAssessmentResult,
)
from nightrecon.web_crawl import (
    CrawlPage,
    CrawlResult,
)


def _crawl():
    return CrawlResult(
        start_url=(
            "https://example.test/"
        ),
        origin=(
            "https://example.test"
        ),
        pages=(
            CrawlPage(
                url=(
                    "https://example.test/"
                ),
                status=200,
                content_type="text/html",
                byte_count=128,
                links=(),
            ),
        ),
        max_pages=50,
        max_bytes_per_page=1_048_576,
    )


def _legacy_safe_active():
    return SafeActiveWebAssessmentResult(
        findings=(),
        requests_attempted=0,
        successful_probes=0,
        max_requests=10,
        errors=(),
    )


def _dast_result():
    return DastCorsAssessmentResult(
        findings=(
            DastFinding(
                check_id=(
                    "web.cors.credentialed-origin-reflection"
                ),
                title=(
                    "Credentialed CORS policy reflected "
                    "NightRecon synthetic origin"
                ),
                severity="medium",
                target_url=(
                    "https://example.test/"
                ),
                summary=(
                    "Configuration observation."
                ),
                evidence=(
                    (
                        "synthetic_origin_reflected="
                        "https://nightrecon.invalid"
                    ),
                ),
            ),
        ),
        evidence_records=(),
        state=DastBudgetState(
            total_used=2,
            check_usage=(
                (
                    "web.cors.credentialed-origin-reflection",
                    2,
                ),
            ),
            family_usage=(
                (
                    "cors",
                    2,
                ),
            ),
        ),
        targets_attempted=1,
        requests_attempted=2,
        errors=(),
    )


class CliDastTests(unittest.TestCase):
    def run_cli(
        self,
        *args,
    ):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                *args,
            ],
        ):
            with contextlib.redirect_stdout(
                stdout
            ):
                with contextlib.redirect_stderr(
                    stderr
                ):
                    try:
                        main()
                        code = 0
                    except SystemExit as exc:
                        code = exc.code

        return (
            code,
            stdout.getvalue(),
            stderr.getvalue(),
        )

    def test_dast_is_disabled_by_default(self):
        crawl = _crawl()

        with patch(
            "nightrecon.cli.crawl_site",
            return_value=crawl,
        ):
            with patch(
                "nightrecon.cli.assess_credentialed_cors"
            ) as dast:
                with patch(
                    "nightrecon.cli.ResultStore"
                ) as store_class:
                    store_class.return_value.save_web_crawl_report.return_value = (
                        Path(
                            "results/crawl.json"
                        )
                    )

                    with patch(
                        "nightrecon.cli.NightReconLogger"
                    ):
                        code, stdout, stderr = (
                            self.run_cli(
                                "crawl",
                                "https://example.test/",
                                "--scope",
                                "example.test",
                            )
                        )

        self.assertEqual(
            code,
            0,
        )
        self.assertEqual(
            stderr,
            "",
        )
        self.assertNotIn(
            "DAST Summary:",
            stdout,
        )
        dast.assert_not_called()
        (
            store_class.return_value
            .save_dast_assessment_report
            .assert_not_called()
        )

    def test_dast_requires_assessment_and_safe_active_mode(self):
        with patch(
            "nightrecon.cli.crawl_site"
        ) as crawl_site:
            code, stdout, stderr = (
                self.run_cli(
                    "crawl",
                    "https://example.test/",
                    "--scope",
                    "example.test",
                    "--dast-cors",
                )
            )

            self.assertEqual(
                code,
                2,
            )
            self.assertEqual(
                stdout,
                "",
            )
            self.assertIn(
                "--dast-cors requires --assessment",
                stderr,
            )

            code, stdout, stderr = (
                self.run_cli(
                    "crawl",
                    "https://example.test/",
                    "--scope",
                    "example.test",
                    "--assessment",
                    "--dast-cors",
                )
            )

            self.assertEqual(
                code,
                2,
            )
            self.assertIn(
                "requires --max-web-assessment-intrusiveness safe-active",
                stderr,
            )

        crawl_site.assert_not_called()

    def test_raw_cookie_mode_is_rejected_before_crawl(self):
        with patch.dict(
            os.environ,
            {
                "NIGHTRECON_COOKIE": (
                    "session=secret"
                ),
            },
            clear=False,
        ):
            with patch(
                "nightrecon.cli.crawl_site"
            ) as crawl_site:
                code, stdout, stderr = (
                    self.run_cli(
                        "crawl",
                        "https://example.test/",
                        "--scope",
                        "example.test",
                        "--assessment",
                        "--max-web-assessment-intrusiveness",
                        "safe-active",
                        "--dast-cors",
                        "--cookie-env",
                        "NIGHTRECON_COOKIE",
                    )
                )

        self.assertEqual(
            code,
            2,
        )
        self.assertEqual(
            stdout,
            "",
        )
        self.assertIn(
            "does not accept raw --cookie-env context",
            stderr,
        )
        self.assertNotIn(
            "session=secret",
            stderr,
        )
        crawl_site.assert_not_called()

    def test_dast_budget_precheck_rejects_impossible_target_count(self):
        with patch(
            "nightrecon.cli.crawl_site"
        ) as crawl_site:
            code, stdout, stderr = (
                self.run_cli(
                    "crawl",
                    "https://example.test/",
                    "--scope",
                    "example.test",
                    "--assessment",
                    "--max-web-assessment-intrusiveness",
                    "safe-active",
                    "--dast-cors",
                    "--dast-cors-max-targets",
                    "3",
                    "--dast-max-total-requests",
                    "4",
                )
            )

        self.assertEqual(
            code,
            2,
        )
        self.assertEqual(
            stdout,
            "",
        )
        self.assertIn(
            "exceed dast_max_total_requests",
            stderr,
        )
        crawl_site.assert_not_called()

    def test_dast_reuses_ephemeral_auth_and_session_context(self):
        crawl = _crawl()
        secret = (
            "Bearer dast-cli-secret"
        )

        with patch.dict(
            os.environ,
            {
                "NIGHTRECON_DAST_AUTH": (
                    secret
                ),
            },
            clear=False,
        ):
            with patch(
                "nightrecon.cli.crawl_site",
                return_value=crawl,
            ) as crawl_site:
                with patch(
                    "nightrecon.cli.assess_web_pages_safe_active",
                    return_value=(
                        _legacy_safe_active()
                    ),
                ):
                    with patch(
                        "nightrecon.cli.assess_credentialed_cors",
                        return_value=(
                            _dast_result()
                        ),
                    ) as dast:
                        with patch(
                            "nightrecon.cli.ResultStore"
                        ) as store_class:
                            store_class.return_value.save_web_crawl_report.return_value = (
                                Path(
                                    "results/crawl.json"
                                )
                            )
                            store_class.return_value.save_dast_assessment_report.return_value = (
                                Path(
                                    "results/session-dast.json"
                                )
                            )

                            with patch(
                                "nightrecon.cli.NightReconLogger"
                            ):
                                code, stdout, stderr = (
                                    self.run_cli(
                                        "crawl",
                                        "https://example.test/",
                                        "--scope",
                                        "example.test",
                                        "--assessment",
                                        "--max-web-assessment-intrusiveness",
                                        "safe-active",
                                        "--dast-cors",
                                        "--dast-cors-max-targets",
                                        "1",
                                        "--authorization-env",
                                        "NIGHTRECON_DAST_AUTH",
                                        "--session-cookies",
                                    )
                                )

        self.assertEqual(
            code,
            0,
        )
        self.assertEqual(
            stderr,
            "",
        )
        self.assertIn(
            (
                "DAST Summary: checks=1 "
                "requests=2 findings=1"
            ),
            stdout,
        )
        self.assertIn(
            "web.cors.credentialed-origin-reflection",
            stdout,
        )
        self.assertNotIn(
            "dast-cli-secret",
            stdout,
        )
        self.assertIn(
            "DAST result file: results/session-dast.json",
            stdout,
        )

        crawl_cookie_jar = (
            crawl_site.call_args.kwargs[
                "cookie_jar"
            ]
        )
        self.assertIsInstance(
            crawl_cookie_jar,
            CookieJar,
        )
        self.assertIs(
            dast.call_args.kwargs[
                "cookie_jar"
            ],
            crawl_cookie_jar,
        )
        self.assertEqual(
            dast.call_args.kwargs[
                "authorization"
            ],
            secret,
        )
        self.assertEqual(
            dast.call_args.kwargs[
                "max_targets"
            ],
            1,
        )
        self.assertEqual(
            dast.call_args.kwargs[
                "urls"
            ],
            (
                "https://example.test/",
            ),
        )

        report = (
            store_class.return_value
            .save_dast_assessment_report
            .call_args.args[0]
        )
        self.assertEqual(
            report.requests_used,
            2,
        )
        self.assertEqual(
            len(
                report.findings
            ),
            1,
        )
        self.assertNotIn(
            "dast-cli-secret",
            repr(
                report
            ),
        )
        self.assertNotIn(
            "CookieJar",
            repr(
                report
            ),
        )


if __name__ == "__main__":
    unittest.main()
