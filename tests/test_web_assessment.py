"""Tests for passive NightRecon web assessment checks."""

import unittest

from nightrecon.web_assessment import (
    assess_web_pages,
    summarize_web_assessments,
)
from nightrecon.web_crawl import (
    CrawlPage,
    WebFormInput,
    WebFormObservation,
)


class WebAssessmentTests(unittest.TestCase):
    def test_password_form_over_http_is_reported(self):
        page = CrawlPage(
            url="http://example.test/login",
            status=200,
            content_type="text/html",
            byte_count=100,
            links=(),
            forms=(
                WebFormObservation(
                    action="http://example.test/session",
                    method="POST",
                    inputs=(
                        WebFormInput(
                            name="password",
                            input_type="password",
                        ),
                    ),
                ),
            ),
        )

        findings = assess_web_pages((page,))

        self.assertEqual(
            tuple(
                finding.check_id
                for finding in findings
            ),
            ("web.password-form-over-http",),
        )
        self.assertEqual(
            findings[0].severity,
            "medium",
        )

    def test_password_form_using_get_is_reported(self):
        page = CrawlPage(
            url="https://example.test/login",
            status=200,
            content_type="text/html",
            byte_count=100,
            links=(),
            forms=(
                WebFormObservation(
                    action="https://example.test/login",
                    method="GET",
                    inputs=(
                        WebFormInput(
                            name="password",
                            input_type="password",
                        ),
                    ),
                ),
            ),
        )

        findings = assess_web_pages((page,))

        self.assertEqual(
            tuple(
                finding.check_id
                for finding in findings
            ),
            ("web.password-form-uses-get",),
        )

    def test_mixed_content_script_is_reported(self):
        page = CrawlPage(
            url="https://example.test/",
            status=200,
            content_type="text/html",
            byte_count=100,
            links=(),
            script_sources=(
                "https://example.test/app.js",
                "http://cdn.example.test/legacy.js",
            ),
        )

        findings = assess_web_pages((page,))

        self.assertEqual(
            tuple(
                finding.check_id
                for finding in findings
            ),
            ("web.mixed-content-script",),
        )
        self.assertIn(
            "http://cdn.example.test/legacy.js",
            findings[0].evidence,
        )

    def test_failed_pages_are_skipped(self):
        page = CrawlPage(
            url="http://example.test/login",
            status=None,
            content_type="",
            byte_count=0,
            links=(),
            error="TimeoutError: timed out",
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
        )

        self.assertEqual(
            assess_web_pages((page,)),
            (),
        )

    def test_summary_counts_severities(self):
        page = CrawlPage(
            url="http://example.test/login",
            status=200,
            content_type="text/html",
            byte_count=100,
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
        )

        findings = assess_web_pages((page,))
        summary = summarize_web_assessments(
            findings
        )

        self.assertEqual(
            summary.total_findings,
            2,
        )
        self.assertEqual(
            summary.medium_count,
            2,
        )
        self.assertEqual(
            summary.high_count,
            0,
        )
        self.assertEqual(
            summary.low_count,
            0,
        )
        self.assertEqual(
            summary.unknown_count,
            0,
        )


if __name__ == "__main__":
    unittest.main()
