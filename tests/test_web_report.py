"""Tests for structured NightRecon web-crawl reporting."""

import json
import tempfile
import unittest

from nightrecon.session import ScanSession
from nightrecon.web_assessment import (
    WebAssessmentFinding,
)
from nightrecon.storage import ResultStore
from nightrecon.targets import parse_target
from nightrecon.web_crawl import (
    CrawlPage,
    CrawlResult,
    WebFormInput,
    WebFormObservation,
)
from nightrecon.web_report import WebCrawlReport


class WebCrawlReportTests(unittest.TestCase):
    def build_report(self) -> WebCrawlReport:
        session = ScanSession.create(
            target=parse_target("example.test"),
            scope_rules=("example.test",),
        )
        crawl = CrawlResult(
            start_url="https://example.test/",
            origin="https://example.test",
            pages=(
                CrawlPage(
                    url="https://example.test/",
                    status=200,
                    content_type="text/html",
                    byte_count=100,
                    links=(
                        "https://example.test/admin",
                    ),
                    title="Home",
                    forms=(
                        WebFormObservation(
                            action="https://example.test/session",
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
                        "https://example.test/app.js",
                    ),
                ),
                CrawlPage(
                    url="https://example.test/admin",
                    status=None,
                    content_type="",
                    byte_count=0,
                    links=(),
                    error="TimeoutError: timed out",
                ),
            ),
            max_pages=10,
            max_bytes_per_page=4096,
        )
        return WebCrawlReport.create(
            session=session,
            crawl=crawl,
        )

    def test_report_summary_is_descriptive(self):
        report = self.build_report()
        data = report.to_dict()

        self.assertEqual(
            data["status"],
            "completed",
        )
        self.assertEqual(
            data["summary"]["pages_fetched"],
            2,
        )
        self.assertEqual(
            data["summary"]["successful_pages"],
            1,
        )
        self.assertEqual(
            data["summary"]["failed_pages"],
            1,
        )
        self.assertEqual(
            data["summary"]["links_observed"],
            1,
        )
        self.assertEqual(
            data["summary"]["forms_observed"],
            1,
        )
        self.assertEqual(
            data["summary"]["script_sources_observed"],
            1,
        )
        self.assertIsNone(
            data["assessment_summary"]
        )
        self.assertIsNone(
            data["safe_active_summary"]
        )

    def test_enabled_assessment_summary_is_persisted(self):
        session = ScanSession.create(
            target=parse_target("example.test"),
            scope_rules=("example.test",),
        )
        crawl = CrawlResult(
            start_url="https://example.test/",
            origin="https://example.test",
            pages=(),
            max_pages=10,
            max_bytes_per_page=4096,
        )
        report = WebCrawlReport.create(
            session=session,
            crawl=crawl,
            assessment_enabled=True,
            assessment_intrusiveness="passive",
            assessment_findings=(
                WebAssessmentFinding(
                    check_id="web.password-form-uses-get",
                    title="Password form uses GET submission",
                    severity="medium",
                    page_url="https://example.test/login",
                    evidence="method=GET contains password input",
                ),
            ),
        )

        data = report.to_dict()

        self.assertTrue(
            data["assessment_enabled"]
        )
        self.assertEqual(
            data["assessment_summary"]["total_findings"],
            1,
        )
        self.assertEqual(
            data["assessment_summary"]["medium_count"],
            1,
        )
        self.assertEqual(
            data["assessment_findings"][0]["check_id"],
            "web.password-form-uses-get",
        )

    def test_safe_active_summary_records_probe_evidence(self):
        session = ScanSession.create(
            target=parse_target("example.test"),
            scope_rules=("example.test",),
        )
        crawl = CrawlResult(
            start_url="https://example.test/",
            origin="https://example.test",
            pages=(),
            max_pages=10,
            max_bytes_per_page=4096,
        )
        report = WebCrawlReport.create(
            session=session,
            crawl=crawl,
            assessment_enabled=True,
            assessment_intrusiveness="safe-active",
            assessment_findings=(),
            safe_active_requests_attempted=3,
            safe_active_successful_probes=2,
            safe_active_errors=(
                "https://example.test/b:HTTPError:405",
            ),
        )

        data = report.to_dict()

        self.assertEqual(
            data["assessment_intrusiveness"],
            "safe-active",
        )
        self.assertEqual(
            data["safe_active_summary"],
            {
                "requests_attempted": 3,
                "successful_probes": 2,
                "errors": 1,
            },
        )
        self.assertEqual(
            data["safe_active_errors"],
            [
                "https://example.test/b:HTTPError:405"
            ],
        )

    def test_report_is_saved_as_json(self):
        report = self.build_report()

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = ResultStore(
                temp_dir
            ).save_web_crawl_report(
                report
            )

            with output_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)

        self.assertEqual(
            data["start_url"],
            "https://example.test/",
        )
        self.assertEqual(
            data["origin"],
            "https://example.test",
        )
        self.assertEqual(
            data["pages"][0]["status"],
            200,
        )
        self.assertEqual(
            data["pages"][1]["error"],
            "TimeoutError: timed out",
        )


if __name__ == "__main__":
    unittest.main()
