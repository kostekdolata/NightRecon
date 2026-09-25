"""Tests for structured NightRecon web-crawl reporting."""

import json
import tempfile
import unittest

from nightrecon.session import ScanSession
from nightrecon.storage import ResultStore
from nightrecon.targets import parse_target
from nightrecon.web_crawl import CrawlPage, CrawlResult
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
