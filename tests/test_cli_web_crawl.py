"""CLI tests for NightRecon authorized web crawling."""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon.cli import main
from nightrecon.web_crawl import CrawlPage, CrawlResult


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
        crawl_site.assert_called_once_with(
            start_url="https://example.test/",
            max_pages=5,
            max_bytes_per_page=4096,
            timeout=5.0,
        )
        store_class.return_value.save_web_crawl_report.assert_called_once()

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
