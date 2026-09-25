"""Tests for bounded NightRecon web crawling."""

import unittest
from unittest.mock import patch

from nightrecon.web_crawl import (
    CrawlPage,
    _SameOriginRedirectHandler,
    crawl_site,
    extract_same_origin_links,
    normalize_http_url,
    url_origin,
)


class WebCrawlTests(unittest.TestCase):
    def test_normalize_http_url_removes_fragment_and_default_port(self):
        self.assertEqual(
            normalize_http_url(
                "HTTPS://Example.TEST:443/docs?q=1#section"
            ),
            "https://example.test/docs?q=1",
        )

    def test_normalize_http_url_rejects_non_http_and_credentials(self):
        with self.assertRaises(ValueError):
            normalize_http_url("ftp://example.test/file")

        with self.assertRaises(ValueError):
            normalize_http_url(
                "https://user:pass@example.test/"
            )

    def test_url_origin_preserves_non_default_port(self):
        self.assertEqual(
            url_origin("http://example.test:8080/a"),
            "http://example.test:8080",
        )

    def test_extract_links_keeps_only_same_origin_http_links(self):
        html = """
        <a href="/admin">Admin</a>
        <a href="https://example.test/help#top">Help</a>
        <a href="https://other.test/out">Out</a>
        <a href="mailto:test@example.test">Mail</a>
        <a href="javascript:void(0)">JS</a>
        <a href="/admin">Duplicate</a>
        """

        links = extract_same_origin_links(
            base_url="https://example.test/start",
            html=html,
            origin="https://example.test",
        )

        self.assertEqual(
            links,
            (
                "https://example.test/admin",
                "https://example.test/help",
            ),
        )

    def test_crawl_is_bounded_and_deterministic(self):
        pages = {
            "https://example.test/": CrawlPage(
                url="https://example.test/",
                status=200,
                content_type="text/html",
                byte_count=10,
                links=(
                    "https://example.test/b",
                    "https://example.test/a",
                ),
            ),
            "https://example.test/b": CrawlPage(
                url="https://example.test/b",
                status=200,
                content_type="text/html",
                byte_count=8,
                links=("https://example.test/c",),
            ),
            "https://example.test/a": CrawlPage(
                url="https://example.test/a",
                status=200,
                content_type="text/html",
                byte_count=7,
                links=(),
            ),
        }

        def fake_fetch_page(**kwargs):
            return pages[kwargs["url"]]

        with patch(
            "nightrecon.web_crawl._fetch_page",
            side_effect=fake_fetch_page,
        ) as fetch:
            result = crawl_site(
                start_url="https://example.test",
                max_pages=3,
                max_bytes_per_page=1024,
                timeout=1.0,
            )

        self.assertEqual(
            tuple(page.url for page in result.pages),
            (
                "https://example.test/",
                "https://example.test/b",
                "https://example.test/a",
            ),
        )
        self.assertEqual(result.pages_fetched, 3)
        self.assertEqual(result.successful_pages, 3)
        self.assertEqual(fetch.call_count, 3)

    def test_crawl_does_not_queue_more_than_page_limit(self):
        first = CrawlPage(
            url="https://example.test/",
            status=200,
            content_type="text/html",
            byte_count=10,
            links=(
                "https://example.test/a",
                "https://example.test/b",
                "https://example.test/c",
            ),
        )
        second = CrawlPage(
            url="https://example.test/a",
            status=200,
            content_type="text/html",
            byte_count=5,
            links=(),
        )

        with patch(
            "nightrecon.web_crawl._fetch_page",
            side_effect=(first, second),
        ):
            result = crawl_site(
                start_url="https://example.test/",
                max_pages=2,
            )

        self.assertEqual(
            tuple(page.url for page in result.pages),
            (
                "https://example.test/",
                "https://example.test/a",
            ),
        )

    def test_cross_origin_redirect_is_blocked(self):
        handler = _SameOriginRedirectHandler(
            "https://example.test"
        )

        class RequestStub:
            full_url = "https://example.test/start"

        with self.assertRaisesRegex(
            ValueError,
            "Cross-origin redirect blocked",
        ):
            handler.redirect_request(
                RequestStub(),
                None,
                302,
                "Found",
                {},
                "https://other.test/landing",
            )

    def test_crawl_validation_rejects_invalid_limits(self):
        with self.assertRaises(ValueError):
            crawl_site(
                start_url="https://example.test/",
                max_pages=0,
            )

        with self.assertRaises(ValueError):
            crawl_site(
                start_url="https://example.test/",
                max_bytes_per_page=0,
            )

        with self.assertRaises(ValueError):
            crawl_site(
                start_url="https://example.test/",
                timeout=0,
            )

        with self.assertRaises(ValueError):
            crawl_site(
                start_url="https://example.test/",
                user_agent="",
            )


if __name__ == "__main__":
    unittest.main()
