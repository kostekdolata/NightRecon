"""Tests for bounded safe-active NightRecon web assessment probes."""

import unittest
from email.message import Message
from unittest.mock import patch

from nightrecon.web_active_assessment import (
    _NoRedirectHandler,
    assess_web_pages_safe_active,
)
from nightrecon.web_crawl import CrawlPage


class _FakeResponse:
    def __init__(
        self,
        *,
        url: str,
        allow: str = "",
    ) -> None:
        self._url = url
        self.headers = Message()

        if allow:
            self.headers["Allow"] = allow

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ) -> bool:
        return False

    def geturl(self) -> str:
        return self._url


class _FakeOpener:
    def __init__(
        self,
        responses: dict[str, _FakeResponse],
    ) -> None:
        self.responses = responses
        self.requests = []
        self.request_objects = []

    def open(
        self,
        request,
        timeout,
    ):
        self.requests.append(
            (
                request.full_url,
                request.get_method(),
                timeout,
            )
        )
        self.request_objects.append(
            request
        )
        return self.responses[
            request.full_url
        ]


class SafeActiveWebAssessmentTests(unittest.TestCase):
    def test_explicit_authorization_is_required_before_requests(self):
        page = CrawlPage(
            url="https://example.test/",
            status=200,
            content_type="text/html",
            byte_count=10,
            links=(),
        )

        with patch(
            "nightrecon.web_active_assessment.build_opener"
        ) as build:
            with self.assertRaises(
                PermissionError
            ):
                assess_web_pages_safe_active(
                    pages=(page,),
                    origin="https://example.test",
                    authorized=False,
                )

        build.assert_not_called()

    def test_options_probe_reports_risky_advertised_methods(self):
        page = CrawlPage(
            url="https://example.test/admin",
            status=200,
            content_type="text/html",
            byte_count=10,
            links=(),
        )
        opener = _FakeOpener(
            {
                "https://example.test/admin": _FakeResponse(
                    url="https://example.test/admin",
                    allow="GET, HEAD, OPTIONS, PUT, DELETE",
                )
            }
        )

        with patch(
            "nightrecon.web_active_assessment.build_opener",
            return_value=opener,
        ):
            result = assess_web_pages_safe_active(
                pages=(page,),
                origin="https://example.test",
                authorized=True,
                timeout=2.0,
                max_requests=5,
            )

        self.assertEqual(
            opener.requests,
            [
                (
                    "https://example.test/admin",
                    "OPTIONS",
                    2.0,
                )
            ],
        )
        self.assertEqual(
            result.requests_attempted,
            1,
        )
        self.assertEqual(
            result.successful_probes,
            1,
        )
        self.assertEqual(
            len(result.findings),
            1,
        )
        self.assertEqual(
            result.findings[0].check_id,
            "web.risky-http-methods-advertised",
        )
        self.assertEqual(
            result.findings[0].severity,
            "low",
        )
        self.assertIn(
            "DELETE, PUT",
            result.findings[0].evidence,
        )

    def test_authenticated_context_is_sent_with_options_probe(self):
        page = CrawlPage(
            url="https://example.test/",
            status=200,
            content_type="text/html",
            byte_count=10,
            links=(),
        )
        opener = _FakeOpener(
            {
                "https://example.test/": _FakeResponse(
                    url="https://example.test/",
                    allow="GET, OPTIONS",
                )
            }
        )

        with patch(
            "nightrecon.web_active_assessment.build_opener",
            return_value=opener,
        ):
            result = assess_web_pages_safe_active(
                pages=(page,),
                origin="https://example.test",
                authorized=True,
                authorization="Bearer test-token",
                cookie="session=test-cookie",
            )

        request = opener.request_objects[0]
        headers = dict(
            request.header_items()
        )

        self.assertEqual(
            headers["Authorization"],
            "Bearer test-token",
        )
        self.assertEqual(
            headers["Cookie"],
            "session=test-cookie",
        )
        self.assertNotIn(
            "test-token",
            repr(result),
        )
        self.assertNotIn(
            "test-cookie",
            repr(result),
        )

    def test_safe_methods_do_not_generate_finding(self):
        page = CrawlPage(
            url="https://example.test/",
            status=200,
            content_type="text/html",
            byte_count=10,
            links=(),
        )
        opener = _FakeOpener(
            {
                "https://example.test/": _FakeResponse(
                    url="https://example.test/",
                    allow="GET, HEAD, OPTIONS",
                )
            }
        )

        with patch(
            "nightrecon.web_active_assessment.build_opener",
            return_value=opener,
        ):
            result = assess_web_pages_safe_active(
                pages=(page,),
                origin="https://example.test",
                authorized=True,
            )

        self.assertEqual(
            result.findings,
            (),
        )

    def test_request_limit_is_enforced(self):
        pages = tuple(
            CrawlPage(
                url=f"https://example.test/{index}",
                status=200,
                content_type="text/html",
                byte_count=10,
                links=(),
            )
            for index in range(4)
        )
        opener = _FakeOpener(
            {
                page.url: _FakeResponse(
                    url=page.url,
                    allow="GET, OPTIONS",
                )
                for page in pages
            }
        )

        with patch(
            "nightrecon.web_active_assessment.build_opener",
            return_value=opener,
        ):
            result = assess_web_pages_safe_active(
                pages=pages,
                origin="https://example.test",
                authorized=True,
                max_requests=2,
            )

        self.assertEqual(
            result.requests_attempted,
            2,
        )
        self.assertEqual(
            len(opener.requests),
            2,
        )

    def test_outside_origin_pages_are_never_requested(self):
        pages = (
            CrawlPage(
                url="https://example.test/",
                status=200,
                content_type="text/html",
                byte_count=10,
                links=(),
            ),
            CrawlPage(
                url="https://other.test/",
                status=200,
                content_type="text/html",
                byte_count=10,
                links=(),
            ),
        )
        opener = _FakeOpener(
            {
                "https://example.test/": _FakeResponse(
                    url="https://example.test/",
                    allow="GET, OPTIONS",
                )
            }
        )

        with patch(
            "nightrecon.web_active_assessment.build_opener",
            return_value=opener,
        ):
            result = assess_web_pages_safe_active(
                pages=pages,
                origin="https://example.test",
                authorized=True,
            )

        self.assertEqual(
            tuple(
                request[0]
                for request in opener.requests
            ),
            ("https://example.test/",),
        )
        self.assertTrue(
            any(
                error.startswith(
                    "outside_authorized_origin:"
                )
                for error in result.errors
            )
        )

    def test_redirect_handler_does_not_follow_redirects(self):
        handler = _NoRedirectHandler()

        self.assertIsNone(
            handler.redirect_request(
                None,
                None,
                302,
                "Found",
                {},
                "https://example.test/next",
            )
        )

    def test_invalid_limits_are_rejected(self):
        with self.assertRaises(ValueError):
            assess_web_pages_safe_active(
                pages=(),
                origin="https://example.test",
                authorized=True,
                timeout=0,
            )

        with self.assertRaises(ValueError):
            assess_web_pages_safe_active(
                pages=(),
                origin="https://example.test",
                authorized=True,
                max_requests=0,
            )

        with self.assertRaises(ValueError):
            assess_web_pages_safe_active(
                pages=(),
                origin="https://example.test",
                authorized=True,
                authorization="",
            )

        with self.assertRaises(ValueError):
            assess_web_pages_safe_active(
                pages=(),
                origin="https://example.test",
                authorized=True,
                cookie="",
            )


if __name__ == "__main__":
    unittest.main()
