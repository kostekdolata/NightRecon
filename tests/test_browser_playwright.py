"""Tests for NightRecon optional Playwright browser adapter."""

import unittest
from unittest.mock import patch

from nightrecon.browser_playwright import (
    BrowserRuntimeUnavailable,
    discover_with_playwright,
)
from nightrecon.browser_policy import BrowserDiscoveryPolicy


class _FakeRequest:
    def __init__(
        self,
        *,
        url,
        method="GET",
        resource_type="document",
        navigation=False,
    ):
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self._navigation = navigation

    def is_navigation_request(self):
        return self._navigation


class _FakeApiResponse:
    def __init__(
        self,
        status=200,
        content_length="64",
        location=None,
    ):
        self.status = status
        self.headers = {
            "content-length": content_length,
        }

        if location is not None:
            self.headers["location"] = location


class _FakeRoute:
    def __init__(self, request):
        self.request = request
        self.continued = False
        self.aborted = False
        self.abort_code = None
        self.fetch_kwargs = None
        self.fulfilled = False
        self.fulfilled_response = None

    def continue_(self):
        self.continued = True

    def fetch(self, **kwargs):
        self.fetch_kwargs = kwargs

        if self.request.url.endswith("/redirect"):
            return _FakeApiResponse(
                status=302,
                content_length="0",
                location="https://outside.test/escaped",
            )

        return _FakeApiResponse()

    def fulfill(self, *, response):
        self.fulfilled = True
        self.fulfilled_response = response

    def abort(self, error_code=None):
        self.aborted = True
        self.abort_code = error_code


class _FakePage:
    def __init__(self, context):
        self._context = context
        self.url = ""
        self.default_timeout = None
        self.navigation_timeout = None
        self.goto_args = None
        self.routes = []

    def set_default_timeout(self, timeout):
        self.default_timeout = timeout

    def set_default_navigation_timeout(self, timeout):
        self.navigation_timeout = timeout

    def goto(self, url, *, wait_until, timeout):
        self.goto_args = (
            url,
            wait_until,
            timeout,
        )

        requests = (
            _FakeRequest(
                url=url,
                method="GET",
                resource_type="document",
                navigation=True,
            ),
            _FakeRequest(
                url="https://example.test/app.js",
                method="GET",
                resource_type="script",
            ),
            _FakeRequest(
                url="https://cdn.other.test/external.js",
                method="GET",
                resource_type="script",
            ),
            _FakeRequest(
                url="https://example.test/api/update",
                method="POST",
                resource_type="fetch",
            ),
        )

        for index, request in enumerate(requests):
            route = _FakeRoute(
                request
            )
            self._context.route_handler(
                route
            )
            self.routes.append(route)

            if index == 0 and route.aborted:
                raise RuntimeError(
                    "navigation blocked"
                )

        self.url = url
        return object()

    def evaluate(self, script, max_items):
        self.evaluate_script = script
        self.evaluate_max_items = max_items
        return {
            "title": "Dynamic App",
            "links": [
                "https://example.test/dashboard#section",
                "/profile",
                "https://outside.test/admin",
                "javascript:void(0)",
                "/profile",
            ],
            "forms": [
                {
                    "action": "/session",
                    "method": "POST",
                    "inputs": [
                        {
                            "name": "username",
                            "type": "text",
                        },
                        {
                            "name": "csrf_token",
                            "type": "hidden",
                        },
                    ],
                },
                {
                    "action": "https://outside.test/submit",
                    "method": "POST",
                    "inputs": [],
                },
            ],
        }


class _FakeContext:
    def __init__(self):
        self.route_pattern = None
        self.route_handler = None
        self.closed = False
        self.page = _FakePage(self)

    def route(self, pattern, handler):
        self.route_pattern = pattern
        self.route_handler = handler

    def new_page(self):
        return self.page

    def close(self):
        self.closed = True


class _FakeBrowser:
    def __init__(self):
        self.context_kwargs = None
        self.context = _FakeContext()
        self.closed = False

    def new_context(self, **kwargs):
        self.context_kwargs = kwargs
        return self.context

    def close(self):
        self.closed = True


class _FakeChromium:
    def __init__(self):
        self.launch_kwargs = None
        self.browser = _FakeBrowser()

    def launch(self, **kwargs):
        self.launch_kwargs = kwargs
        return self.browser


class _FakePlaywright:
    def __init__(self):
        self.chromium = _FakeChromium()


class _FakeFactoryContext:
    def __init__(self, playwright):
        self.playwright = playwright

    def __enter__(self):
        return self.playwright

    def __exit__(
        self,
        exc_type,
        exc,
        tb,
    ):
        return False


class _FakeFactory:
    def __init__(self):
        self.playwright = _FakePlaywright()

    def __call__(self):
        return _FakeFactoryContext(
            self.playwright
        )


class PlaywrightBrowserAdapterTests(unittest.TestCase):
    def setUp(self):
        self.policy = BrowserDiscoveryPolicy(
            origin="https://example.test",
            max_requests=10,
            max_pages=2,
            max_runtime_seconds=5.0,
            max_response_bytes=1024,
            max_dom_bytes=4096,
            max_dom_items=10,
        )

    def test_adapter_routes_every_request_through_nightrecon_policy(self):
        factory = _FakeFactory()
        times = iter(
            (
                10.0,
                10.5,
            )
        )

        result = discover_with_playwright(
            start_url="https://example.test/",
            policy=self.policy,
            playwright_factory=factory,
            clock=lambda: next(times),
        )

        self.assertIsNone(result.error)
        self.assertIsNotNone(result.page)
        self.assertEqual(
            result.page.title,
            "Dynamic App",
        )
        self.assertEqual(
            result.page.links,
            (
                "https://example.test/dashboard",
                "https://example.test/profile",
            ),
        )
        self.assertEqual(
            len(result.page.forms),
            2,
        )
        self.assertEqual(
            result.page.forms[0].action,
            "https://example.test/session",
        )
        self.assertEqual(
            result.page.forms[1].action,
            "",
        )

        browser = (
            factory.playwright
            .chromium.browser
        )
        context = browser.context
        page = context.page

        self.assertEqual(
            factory.playwright.chromium.launch_kwargs,
            {
                "headless": True,
            },
        )
        self.assertEqual(
            browser.context_kwargs,
            {
                "service_workers": "block",
            },
        )
        self.assertEqual(
            context.route_pattern,
            "**/*",
        )
        self.assertEqual(
            page.routes[0].fetch_kwargs,
            {
                "max_redirects": 0,
                "timeout": 5000,
            },
        )
        self.assertEqual(
            page.default_timeout,
            5000,
        )
        self.assertEqual(
            page.navigation_timeout,
            5000,
        )

        self.assertTrue(
            page.routes[0].fulfilled
        )
        self.assertTrue(
            page.routes[1].fulfilled
        )
        self.assertTrue(
            page.routes[2].aborted
        )
        self.assertEqual(
            page.routes[2].abort_code,
            "blockedbyclient",
        )
        self.assertTrue(
            page.routes[3].aborted
        )

        snapshot = result.snapshot
        self.assertEqual(
            snapshot.state.requests_used,
            2,
        )
        self.assertEqual(
            snapshot.state.pages_used,
            1,
        )
        self.assertEqual(
            snapshot.state.runtime_seconds,
            0.5,
        )
        self.assertEqual(
            len(snapshot.requests),
            4,
        )
        self.assertEqual(
            snapshot.requests[2].reason,
            "outside_authorized_origin",
        )
        self.assertEqual(
            snapshot.requests[3].reason,
            "method_not_allowed",
        )
        self.assertTrue(
            browser.closed
        )
        self.assertTrue(
            context.closed
        )

    def test_authorization_header_is_ephemeral_browser_context_only(self):
        factory = _FakeFactory()
        times = iter((10.0, 10.1))
        secret = "Bearer browser-runtime-secret"

        result = discover_with_playwright(
            start_url="https://example.test/",
            policy=self.policy,
            authorization=secret,
            playwright_factory=factory,
            clock=lambda: next(times),
        )

        self.assertIsNone(result.error)
        browser = factory.playwright.chromium.browser
        self.assertEqual(
            browser.context_kwargs,
            {
                "service_workers": "block",
                "extra_http_headers": {
                    "Authorization": secret,
                },
            },
        )
        self.assertNotIn(secret, repr(result))

    def test_start_url_must_match_policy_origin_before_browser_launch(self):
        factory = _FakeFactory()

        with self.assertRaises(PermissionError):
            discover_with_playwright(
                start_url="https://outside.test/",
                policy=self.policy,
                playwright_factory=factory,
            )

        self.assertIsNone(
            factory.playwright.chromium.launch_kwargs
        )

    def test_redirect_response_is_blocked_before_browser_followup(self):
        factory = _FakeFactory()
        times = iter(
            (
                2.0,
            )
        )

        result = discover_with_playwright(
            start_url="https://example.test/redirect",
            policy=self.policy,
            playwright_factory=factory,
            clock=lambda: next(times),
        )

        self.assertIsNone(
            result.page
        )
        self.assertIn(
            "navigation blocked",
            result.error,
        )
        route = (
            factory.playwright
            .chromium.browser.context.page.routes[0]
        )
        self.assertTrue(
            route.aborted
        )
        self.assertFalse(
            route.fulfilled
        )
        self.assertEqual(
            route.abort_code,
            "blockedbyresponse",
        )
        self.assertEqual(
            route.fetch_kwargs["max_redirects"],
            0,
        )

    def test_dom_metadata_over_ceiling_is_discarded(self):
        factory = _FakeFactory()
        tiny_policy = BrowserDiscoveryPolicy(
            origin="https://example.test",
            max_requests=10,
            max_pages=2,
            max_runtime_seconds=5.0,
            max_response_bytes=1024,
            max_dom_bytes=16,
            max_dom_items=10,
        )
        times = iter(
            (
                1.0,
                1.1,
            )
        )

        result = discover_with_playwright(
            start_url="https://example.test/",
            policy=tiny_policy,
            playwright_factory=factory,
            clock=lambda: next(times),
        )

        self.assertIsNone(
            result.page
        )
        self.assertEqual(
            result.error,
            "dom_byte_limit_exceeded",
        )
        self.assertEqual(
            result.snapshot.dom_snapshots[0].reason,
            "dom_byte_limit_exceeded",
        )

    def test_request_budget_blocks_resources_before_continue(self):
        factory = _FakeFactory()
        tight_policy = BrowserDiscoveryPolicy(
            origin="https://example.test",
            max_requests=1,
            max_pages=1,
            max_runtime_seconds=5.0,
            max_response_bytes=1024,
            max_dom_bytes=4096,
            max_dom_items=10,
        )
        times = iter(
            (
                3.0,
                3.1,
            )
        )

        result = discover_with_playwright(
            start_url="https://example.test/",
            policy=tight_policy,
            playwright_factory=factory,
            clock=lambda: next(times),
        )

        page = (
            factory.playwright
            .chromium.browser.context.page
        )

        self.assertIsNone(
            result.error
        )
        self.assertTrue(
            page.routes[0].fulfilled
        )
        self.assertTrue(
            page.routes[1].aborted
        )
        self.assertEqual(
            result.snapshot.requests[1].reason,
            "request_budget_exhausted",
        )

    def test_runtime_budget_failure_returns_non_secret_error(self):
        factory = _FakeFactory()
        times = iter(
            (
                1.0,
                10.0,
            )
        )

        result = discover_with_playwright(
            start_url="https://example.test/",
            policy=self.policy,
            playwright_factory=factory,
            clock=lambda: next(times),
        )

        self.assertIsNone(
            result.page
        )
        self.assertIn(
            "Browser runtime budget exceeded",
            result.error,
        )
        self.assertNotIn(
            "cookie",
            repr(result).lower(),
        )
        self.assertNotIn(
            "authorization",
            repr(result).lower(),
        )

    def test_missing_optional_runtime_has_clear_error(self):
        with patch(
            "nightrecon.browser_playwright._load_sync_playwright",
            side_effect=BrowserRuntimeUnavailable(
                "browser runtime missing"
            ),
        ):
            with self.assertRaises(
                BrowserRuntimeUnavailable
            ):
                discover_with_playwright(
                    start_url="https://example.test/",
                    policy=self.policy,
                )


class BrowserPolicyDomItemTests(unittest.TestCase):
    def test_dom_item_limit_must_be_positive(self):
        with self.assertRaises(ValueError):
            BrowserDiscoveryPolicy(
                origin="https://example.test",
                max_dom_items=0,
            )


if __name__ == "__main__":
    unittest.main()
