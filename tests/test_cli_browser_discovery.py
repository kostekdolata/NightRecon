"""CLI tests for NightRecon browser-powered discovery."""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon.browser_playwright import (
    BrowserFormFieldObservation,
    BrowserFormObservation,
    BrowserPageObservation,
    BrowserRuntimeUnavailable,
    PlaywrightDiscoveryResult,
)
from nightrecon.browser_policy import (
    BrowserResourceKind,
    BrowserWorkerState,
)
from nightrecon.browser_worker import (
    BrowserDiscoverySnapshot,
    BrowserDomObservation,
    BrowserRequestObservation,
    BrowserResponseObservation,
)
from nightrecon.cli import main
from nightrecon.web_crawl import (
    CrawlPage,
    CrawlResult,
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
                links=(),
            ),
        ),
        max_pages=50,
        max_bytes_per_page=1_048_576,
    )


def _browser_result(secret="dynamic-query-secret"):
    return PlaywrightDiscoveryResult(
        page=BrowserPageObservation(
            url=(
                "https://example.test/app"
                f"?state={secret}"
            ),
            title="Dynamic Browser App",
            links=(
                (
                    "https://example.test/spa"
                    f"?token={secret}#route"
                ),
            ),
            forms=(
                BrowserFormObservation(
                    action=(
                        "https://example.test/session"
                        f"?csrf={secret}"
                    ),
                    method="POST",
                    inputs=(
                        BrowserFormFieldObservation(
                            name="csrf_token",
                            input_type="hidden",
                        ),
                    ),
                ),
            ),
        ),
        snapshot=BrowserDiscoverySnapshot(
            origin="https://example.test",
            state=BrowserWorkerState(
                requests_used=2,
                pages_used=1,
                runtime_seconds=0.25,
                max_requests=7,
                max_pages=3,
                max_runtime_seconds=4.0,
            ),
            requests=(
                BrowserRequestObservation(
                    url=(
                        "https://example.test/app.js"
                        f"?key={secret}"
                    ),
                    method="GET",
                    resource_kind=BrowserResourceKind.SCRIPT,
                    allowed=True,
                    reason="authorized",
                ),
                BrowserRequestObservation(
                    url="https://outside.test/script.js?key=outside-secret",
                    method="GET",
                    resource_kind=BrowserResourceKind.SCRIPT,
                    allowed=False,
                    reason="outside_authorized_origin",
                ),
            ),
            responses=(
                BrowserResponseObservation(
                    url=(
                        "https://example.test/app.js"
                        f"?key={secret}"
                    ),
                    status=200,
                    byte_count=64,
                    capture_allowed=True,
                    reason="authorized",
                ),
            ),
            dom_snapshots=(
                BrowserDomObservation(
                    url=(
                        "https://example.test/app"
                        f"?state={secret}"
                    ),
                    byte_count=256,
                    capture_allowed=True,
                    reason="authorized",
                ),
            ),
        ),
        error=None,
    )


class CliBrowserDiscoveryTests(unittest.TestCase):
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

    def test_browser_discovery_is_disabled_by_default(self):
        crawl = _crawl_result()

        with patch(
            "nightrecon.cli.crawl_site",
            return_value=crawl,
        ):
            with patch(
                "nightrecon.cli.discover_with_playwright"
            ) as browser:
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
            "Browser Discovery Summary:",
            stdout,
        )
        browser.assert_not_called()
        (
            store_class.return_value
            .save_browser_discovery_report
            .assert_not_called()
        )

    def test_browser_discovery_is_explicit_bounded_and_redacted(self):
        crawl = _crawl_result()
        secret = "dynamic-query-secret"
        result = _browser_result(
            secret
        )

        with patch(
            "nightrecon.cli.crawl_site",
            return_value=crawl,
        ):
            with patch(
                "nightrecon.cli.discover_with_playwright",
                return_value=result,
            ) as browser:
                with patch(
                    "nightrecon.cli.ResultStore"
                ) as store_class:
                    store_class.return_value.save_web_crawl_report.return_value = (
                        Path("results/crawl.json")
                    )
                    store_class.return_value.save_browser_discovery_report.return_value = (
                        Path("results/crawl-browser.json")
                    )

                    with patch(
                        "nightrecon.cli.NightReconLogger"
                    ) as logger_class:
                        code, stdout, stderr = self.run_cli(
                            "crawl",
                            "https://example.test/",
                            "--scope",
                            "example.test",
                            "--browser-discovery",
                            "--browser-max-requests",
                            "7",
                            "--browser-max-pages",
                            "3",
                            "--browser-max-runtime",
                            "4",
                            "--browser-max-response-bytes",
                            "2048",
                            "--browser-max-dom-bytes",
                            "4096",
                            "--browser-max-dom-items",
                            "25",
                        )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "Browser Discovery Summary: status=completed requests=2 blocked=1 links=1 forms=1",
            stdout,
        )
        self.assertIn(
            "BROWSER LINK https://example.test/spa",
            stdout,
        )
        self.assertIn(
            "BROWSER FORM method=POST action=https://example.test/session",
            stdout,
        )
        self.assertNotIn(
            secret,
            stdout,
        )
        self.assertNotIn(
            "outside-secret",
            stdout,
        )

        kwargs = browser.call_args.kwargs
        self.assertEqual(
            kwargs["start_url"],
            "https://example.test/",
        )
        self.assertTrue(
            kwargs["headless"],
        )
        policy = kwargs["policy"]
        self.assertEqual(
            policy.max_requests,
            7,
        )
        self.assertEqual(
            policy.max_pages,
            3,
        )
        self.assertEqual(
            policy.max_runtime_seconds,
            4.0,
        )
        self.assertEqual(
            policy.max_response_bytes,
            2048,
        )
        self.assertEqual(
            policy.max_dom_bytes,
            4096,
        )
        self.assertEqual(
            policy.max_dom_items,
            25,
        )

        report = (
            store_class.return_value
            .save_browser_discovery_report
            .call_args.args[0]
        )
        serialized = repr(
            report.to_dict()
        )
        self.assertNotIn(
            secret,
            serialized,
        )
        self.assertNotIn(
            "outside-secret",
            serialized,
        )
        self.assertEqual(
            report.page.links,
            ("https://example.test/spa",),
        )
        self.assertEqual(
            report.page.forms[0].action,
            "https://example.test/session",
        )

        audit = repr(
            logger_class.return_value.write.call_args_list
        )
        self.assertNotIn(
            secret,
            audit,
        )
        self.assertNotIn(
            "outside-secret",
            audit,
        )

    def test_browser_discovery_rejects_authenticated_crawl_context_before_network(self):
        for auth_args in (
            (
                "--authorization-env",
                "NIGHTRECON_AUTH",
            ),
            (
                "--cookie-env",
                "NIGHTRECON_COOKIE",
            ),
            (
                "--session-cookies",
            ),
        ):
            with self.subTest(
                auth_args=auth_args
            ):
                with patch(
                    "nightrecon.cli.crawl_site"
                ) as crawl_site:
                    with patch(
                        "nightrecon.cli.discover_with_playwright"
                    ) as browser:
                        code, stdout, stderr = self.run_cli(
                            "crawl",
                            "https://example.test/",
                            "--scope",
                            "example.test",
                            "--browser-discovery",
                            *auth_args,
                        )

                self.assertEqual(code, 2)
                self.assertEqual(stdout, "")
                self.assertIn(
                    "does not yet accept authenticated crawl context",
                    stderr,
                )
                crawl_site.assert_not_called()
                browser.assert_not_called()

    def test_browser_discovery_rejects_query_bearing_start_url_before_network(self):
        secret = "start-query-secret"

        with patch(
            "nightrecon.cli.crawl_site"
        ) as crawl_site:
            with patch(
                "nightrecon.cli.discover_with_playwright"
            ) as browser:
                code, stdout, stderr = self.run_cli(
                    "crawl",
                    (
                        "https://example.test/"
                        f"?token={secret}"
                    ),
                    "--scope",
                    "example.test",
                    "--browser-discovery",
                )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "must not include a query string",
            stderr,
        )
        self.assertNotIn(
            secret,
            stderr,
        )
        crawl_site.assert_not_called()
        browser.assert_not_called()

    def test_invalid_browser_limits_are_rejected_before_network(self):
        with patch(
            "nightrecon.cli.crawl_site"
        ) as crawl_site:
            with patch(
                "nightrecon.cli.discover_with_playwright"
            ) as browser:
                code, stdout, stderr = self.run_cli(
                    "crawl",
                    "https://example.test/",
                    "--scope",
                    "example.test",
                    "--browser-discovery",
                    "--browser-max-requests",
                    "0",
                )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "max_requests must be at least 1",
            stderr,
        )
        crawl_site.assert_not_called()
        browser.assert_not_called()

    def test_missing_browser_runtime_fails_with_generic_message_and_safe_audit(self):
        crawl = _crawl_result()

        with patch(
            "nightrecon.cli.crawl_site",
            return_value=crawl,
        ):
            with patch(
                "nightrecon.cli.discover_with_playwright",
                side_effect=BrowserRuntimeUnavailable(
                    "internal runtime detail with secret-value"
                ),
            ):
                with patch(
                    "nightrecon.cli.NightReconLogger"
                ) as logger_class:
                    code, stdout, stderr = self.run_cli(
                        "crawl",
                        "https://example.test/",
                        "--scope",
                        "example.test",
                        "--browser-discovery",
                    )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "Browser runtime unavailable",
            stderr,
        )
        self.assertNotIn(
            "secret-value",
            stderr,
        )

        calls = (
            logger_class.return_value
            .write.call_args_list
        )
        self.assertEqual(
            len(calls),
            1,
        )
        self.assertEqual(
            calls[0].args[0],
            "crawl.browser_failed",
        )
        kwargs = calls[0].kwargs
        self.assertEqual(
            kwargs["origin"],
            "https://example.test",
        )
        self.assertEqual(
            kwargs["reason"],
            "browser_runtime_unavailable",
        )
        self.assertNotIn(
            "url",
            kwargs,
        )
        self.assertNotIn(
            "secret-value",
            repr(calls),
        )


if __name__ == "__main__":
    unittest.main()
