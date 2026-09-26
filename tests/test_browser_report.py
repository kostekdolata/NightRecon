"""Tests for NightRecon non-secret browser discovery reporting."""

import unittest

from nightrecon.browser_playwright import (
    BrowserFormFieldObservation,
    BrowserFormObservation,
    BrowserPageObservation,
    PlaywrightDiscoveryResult,
)
from nightrecon.browser_policy import (
    BrowserDiscoveryPolicy,
    BrowserResourceKind,
    BrowserWorkerState,
)
from nightrecon.browser_report import BrowserDiscoveryReport
from nightrecon.browser_worker import (
    BrowserDiscoverySnapshot,
    BrowserDomObservation,
    BrowserRequestObservation,
    BrowserResponseObservation,
)
from nightrecon.session import ScanSession
from nightrecon.targets import parse_target


class BrowserReportTests(unittest.TestCase):
    def test_report_strips_query_fragment_and_raw_error_detail(self):
        secret = "browser-query-secret"
        session = ScanSession.create(
            target=parse_target("example.test"),
            scope_rules=("example.test",),
        )
        policy = BrowserDiscoveryPolicy(
            origin="https://example.test",
            max_requests=5,
            max_pages=2,
            max_runtime_seconds=10.0,
            max_response_bytes=4096,
            max_dom_bytes=8192,
            max_dom_items=50,
        )
        snapshot = BrowserDiscoverySnapshot(
            origin="https://example.test",
            state=BrowserWorkerState(
                requests_used=2,
                pages_used=1,
                runtime_seconds=0.5,
                max_requests=5,
                max_pages=2,
                max_runtime_seconds=10.0,
            ),
            requests=(
                BrowserRequestObservation(
                    url=(
                        "https://example.test/api"
                        f"?token={secret}#frag"
                    ),
                    method="GET",
                    resource_kind=BrowserResourceKind.XHR,
                    allowed=True,
                    reason="authorized",
                ),
                BrowserRequestObservation(
                    url="https://outside.test/script.js?api_key=outside-secret",
                    method="GET",
                    resource_kind=BrowserResourceKind.SCRIPT,
                    allowed=False,
                    reason="outside_authorized_origin",
                ),
            ),
            responses=(
                BrowserResponseObservation(
                    url=(
                        "https://example.test/api"
                        f"?token={secret}"
                    ),
                    status=200,
                    byte_count=128,
                    capture_allowed=True,
                    reason="authorized",
                ),
            ),
            dom_snapshots=(
                BrowserDomObservation(
                    url=(
                        "https://example.test/app"
                        f"?session={secret}"
                    ),
                    byte_count=512,
                    capture_allowed=True,
                    reason="authorized",
                ),
            ),
        )
        result = PlaywrightDiscoveryResult(
            page=BrowserPageObservation(
                url=(
                    "https://example.test/app"
                    f"?session={secret}#state"
                ),
                title="Dynamic App",
                links=(
                    (
                        "https://example.test/dashboard"
                        f"?token={secret}#section"
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
            snapshot=snapshot,
            error=(
                "RuntimeError: browser failed at "
                f"https://example.test/app?token={secret}"
            ),
        )

        report = BrowserDiscoveryReport.create(
            session=session,
            policy=policy,
            result=result,
        )
        data = report.to_dict()
        serialized = repr(data)

        self.assertEqual(
            report.status,
            "failed",
        )
        self.assertEqual(
            report.error,
            "RuntimeError",
        )
        self.assertEqual(
            report.page.url,
            "https://example.test/app",
        )
        self.assertEqual(
            report.page.links,
            ("https://example.test/dashboard",),
        )
        self.assertEqual(
            report.page.forms[0].action,
            "https://example.test/session",
        )
        self.assertEqual(
            report.requests[0].url,
            "https://example.test/api",
        )
        self.assertEqual(
            report.responses[0].url,
            "https://example.test/api",
        )
        self.assertEqual(
            report.dom_snapshots[0].url,
            "https://example.test/app",
        )
        self.assertNotIn(
            secret,
            serialized,
        )
        self.assertNotIn(
            "outside-secret",
            serialized,
        )
        self.assertNotIn(
            "?",
            report.page.url,
        )
        self.assertEqual(
            data["summary"]["requests_observed"],
            2,
        )
        self.assertEqual(
            data["summary"]["requests_allowed"],
            1,
        )
        self.assertEqual(
            data["summary"]["requests_blocked"],
            1,
        )

    def test_known_limit_error_code_is_preserved(self):
        session = ScanSession.create(
            target=parse_target("example.test"),
            scope_rules=("example.test",),
        )
        policy = BrowserDiscoveryPolicy(
            origin="https://example.test",
        )
        snapshot = BrowserDiscoverySnapshot(
            origin="https://example.test",
            state=BrowserWorkerState(
                requests_used=0,
                pages_used=0,
                runtime_seconds=0.0,
                max_requests=policy.max_requests,
                max_pages=policy.max_pages,
                max_runtime_seconds=policy.max_runtime_seconds,
            ),
            requests=(),
            responses=(),
            dom_snapshots=(),
        )
        report = BrowserDiscoveryReport.create(
            session=session,
            policy=policy,
            result=PlaywrightDiscoveryResult(
                page=None,
                snapshot=snapshot,
                error="dom_byte_limit_exceeded",
            ),
        )

        self.assertEqual(
            report.error,
            "dom_byte_limit_exceeded",
        )


if __name__ == "__main__":
    unittest.main()
