"""Tests for NightRecon browser discovery safety policy."""

import unittest

from nightrecon.browser_policy import (
    BrowserDiscoveryPolicy,
    BrowserRequest,
    BrowserRequestDecision,
    BrowserResourceKind,
    BrowserWorkerState,
    advance_browser_worker_state,
    authorize_browser_request,
    authorize_dom_snapshot,
    authorize_new_document,
    authorize_response_capture,
)


def _policy():
    return BrowserDiscoveryPolicy(
        origin="https://example.test",
        max_requests=3,
        max_pages=2,
        max_runtime_seconds=5.0,
        max_response_bytes=1024,
        max_dom_bytes=2048,
    )


def _state():
    return BrowserWorkerState(
        requests_used=0,
        pages_used=0,
        runtime_seconds=0.0,
        max_requests=3,
        max_pages=2,
        max_runtime_seconds=5.0,
    )


class BrowserPolicyTests(unittest.TestCase):
    def test_same_origin_get_is_authorized(self):
        decision = authorize_browser_request(
            request=BrowserRequest(
                url="https://example.test/app.js#x",
                method="get",
                resource_kind=BrowserResourceKind.SCRIPT,
            ),
            policy=_policy(),
            state=_state(),
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "authorized",
        )
        self.assertEqual(
            decision.normalized_url,
            "https://example.test/app.js",
        )
        self.assertEqual(
            decision.method,
            "GET",
        )

    def test_cross_origin_request_is_rejected(self):
        decision = authorize_browser_request(
            request=BrowserRequest(
                url="https://cdn.other.test/app.js",
                method="GET",
                resource_kind=BrowserResourceKind.SCRIPT,
            ),
            policy=_policy(),
            state=_state(),
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "outside_authorized_origin",
        )

    def test_mutating_method_is_rejected_by_default(self):
        decision = authorize_browser_request(
            request=BrowserRequest(
                url="https://example.test/api/update",
                method="POST",
                resource_kind=BrowserResourceKind.FETCH,
            ),
            policy=_policy(),
            state=_state(),
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "method_not_allowed",
        )

    def test_request_budget_is_enforced(self):
        state = BrowserWorkerState(
            requests_used=3,
            pages_used=1,
            runtime_seconds=1.0,
            max_requests=3,
            max_pages=2,
            max_runtime_seconds=5.0,
        )

        decision = authorize_browser_request(
            request=BrowserRequest(
                url="https://example.test/api",
                method="GET",
                resource_kind=BrowserResourceKind.XHR,
            ),
            policy=_policy(),
            state=state,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "request_budget_exhausted",
        )

    def test_runtime_budget_is_enforced(self):
        state = BrowserWorkerState(
            requests_used=1,
            pages_used=1,
            runtime_seconds=5.0,
            max_requests=3,
            max_pages=2,
            max_runtime_seconds=5.0,
        )

        decision = authorize_browser_request(
            request=BrowserRequest(
                url="https://example.test/api",
                method="GET",
                resource_kind=BrowserResourceKind.XHR,
            ),
            policy=_policy(),
            state=state,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "runtime_budget_exhausted",
        )

    def test_document_page_budget_is_enforced(self):
        state = BrowserWorkerState(
            requests_used=1,
            pages_used=2,
            runtime_seconds=1.0,
            max_requests=3,
            max_pages=2,
            max_runtime_seconds=5.0,
        )

        decision = authorize_new_document(
            url="https://example.test/dashboard",
            policy=_policy(),
            state=state,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "page_budget_exhausted",
        )

    def test_authorized_document_can_advance_immutable_state(self):
        state = _state()
        decision = authorize_new_document(
            url="https://example.test/",
            policy=_policy(),
            state=state,
        )

        advanced = advance_browser_worker_state(
            state=state,
            request_decision=decision,
            document_loaded=True,
            elapsed_seconds=0.5,
        )

        self.assertEqual(
            state.requests_used,
            0,
        )
        self.assertEqual(
            advanced.requests_used,
            1,
        )
        self.assertEqual(
            advanced.pages_used,
            1,
        )
        self.assertEqual(
            advanced.runtime_seconds,
            0.5,
        )
        self.assertEqual(
            advanced.requests_remaining,
            2,
        )
        self.assertEqual(
            advanced.pages_remaining,
            1,
        )

    def test_denied_request_cannot_advance_state(self):
        decision = BrowserRequestDecision(
            allowed=False,
            reason="outside_authorized_origin",
            normalized_url="https://outside.test/",
            method="GET",
            resource_kind=BrowserResourceKind.DOCUMENT,
        )

        with self.assertRaises(PermissionError):
            advance_browser_worker_state(
                state=_state(),
                request_decision=decision,
                document_loaded=True,
                elapsed_seconds=0.1,
            )

    def test_response_capture_ceiling(self):
        permitted = authorize_response_capture(
            byte_count=1024,
            policy=_policy(),
        )
        blocked = authorize_response_capture(
            byte_count=1025,
            policy=_policy(),
        )

        self.assertTrue(permitted.allowed)
        self.assertFalse(blocked.allowed)
        self.assertEqual(
            blocked.reason,
            "response_byte_limit_exceeded",
        )

    def test_dom_snapshot_ceiling(self):
        permitted = authorize_dom_snapshot(
            byte_count=2048,
            policy=_policy(),
        )
        blocked = authorize_dom_snapshot(
            byte_count=2049,
            policy=_policy(),
        )

        self.assertTrue(permitted.allowed)
        self.assertFalse(blocked.allowed)
        self.assertEqual(
            blocked.reason,
            "dom_byte_limit_exceeded",
        )

    def test_invalid_limits_fail_closed(self):
        with self.assertRaises(ValueError):
            BrowserDiscoveryPolicy(
                origin="https://example.test",
                max_requests=0,
            )

        with self.assertRaises(ValueError):
            BrowserDiscoveryPolicy(
                origin="https://example.test",
                max_pages=0,
            )

        with self.assertRaises(ValueError):
            BrowserDiscoveryPolicy(
                origin="https://example.test",
                max_runtime_seconds=0,
            )

        with self.assertRaises(ValueError):
            BrowserDiscoveryPolicy(
                origin="https://example.test",
                max_response_bytes=0,
            )

        with self.assertRaises(ValueError):
            BrowserDiscoveryPolicy(
                origin="https://example.test",
                max_dom_bytes=0,
            )

        with self.assertRaises(ValueError):
            BrowserDiscoveryPolicy(
                origin="https://example.test",
                allowed_methods=(),
            )

    def test_negative_accounting_values_fail_closed(self):
        with self.assertRaises(ValueError):
            authorize_browser_request(
                request=BrowserRequest(
                    url="https://example.test/",
                    method="GET",
                    resource_kind=BrowserResourceKind.DOCUMENT,
                ),
                policy=_policy(),
                state=BrowserWorkerState(
                    requests_used=-1,
                    pages_used=0,
                    runtime_seconds=0,
                    max_requests=3,
                    max_pages=2,
                    max_runtime_seconds=5,
                ),
            )

        with self.assertRaises(ValueError):
            authorize_response_capture(
                byte_count=-1,
                policy=_policy(),
            )

        with self.assertRaises(ValueError):
            authorize_dom_snapshot(
                byte_count=-1,
                policy=_policy(),
            )


if __name__ == "__main__":
    unittest.main()
