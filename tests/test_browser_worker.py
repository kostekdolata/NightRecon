"""Tests for NightRecon backend-neutral browser worker controller."""

import unittest

from nightrecon.browser_policy import (
    BrowserDiscoveryPolicy,
    BrowserResourceKind,
)
from nightrecon.browser_worker import BrowserDiscoveryController


class BrowserWorkerControllerTests(unittest.TestCase):
    def setUp(self):
        self.policy = BrowserDiscoveryPolicy(
            origin="https://example.test",
            max_requests=3,
            max_pages=2,
            max_runtime_seconds=5.0,
            max_response_bytes=128,
            max_dom_bytes=256,
        )
        self.controller = BrowserDiscoveryController(
            self.policy
        )

    def test_top_level_document_requires_policy_authorization(self):
        decision = self.controller.decide_request(
            url="https://example.test/",
            method="GET",
            resource_kind=BrowserResourceKind.DOCUMENT,
            top_level_document=True,
        )

        self.assertTrue(decision.allowed)
        self.controller.record_completed_request(
            decision=decision,
            document_loaded=True,
            elapsed_seconds=0.5,
        )

        snapshot = self.controller.snapshot()
        self.assertEqual(
            snapshot.state.requests_used,
            1,
        )
        self.assertEqual(
            snapshot.state.pages_used,
            1,
        )
        self.assertEqual(
            len(snapshot.requests),
            1,
        )
        self.assertTrue(
            snapshot.requests[0].allowed
        )

    def test_cross_origin_subresource_is_observed_and_denied(self):
        decision = self.controller.decide_request(
            url="https://cdn.other.test/app.js",
            method="GET",
            resource_kind=BrowserResourceKind.SCRIPT,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "outside_authorized_origin",
        )

        snapshot = self.controller.snapshot()
        self.assertEqual(
            len(snapshot.requests),
            1,
        )
        self.assertFalse(
            snapshot.requests[0].allowed
        )
        self.assertEqual(
            snapshot.state.requests_used,
            0,
        )

    def test_mutating_fetch_is_denied_before_state_changes(self):
        decision = self.controller.decide_request(
            url="https://example.test/api/update",
            method="POST",
            resource_kind=BrowserResourceKind.FETCH,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "method_not_allowed",
        )
        self.assertEqual(
            self.controller.state.requests_used,
            0,
        )

    def test_completed_subresources_consume_request_and_runtime_budgets(self):
        first = self.controller.decide_request(
            url="https://example.test/app.js",
            method="GET",
            resource_kind=BrowserResourceKind.SCRIPT,
        )
        self.controller.record_completed_request(
            decision=first,
            document_loaded=False,
            elapsed_seconds=1.0,
        )

        second = self.controller.decide_request(
            url="https://example.test/api/data",
            method="GET",
            resource_kind=BrowserResourceKind.XHR,
        )
        self.controller.record_completed_request(
            decision=second,
            document_loaded=False,
            elapsed_seconds=1.5,
        )

        snapshot = self.controller.snapshot()
        self.assertEqual(
            snapshot.state.requests_used,
            2,
        )
        self.assertEqual(
            snapshot.state.pages_used,
            0,
        )
        self.assertEqual(
            snapshot.state.runtime_seconds,
            2.5,
        )

    def test_interception_reserves_budget_before_network_continuation(self):
        first = self.controller.intercept_request(
            url="https://example.test/a.js",
            method="GET",
            resource_kind=BrowserResourceKind.SCRIPT,
        )
        second = self.controller.intercept_request(
            url="https://example.test/b.js",
            method="GET",
            resource_kind=BrowserResourceKind.SCRIPT,
        )
        third = self.controller.intercept_request(
            url="https://example.test/c.js",
            method="GET",
            resource_kind=BrowserResourceKind.SCRIPT,
        )
        blocked = self.controller.intercept_request(
            url="https://example.test/d.js",
            method="GET",
            resource_kind=BrowserResourceKind.SCRIPT,
        )

        self.assertTrue(first.allowed)
        self.assertTrue(second.allowed)
        self.assertTrue(third.allowed)
        self.assertFalse(blocked.allowed)
        self.assertEqual(
            blocked.reason,
            "request_budget_exhausted",
        )
        self.assertEqual(
            self.controller.state.requests_used,
            3,
        )

    def test_intercepted_document_reserves_page_budget_immediately(self):
        first = self.controller.intercept_request(
            url="https://example.test/one",
            method="GET",
            resource_kind=BrowserResourceKind.DOCUMENT,
            top_level_document=True,
        )
        second = self.controller.intercept_request(
            url="https://example.test/two",
            method="GET",
            resource_kind=BrowserResourceKind.DOCUMENT,
            top_level_document=True,
        )
        blocked = self.controller.intercept_request(
            url="https://example.test/three",
            method="GET",
            resource_kind=BrowserResourceKind.DOCUMENT,
            top_level_document=True,
        )

        self.assertTrue(first.allowed)
        self.assertTrue(second.allowed)
        self.assertFalse(blocked.allowed)
        self.assertEqual(
            blocked.reason,
            "page_budget_exhausted",
        )
        self.assertEqual(
            self.controller.state.pages_used,
            2,
        )

    def test_runtime_can_be_accounted_without_double_counting_requests(self):
        decision = self.controller.intercept_request(
            url="https://example.test/app.js",
            method="GET",
            resource_kind=BrowserResourceKind.SCRIPT,
        )
        self.assertTrue(decision.allowed)

        self.controller.add_runtime_elapsed(
            elapsed_seconds=1.25,
        )

        self.assertEqual(
            self.controller.state.requests_used,
            1,
        )
        self.assertEqual(
            self.controller.state.runtime_seconds,
            1.25,
        )

        with self.assertRaises(ValueError):
            self.controller.add_runtime_elapsed(
                elapsed_seconds=4.0,
            )

    def test_request_budget_blocks_later_interception(self):
        for path in (
            "/a.js",
            "/b.js",
            "/c.js",
        ):
            decision = self.controller.decide_request(
                url=f"https://example.test{path}",
                method="GET",
                resource_kind=BrowserResourceKind.SCRIPT,
            )
            self.assertTrue(decision.allowed)
            self.controller.record_completed_request(
                decision=decision,
                document_loaded=False,
                elapsed_seconds=0.1,
            )

        blocked = self.controller.decide_request(
            url="https://example.test/d.js",
            method="GET",
            resource_kind=BrowserResourceKind.SCRIPT,
        )

        self.assertFalse(blocked.allowed)
        self.assertEqual(
            blocked.reason,
            "request_budget_exhausted",
        )

    def test_response_capture_ceiling_is_recorded_without_body_data(self):
        allowed = self.controller.record_response(
            url="https://example.test/api",
            status=200,
            byte_count=128,
        )
        blocked = self.controller.record_response(
            url="https://example.test/large",
            status=200,
            byte_count=129,
        )

        self.assertTrue(
            allowed.capture_allowed
        )
        self.assertFalse(
            blocked.capture_allowed
        )
        self.assertEqual(
            blocked.reason,
            "response_byte_limit_exceeded",
        )

        snapshot = self.controller.snapshot()
        self.assertEqual(
            len(snapshot.responses),
            2,
        )
        self.assertFalse(
            hasattr(
                snapshot.responses[0],
                "body",
            )
        )

    def test_dom_ceiling_is_recorded_without_dom_content(self):
        allowed = self.controller.record_dom_snapshot(
            url="https://example.test/",
            byte_count=256,
        )
        blocked = self.controller.record_dom_snapshot(
            url="https://example.test/huge",
            byte_count=257,
        )

        self.assertTrue(
            allowed.capture_allowed
        )
        self.assertFalse(
            blocked.capture_allowed
        )
        self.assertEqual(
            blocked.reason,
            "dom_byte_limit_exceeded",
        )

        snapshot = self.controller.snapshot()
        self.assertFalse(
            hasattr(
                snapshot.dom_snapshots[0],
                "html",
            )
        )
        self.assertFalse(
            hasattr(
                snapshot.dom_snapshots[0],
                "content",
            )
        )

    def test_page_budget_blocks_third_top_level_document(self):
        for path in (
            "/one",
            "/two",
        ):
            decision = self.controller.decide_request(
                url=f"https://example.test{path}",
                method="GET",
                resource_kind=BrowserResourceKind.DOCUMENT,
                top_level_document=True,
            )
            self.assertTrue(decision.allowed)
            self.controller.record_completed_request(
                decision=decision,
                document_loaded=True,
                elapsed_seconds=0.2,
            )

        blocked = self.controller.decide_request(
            url="https://example.test/three",
            method="GET",
            resource_kind=BrowserResourceKind.DOCUMENT,
            top_level_document=True,
        )

        self.assertFalse(blocked.allowed)
        self.assertEqual(
            blocked.reason,
            "page_budget_exhausted",
        )

    def test_snapshot_is_non_secret_metadata_only(self):
        decision = self.controller.decide_request(
            url="https://example.test/",
            method="GET",
            resource_kind=BrowserResourceKind.DOCUMENT,
            top_level_document=True,
        )
        self.controller.record_completed_request(
            decision=decision,
            document_loaded=True,
            elapsed_seconds=0.1,
        )
        snapshot = self.controller.snapshot()

        serialized = repr(snapshot)
        self.assertNotIn(
            "authorization",
            serialized.lower(),
        )
        self.assertNotIn(
            "cookie",
            serialized.lower(),
        )
        self.assertNotIn(
            "javascript",
            serialized.lower(),
        )


if __name__ == "__main__":
    unittest.main()
