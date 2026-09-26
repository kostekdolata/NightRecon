"""Tests for bounded NightRecon workflow navigation execution."""

import unittest
from http.cookiejar import CookieJar
from unittest.mock import patch

from nightrecon.web_crawl import (
    CrawlPage,
    CrawlResult,
)
from nightrecon.web_workflow import (
    WorkflowAction,
    WorkflowActionKind,
    WorkflowPolicy,
    WorkflowState,
    authorize_workflow_action,
)
from nightrecon.web_workflow_execution import (
    execute_workflow_navigation,
)


def _state() -> WorkflowState:
    return WorkflowState(
        current_url="https://example.test/",
        visited_urls=(
            "https://example.test/",
        ),
        actions_used=0,
        max_actions=3,
    )


def _authorized_action():
    policy = WorkflowPolicy(
        origin="https://example.test",
        max_actions=3,
    )
    action = WorkflowAction(
        kind=WorkflowActionKind.NAVIGATE,
        source_url="https://example.test/",
        target_url="https://example.test/dashboard",
        method="GET",
    )
    decision = authorize_workflow_action(
        action=action,
        policy=policy,
        actions_used=0,
    )
    return action, decision


class WebWorkflowExecutionTests(unittest.TestCase):
    def test_authorized_get_uses_single_page_bounded_crawler(self):
        action, decision = _authorized_action()
        crawl = CrawlResult(
            start_url="https://example.test/dashboard",
            origin="https://example.test",
            pages=(
                CrawlPage(
                    url="https://example.test/dashboard",
                    status=200,
                    content_type="text/html",
                    byte_count=100,
                    links=(),
                    title="Dashboard",
                ),
            ),
            max_pages=1,
            max_bytes_per_page=4096,
        )

        with patch(
            "nightrecon.web_workflow_execution.crawl_site",
            return_value=crawl,
        ) as crawl_site:
            result = execute_workflow_navigation(
                action=action,
                decision=decision,
                state=_state(),
                origin="https://example.test",
                authorized=True,
                timeout=2.0,
                max_bytes=4096,
            )

        self.assertTrue(result.success)
        self.assertEqual(
            result.reason,
            "completed",
        )
        self.assertEqual(
            result.state.current_url,
            "https://example.test/dashboard",
        )
        self.assertEqual(
            result.state.actions_used,
            1,
        )
        crawl_site.assert_called_once_with(
            start_url="https://example.test/dashboard",
            max_pages=1,
            max_bytes_per_page=4096,
            timeout=2.0,
            user_agent="NightRecon/0.25 workflow-navigation",
            authorization=None,
            cookie=None,
            cookie_jar=None,
        )

    def test_ephemeral_auth_context_is_forwarded_but_not_retained(self):
        action, decision = _authorized_action()
        cookie_jar = CookieJar()
        secret = "Bearer workflow-secret-value"
        crawl = CrawlResult(
            start_url="https://example.test/dashboard",
            origin="https://example.test",
            pages=(
                CrawlPage(
                    url="https://example.test/dashboard",
                    status=200,
                    content_type="text/html",
                    byte_count=100,
                    links=(),
                ),
            ),
            max_pages=1,
            max_bytes_per_page=262_144,
        )

        with patch(
            "nightrecon.web_workflow_execution.crawl_site",
            return_value=crawl,
        ) as crawl_site:
            result = execute_workflow_navigation(
                action=action,
                decision=decision,
                state=_state(),
                origin="https://example.test",
                authorized=True,
                authorization=secret,
                cookie_jar=cookie_jar,
            )

        self.assertTrue(result.success)
        self.assertEqual(
            crawl_site.call_args.kwargs["authorization"],
            secret,
        )
        self.assertIs(
            crawl_site.call_args.kwargs["cookie_jar"],
            cookie_jar,
        )
        self.assertNotIn(
            "workflow-secret-value",
            repr(result),
        )
        self.assertNotIn(
            "CookieJar",
            repr(result),
        )

    def test_explicit_authorization_is_required(self):
        action, decision = _authorized_action()

        with patch(
            "nightrecon.web_workflow_execution.crawl_site"
        ) as crawl_site:
            with self.assertRaises(PermissionError):
                execute_workflow_navigation(
                    action=action,
                    decision=decision,
                    state=_state(),
                    origin="https://example.test",
                    authorized=False,
                )

        crawl_site.assert_not_called()

    def test_form_submission_action_is_structurally_rejected(self):
        policy = WorkflowPolicy(
            origin="https://example.test",
            allow_form_submission=True,
            allowed_methods=("GET", "POST"),
        )
        action = WorkflowAction(
            kind=WorkflowActionKind.SUBMIT_FORM,
            source_url="https://example.test/login",
            target_url="https://example.test/session",
            method="POST",
        )
        decision = authorize_workflow_action(
            action=action,
            policy=policy,
            actions_used=0,
        )
        self.assertTrue(decision.allowed)

        with patch(
            "nightrecon.web_workflow_execution.crawl_site"
        ) as crawl_site:
            with self.assertRaises(PermissionError):
                execute_workflow_navigation(
                    action=action,
                    decision=decision,
                    state=_state(),
                    origin="https://example.test",
                    authorized=True,
                )

        crawl_site.assert_not_called()

    def test_non_get_navigation_is_rejected_before_request(self):
        policy = WorkflowPolicy(
            origin="https://example.test",
            allowed_methods=("GET", "HEAD"),
        )
        action = WorkflowAction(
            kind=WorkflowActionKind.NAVIGATE,
            source_url="https://example.test/",
            target_url="https://example.test/dashboard",
            method="HEAD",
        )
        decision = authorize_workflow_action(
            action=action,
            policy=policy,
            actions_used=0,
        )
        self.assertTrue(decision.allowed)

        with patch(
            "nightrecon.web_workflow_execution.crawl_site"
        ) as crawl_site:
            with self.assertRaises(PermissionError):
                execute_workflow_navigation(
                    action=action,
                    decision=decision,
                    state=_state(),
                    origin="https://example.test",
                    authorized=True,
                )

        crawl_site.assert_not_called()

    def test_cross_origin_action_is_rejected_before_request(self):
        action, decision = _authorized_action()
        altered = WorkflowAction(
            kind=WorkflowActionKind.NAVIGATE,
            source_url=action.source_url,
            target_url="https://outside.test/",
            method="GET",
        )

        with patch(
            "nightrecon.web_workflow_execution.crawl_site"
        ) as crawl_site:
            with self.assertRaises(
                (PermissionError, ValueError)
            ):
                execute_workflow_navigation(
                    action=altered,
                    decision=decision,
                    state=_state(),
                    origin="https://example.test",
                    authorized=True,
                )

        crawl_site.assert_not_called()

    def test_failed_navigation_does_not_advance_state(self):
        action, decision = _authorized_action()
        state = _state()
        crawl = CrawlResult(
            start_url="https://example.test/dashboard",
            origin="https://example.test",
            pages=(
                CrawlPage(
                    url="https://example.test/dashboard",
                    status=None,
                    content_type="",
                    byte_count=0,
                    links=(),
                    error="TimeoutError: timed out",
                ),
            ),
            max_pages=1,
            max_bytes_per_page=262_144,
        )

        with patch(
            "nightrecon.web_workflow_execution.crawl_site",
            return_value=crawl,
        ):
            result = execute_workflow_navigation(
                action=action,
                decision=decision,
                state=state,
                origin="https://example.test",
                authorized=True,
            )

        self.assertFalse(result.success)
        self.assertEqual(
            result.reason,
            "navigation_failed",
        )
        self.assertIs(
            result.state,
            state,
        )
        self.assertEqual(
            result.state.actions_used,
            0,
        )

    def test_invalid_limits_are_rejected_before_request(self):
        action, decision = _authorized_action()

        with patch(
            "nightrecon.web_workflow_execution.crawl_site"
        ) as crawl_site:
            with self.assertRaises(ValueError):
                execute_workflow_navigation(
                    action=action,
                    decision=decision,
                    state=_state(),
                    origin="https://example.test",
                    authorized=True,
                    timeout=0,
                )

            with self.assertRaises(ValueError):
                execute_workflow_navigation(
                    action=action,
                    decision=decision,
                    state=_state(),
                    origin="https://example.test",
                    authorized=True,
                    max_bytes=0,
                )

        crawl_site.assert_not_called()


if __name__ == "__main__":
    unittest.main()
