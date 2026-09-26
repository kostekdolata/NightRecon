"""Tests for NightRecon safe web workflow policy models."""

import unittest

from nightrecon.web_crawl import (
    CrawlPage,
    WebFormInput,
    WebFormObservation,
)
from nightrecon.web_workflow import (
    WorkflowAction,
    WorkflowActionKind,
    WorkflowPolicy,
    WorkflowState,
    authorize_workflow_action,
    build_observed_navigation_plan,
)


class WebWorkflowTests(unittest.TestCase):
    def test_same_origin_get_navigation_is_authorized(self):
        policy = WorkflowPolicy(
            origin="https://example.test",
            max_actions=5,
        )
        action = WorkflowAction(
            kind=WorkflowActionKind.NAVIGATE,
            source_url="https://example.test/start",
            target_url="https://example.test/next#top",
            method="get",
        )

        decision = authorize_workflow_action(
            action=action,
            policy=policy,
            actions_used=0,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "authorized",
        )
        self.assertEqual(
            decision.normalized_target_url,
            "https://example.test/next",
        )
        self.assertEqual(
            decision.method,
            "GET",
        )

    def test_cross_origin_transition_is_rejected(self):
        policy = WorkflowPolicy(
            origin="https://example.test",
        )
        action = WorkflowAction(
            kind=WorkflowActionKind.NAVIGATE,
            source_url="https://example.test/start",
            target_url="https://other.test/next",
            method="GET",
        )

        decision = authorize_workflow_action(
            action=action,
            policy=policy,
            actions_used=0,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "outside_authorized_origin",
        )

    def test_action_budget_is_enforced_before_execution(self):
        policy = WorkflowPolicy(
            origin="https://example.test",
            max_actions=2,
        )
        action = WorkflowAction(
            kind=WorkflowActionKind.NAVIGATE,
            source_url="https://example.test/start",
            target_url="https://example.test/next",
            method="GET",
        )

        decision = authorize_workflow_action(
            action=action,
            policy=policy,
            actions_used=2,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "action_budget_exhausted",
        )

    def test_form_submission_is_disabled_by_default(self):
        policy = WorkflowPolicy(
            origin="https://example.test",
        )
        action = WorkflowAction(
            kind=WorkflowActionKind.SUBMIT_FORM,
            source_url="https://example.test/login",
            target_url="https://example.test/session",
            method="GET",
        )

        decision = authorize_workflow_action(
            action=action,
            policy=policy,
            actions_used=0,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "form_submission_not_enabled",
        )

    def test_disallowed_http_method_is_rejected(self):
        policy = WorkflowPolicy(
            origin="https://example.test",
            allow_form_submission=True,
            allowed_methods=("GET",),
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

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "method_not_allowed",
        )

    def test_observed_plan_never_converts_forms_to_submissions(self):
        page = CrawlPage(
            url="https://example.test/login",
            status=200,
            content_type="text/html",
            byte_count=100,
            links=(
                "https://example.test/help",
                "https://example.test/profile",
            ),
            forms=(
                WebFormObservation(
                    action="https://example.test/session",
                    method="POST",
                    inputs=(
                        WebFormInput(
                            name="username",
                            input_type="text",
                        ),
                        WebFormInput(
                            name="password",
                            input_type="password",
                        ),
                    ),
                ),
            ),
        )

        actions = build_observed_navigation_plan(
            pages=(page,),
            origin="https://example.test",
            max_actions=10,
        )

        self.assertEqual(
            len(actions),
            2,
        )
        self.assertTrue(
            all(
                action.kind
                == WorkflowActionKind.NAVIGATE
                for action in actions
            )
        )
        self.assertTrue(
            all(
                action.method == "GET"
                for action in actions
            )
        )
        self.assertNotIn(
            "https://example.test/session",
            tuple(
                action.target_url
                for action in actions
            ),
        )

    def test_observed_plan_is_same_origin_deduplicated_and_bounded(self):
        pages = (
            CrawlPage(
                url="https://example.test/",
                status=200,
                content_type="text/html",
                byte_count=100,
                links=(
                    "https://example.test/a",
                    "https://example.test/a#top",
                    "https://other.test/out",
                    "https://example.test/b",
                ),
            ),
            CrawlPage(
                url="https://example.test/a",
                status=200,
                content_type="text/html",
                byte_count=100,
                links=(
                    "https://example.test/c",
                ),
            ),
        )

        actions = build_observed_navigation_plan(
            pages=pages,
            origin="https://example.test",
            max_actions=2,
        )

        self.assertEqual(
            tuple(
                action.target_url
                for action in actions
            ),
            (
                "https://example.test/a",
                "https://example.test/b",
            ),
        )

    def test_workflow_state_reports_remaining_budget(self):
        state = WorkflowState(
            current_url="https://example.test/",
            visited_urls=(
                "https://example.test/",
            ),
            actions_used=3,
            max_actions=5,
        )

        self.assertEqual(
            state.actions_remaining,
            2,
        )

    def test_policy_rejects_invalid_limits_and_empty_methods(self):
        with self.assertRaises(ValueError):
            WorkflowPolicy(
                origin="https://example.test",
                max_actions=0,
            )

        with self.assertRaises(ValueError):
            WorkflowPolicy(
                origin="https://example.test",
                allowed_methods=(),
            )

        with self.assertRaises(ValueError):
            build_observed_navigation_plan(
                pages=(),
                origin="https://example.test",
                max_actions=0,
            )

    def test_negative_action_count_is_rejected(self):
        policy = WorkflowPolicy(
            origin="https://example.test",
        )
        action = WorkflowAction(
            kind=WorkflowActionKind.NAVIGATE,
            source_url="https://example.test/",
            target_url="https://example.test/next",
            method="GET",
        )

        with self.assertRaises(ValueError):
            authorize_workflow_action(
                action=action,
                policy=policy,
                actions_used=-1,
            )


if __name__ == "__main__":
    unittest.main()
