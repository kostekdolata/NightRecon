"""Tests for NightRecon non-secret web workflow reporting."""

import unittest

from nightrecon.session import ScanSession
from nightrecon.targets import parse_target
from nightrecon.web_form_intent import (
    WorkflowFieldClass,
    WorkflowFormFieldIntent,
    WorkflowFormIntent,
)
from nightrecon.web_workflow import (
    WorkflowAction,
    WorkflowActionKind,
    WorkflowDecision,
    WorkflowState,
)
from nightrecon.web_workflow_execution import (
    WorkflowNavigationResult,
)
from nightrecon.web_workflow_report import (
    WebWorkflowReport,
    WorkflowExecutionRecord,
)


class WebWorkflowReportTests(unittest.TestCase):
    def test_report_contains_metadata_without_secret_values(self):
        session = ScanSession.create(
            target=parse_target("example.test"),
            scope_rules=("example.test",),
        )
        action = WorkflowAction(
            kind=WorkflowActionKind.NAVIGATE,
            source_url="https://example.test/",
            target_url="https://example.test/dashboard",
            method="GET",
        )
        decision = WorkflowDecision(
            allowed=True,
            reason="authorized",
            normalized_source_url="https://example.test/",
            normalized_target_url="https://example.test/dashboard",
            method="GET",
        )
        state = WorkflowState(
            current_url="https://example.test/dashboard",
            visited_urls=(
                "https://example.test/",
                "https://example.test/dashboard",
            ),
            actions_used=1,
            max_actions=3,
        )
        result = WorkflowNavigationResult(
            success=True,
            reason="completed",
            page=None,
            state=state,
        )
        form = WorkflowFormIntent(
            source_url="https://example.test/login",
            action_url="https://example.test/session",
            method="POST",
            action_same_origin=True,
            fields=(
                WorkflowFormFieldIntent(
                    name="csrf_token",
                    input_type="hidden",
                    field_class=WorkflowFieldClass.ANTI_CSRF,
                    sensitive=True,
                    value_retained=False,
                ),
            ),
        )

        report = WebWorkflowReport.create(
            session=session,
            origin="https://example.test",
            max_actions=3,
            planned_actions=(action,),
            forms=(form,),
            executions=(
                WorkflowExecutionRecord.completed(
                    action=action,
                    decision=decision,
                    result=result,
                ),
            ),
        )
        data = report.to_dict()

        self.assertEqual(
            data["summary"]["planned_actions"],
            1,
        )
        self.assertEqual(
            data["summary"]["forms_observed"],
            1,
        )
        self.assertEqual(
            data["summary"]["successful_executions"],
            1,
        )
        self.assertFalse(
            data["forms"][0]["fields"][0]["value_retained"]
        )
        serialized = repr(data)
        self.assertNotIn(
            "secret-value",
            serialized,
        )
        self.assertNotIn(
            "authorization",
            serialized.lower(),
        )
        self.assertNotIn(
            "cookiejar",
            serialized.lower(),
        )

    def test_denied_execution_is_reported_without_network_result(self):
        session = ScanSession.create(
            target=parse_target("example.test"),
            scope_rules=("example.test",),
        )
        action = WorkflowAction(
            kind=WorkflowActionKind.NAVIGATE,
            source_url="https://example.test/",
            target_url="https://example.test/admin",
            method="GET",
        )
        decision = WorkflowDecision(
            allowed=False,
            reason="action_budget_exhausted",
            normalized_source_url="https://example.test/",
            normalized_target_url="https://example.test/admin",
            method="GET",
        )

        record = WorkflowExecutionRecord.denied(
            action=action,
            decision=decision,
            actions_used_after=3,
        )
        report = WebWorkflowReport.create(
            session=session,
            origin="https://example.test",
            max_actions=3,
            planned_actions=(),
            forms=(),
            executions=(record,),
        )

        self.assertFalse(
            report.executions[0].success
        )
        self.assertEqual(
            report.executions[0].execution_reason,
            "not_executed",
        )
        self.assertEqual(
            report.executions[0].actions_used_after,
            3,
        )


if __name__ == "__main__":
    unittest.main()
