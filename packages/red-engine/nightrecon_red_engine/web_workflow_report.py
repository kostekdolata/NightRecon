"""Structured non-secret reporting for NightRecon web workflows."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from nightrecon_red_engine.session import ScanSession
from nightrecon_red_engine.web_form_intent import WorkflowFormIntent
from nightrecon_red_engine.web_workflow import (
    WorkflowAction,
    WorkflowDecision,
)
from nightrecon_red_engine.web_workflow_execution import (
    WorkflowNavigationResult,
)


@dataclass(frozen=True)
class WorkflowActionRecord:
    kind: str
    source_url: str
    target_url: str
    method: str

    @classmethod
    def from_action(
        cls,
        action: WorkflowAction,
    ) -> "WorkflowActionRecord":
        return cls(
            kind=action.kind.value,
            source_url=action.source_url,
            target_url=action.target_url,
            method=action.method,
        )


@dataclass(frozen=True)
class WorkflowFormFieldRecord:
    name: str
    input_type: str
    field_class: str
    sensitive: bool
    value_retained: bool


@dataclass(frozen=True)
class WorkflowFormRecord:
    source_url: str
    action_url: str
    method: str
    action_same_origin: bool
    submission_enabled: bool
    fields: tuple[WorkflowFormFieldRecord, ...]

    @classmethod
    def from_intent(
        cls,
        intent: WorkflowFormIntent,
    ) -> "WorkflowFormRecord":
        return cls(
            source_url=intent.source_url,
            action_url=intent.action_url,
            method=intent.method,
            action_same_origin=intent.action_same_origin,
            submission_enabled=intent.submission_enabled,
            fields=tuple(
                WorkflowFormFieldRecord(
                    name=field.name,
                    input_type=field.input_type,
                    field_class=field.field_class.value,
                    sensitive=field.sensitive,
                    value_retained=field.value_retained,
                )
                for field in intent.fields
            ),
        )


@dataclass(frozen=True)
class WorkflowExecutionRecord:
    action: WorkflowActionRecord
    allowed: bool
    decision_reason: str
    success: bool
    execution_reason: str
    status: int | None
    byte_count: int
    actions_used_after: int

    @classmethod
    def denied(
        cls,
        *,
        action: WorkflowAction,
        decision: WorkflowDecision,
        actions_used_after: int,
    ) -> "WorkflowExecutionRecord":
        return cls(
            action=WorkflowActionRecord.from_action(action),
            allowed=False,
            decision_reason=decision.reason,
            success=False,
            execution_reason="not_executed",
            status=None,
            byte_count=0,
            actions_used_after=actions_used_after,
        )

    @classmethod
    def completed(
        cls,
        *,
        action: WorkflowAction,
        decision: WorkflowDecision,
        result: WorkflowNavigationResult,
    ) -> "WorkflowExecutionRecord":
        page = result.page

        return cls(
            action=WorkflowActionRecord.from_action(action),
            allowed=decision.allowed,
            decision_reason=decision.reason,
            success=result.success,
            execution_reason=result.reason,
            status=(
                page.status
                if page is not None
                else None
            ),
            byte_count=(
                page.byte_count
                if page is not None
                else 0
            ),
            actions_used_after=result.state.actions_used,
        )


@dataclass(frozen=True)
class WebWorkflowReport:
    session_id: str
    created_at: str
    target: str
    target_type: str
    scope: tuple[str, ...]
    status: str
    origin: str
    max_actions: int
    planned_actions: tuple[WorkflowActionRecord, ...]
    forms: tuple[WorkflowFormRecord, ...]
    executions: tuple[WorkflowExecutionRecord, ...]

    @classmethod
    def create(
        cls,
        *,
        session: ScanSession,
        origin: str,
        max_actions: int,
        planned_actions: tuple[WorkflowAction, ...],
        forms: tuple[WorkflowFormIntent, ...],
        executions: tuple[WorkflowExecutionRecord, ...],
    ) -> "WebWorkflowReport":
        return cls(
            session_id=session.session_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            target=session.target,
            target_type=session.target_type,
            scope=session.scope,
            status="completed",
            origin=origin,
            max_actions=max_actions,
            planned_actions=tuple(
                WorkflowActionRecord.from_action(action)
                for action in planned_actions
            ),
            forms=tuple(
                WorkflowFormRecord.from_intent(intent)
                for intent in forms
            ),
            executions=executions,
        )

    @property
    def successful_executions(self) -> int:
        return sum(
            execution.success
            for execution in self.executions
        )

    def to_dict(self) -> dict:
        data = asdict(self)
        data["summary"] = {
            "planned_actions": len(self.planned_actions),
            "forms_observed": len(self.forms),
            "executions_requested": len(self.executions),
            "successful_executions": self.successful_executions,
        }
        return data
