"""Explicit stop and evidence state for validation operation plans."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from nightrecon_red_engine.validation_operation_plan import ValidationOperationPlan
from nightrecon_red_engine.validation_worker import ValidationWorkerState


class ValidationOperationStepState(str, Enum):
    CONFIRMED = "confirmed"
    NOT_CONFIRMED = "not-confirmed"
    DENIED = "denied"
    REVOKED = "revoked"
    TIMED_OUT = "timed-out"
    CONTRACT_REJECTED = "contract-rejected"
    ERROR = "error"


@dataclass(frozen=True)
class ValidationOperationOutcome:
    order: int
    binding_id: str
    state: ValidationOperationStepState
    validation_evidence_id: str
    cleanup_evidence_id: str
    cleanup_state: str

    def to_dict(self) -> dict[str, object]:
        return {
            "order": self.order,
            "binding_id": self.binding_id,
            "state": self.state.value,
            "validation_evidence_id": self.validation_evidence_id,
            "cleanup_evidence_id": self.cleanup_evidence_id,
            "cleanup_state": self.cleanup_state,
        }


@dataclass(frozen=True)
class ValidationOperationProgress:
    operation_id: str
    outcomes: tuple[ValidationOperationOutcome, ...] = ()
    stop_requested: bool = False
    stop_reason: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "outcomes": [item.to_dict() for item in self.outcomes],
            "stop_requested": self.stop_requested,
            "stop_reason": self.stop_reason,
        }


def new_validation_operation_progress(
    plan: ValidationOperationPlan,
) -> ValidationOperationProgress:
    if not isinstance(plan, ValidationOperationPlan):
        raise ValueError("plan must be ValidationOperationPlan")
    return ValidationOperationProgress(operation_id=plan.operation_id)


def request_validation_operation_stop(
    plan: ValidationOperationPlan,
    progress: ValidationOperationProgress,
    *,
    reason: str,
) -> ValidationOperationProgress:
    if progress.operation_id != plan.operation_id:
        raise ValueError("operation progress does not match plan")
    if not isinstance(reason, str) or not reason or reason != reason.strip():
        raise ValueError("stop reason must be nonblank and trimmed")
    return ValidationOperationProgress(
        operation_id=progress.operation_id,
        outcomes=progress.outcomes,
        stop_requested=True,
        stop_reason=reason,
    )


def record_validation_operation_outcome(
    plan: ValidationOperationPlan,
    progress: ValidationOperationProgress,
    *,
    binding_id: str,
    worker_state: ValidationWorkerState,
    validation_evidence_id: str,
    cleanup_evidence_id: str,
    cleanup_state: str,
) -> ValidationOperationProgress:
    """Record evidence from one separately authorized worker lifecycle."""

    if progress.operation_id != plan.operation_id:
        raise ValueError("operation progress does not match plan")
    if progress.stop_requested:
        raise ValueError("validation operation has been stopped")
    if len(progress.outcomes) >= len(plan.steps):
        raise ValueError("validation operation already has all step outcomes")

    step = plan.steps[len(progress.outcomes)]
    if binding_id != step.binding_id:
        raise ValueError("operation outcome must follow explicit plan order")
    if not isinstance(worker_state, ValidationWorkerState):
        raise ValueError("worker_state must be ValidationWorkerState")
    for value, field in (
        (validation_evidence_id, "validation_evidence_id"),
        (cleanup_evidence_id, "cleanup_evidence_id"),
        (cleanup_state, "cleanup_state"),
    ):
        if not isinstance(value, str) or not value or value != value.strip():
            raise ValueError(f"{field} must be nonblank and trimmed")

    try:
        state = ValidationOperationStepState(worker_state.value)
    except ValueError as exc:
        raise ValueError("worker state is not supported by operation progress") from exc

    outcome = ValidationOperationOutcome(
        order=step.order,
        binding_id=binding_id,
        state=state,
        validation_evidence_id=validation_evidence_id,
        cleanup_evidence_id=cleanup_evidence_id,
        cleanup_state=cleanup_state,
    )
    return ValidationOperationProgress(
        operation_id=progress.operation_id,
        outcomes=progress.outcomes + (outcome,),
    )
