"""Secret-safe validation operation handoff for exercise review."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.validation_operation_plan import ValidationOperationPlan
from nightrecon_red_engine.validation_operation_state import ValidationOperationProgress


@dataclass(frozen=True)
class ValidationOperationHandoff:
    operation_id: str
    status: str
    planned_steps: int
    completed_steps: int
    attack_ids: tuple[str, ...]
    validation_evidence_ids: tuple[str, ...]
    cleanup_evidence_ids: tuple[str, ...]
    pending_binding_ids: tuple[str, ...]
    stop_reason: str
    authorization_effect: str = "none"

    def to_dict(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "status": self.status,
            "planned_steps": self.planned_steps,
            "completed_steps": self.completed_steps,
            "attack_ids": list(self.attack_ids),
            "validation_evidence_ids": list(self.validation_evidence_ids),
            "cleanup_evidence_ids": list(self.cleanup_evidence_ids),
            "pending_binding_ids": list(self.pending_binding_ids),
            "stop_reason": self.stop_reason,
            "authorization_effect": self.authorization_effect,
        }


def build_validation_operation_handoff(
    plan: ValidationOperationPlan,
    progress: ValidationOperationProgress,
) -> ValidationOperationHandoff:
    """Produce a portable evidence-reference handoff without raw evidence data."""

    if progress.operation_id != plan.operation_id:
        raise ValueError("operation progress does not match plan")
    completed = len(progress.outcomes)
    if completed > len(plan.steps):
        raise ValueError("operation progress exceeds plan step count")

    if progress.stop_requested:
        status = "stopped"
    elif completed == len(plan.steps):
        status = "complete"
    else:
        status = "in-progress"

    pending = tuple(
        item.binding_id for item in plan.steps[completed:]
    )
    return ValidationOperationHandoff(
        operation_id=plan.operation_id,
        status=status,
        planned_steps=len(plan.steps),
        completed_steps=completed,
        attack_ids=plan.attack_ids,
        validation_evidence_ids=tuple(
            item.validation_evidence_id for item in progress.outcomes
        ),
        cleanup_evidence_ids=tuple(
            item.cleanup_evidence_id for item in progress.outcomes
        ),
        pending_binding_ids=pending,
        stop_reason=progress.stop_reason,
    )
