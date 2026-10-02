"""Deterministic operator-selected validation operation planning."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from nightrecon_red_engine.validation_adapter_contracts import ValidationAdapterBinding
from nightrecon_red_engine.validation_attack_review import (
    BUILTIN_VALIDATION_ATTACK_REVIEW_REGISTRY,
)


MAX_VALIDATION_OPERATION_STEPS = 32
OPERATION_INTERPRETATION = (
    "The operation is an explicit review/orchestration plan only. It grants no "
    "authorization, selects no targets or techniques automatically, and does "
    "not execute a validation adapter."
)


@dataclass(frozen=True)
class ValidationOperationStep:
    order: int
    binding_id: str
    candidate_id: str
    technique_id: str
    target_node_id: str
    target_kind: str
    requires_approval: bool
    cleanup_mode: str
    attack_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "order": self.order,
            "binding_id": self.binding_id,
            "candidate_id": self.candidate_id,
            "technique_id": self.technique_id,
            "target_node_id": self.target_node_id,
            "target_kind": self.target_kind,
            "requires_approval": self.requires_approval,
            "cleanup_mode": self.cleanup_mode,
            "attack_ids": list(self.attack_ids),
        }


@dataclass(frozen=True)
class ValidationOperationPlan:
    operation_id: str
    steps: tuple[ValidationOperationStep, ...]
    attack_ids: tuple[str, ...]
    authorization_effect: str = "none"
    execution_mode: str = "operator-selected-sequential"
    interpretation: str = OPERATION_INTERPRETATION

    def to_dict(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "steps": [item.to_dict() for item in self.steps],
            "attack_ids": list(self.attack_ids),
            "authorization_effect": self.authorization_effect,
            "execution_mode": self.execution_mode,
            "interpretation": self.interpretation,
        }


def build_validation_operation_plan(
    bindings: tuple[ValidationAdapterBinding, ...],
) -> ValidationOperationPlan:
    """Build a bounded plan from bindings the operator already selected."""

    if not isinstance(bindings, tuple):
        raise ValueError("bindings must be a tuple")
    if not bindings:
        raise ValueError("validation operation requires at least one binding")
    if len(bindings) > MAX_VALIDATION_OPERATION_STEPS:
        raise ValueError("validation operation step ceiling exceeded")

    ids = tuple(item.binding_id for item in bindings)
    if len(ids) != len(set(ids)):
        raise ValueError("validation operation bindings must be unique")

    steps: list[ValidationOperationStep] = []
    all_attack_ids: set[str] = set()
    for order, binding in enumerate(bindings, start=1):
        if not isinstance(binding, ValidationAdapterBinding):
            raise ValueError("operation bindings must be ValidationAdapterBinding")
        if binding.execution_mode != "contract-only":
            raise ValueError("validation binding must remain contract-only")
        if binding.side_effect_mode != "none":
            raise ValueError(
                "side-effecting validation requires a separately reviewed operation model"
            )
        if binding.adapter_kind != "read-only-proof":
            raise ValueError("validation operation accepts read-only-proof bindings only")
        review = BUILTIN_VALIDATION_ATTACK_REVIEW_REGISTRY.get(binding.technique_id)
        attack_ids = review.attack_ids
        all_attack_ids.update(attack_ids)
        steps.append(ValidationOperationStep(
            order=order,
            binding_id=binding.binding_id,
            candidate_id=binding.candidate_id,
            technique_id=binding.technique_id,
            target_node_id=binding.target_node_id,
            target_kind=binding.target_kind,
            requires_approval=binding.requires_approval,
            cleanup_mode=binding.cleanup_mode,
            attack_ids=attack_ids,
        ))

    canonical = json.dumps(
        [item.to_dict() for item in steps],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    operation_id = "validation-operation-" + sha256(canonical).hexdigest()

    return ValidationOperationPlan(
        operation_id=operation_id,
        steps=tuple(steps),
        attack_ids=tuple(sorted(all_attack_ids)),
    )
