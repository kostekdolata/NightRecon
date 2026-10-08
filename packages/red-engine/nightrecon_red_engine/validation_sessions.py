"""Reviewed controlled-validation module registry and session lifecycle."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ValidationSessionState(str, Enum):
    CREATED = "created"
    APPROVED = "approved"
    RUNNING = "running"
    CONFIRMED = "confirmed"
    NOT_CONFIRMED = "not-confirmed"
    FAILED = "failed"
    CLEANUP_REQUIRED = "cleanup-required"
    CLEANED = "cleaned"


@dataclass(frozen=True)
class ReviewedValidationModule:
    module_id: str
    title: str
    proof_mode: str
    required_service: str
    required_evidence: tuple[str, ...]
    impact: str = "low"
    cleanup_required: bool = False
    provides_shell: bool = False

    def __post_init__(self) -> None:
        if not self.module_id.strip() or not self.title.strip():
            raise ValueError("module_id and title must not be empty")
        if self.proof_mode not in {
            "tcp-property",
            "tls-property",
            "http-policy",
            "authenticated-readonly",
        }:
            raise ValueError("unsupported reviewed proof mode")
        if self.impact not in {"low", "standard", "high"}:
            raise ValueError("impact must be low, standard, or high")
        if self.provides_shell:
            raise ValueError(
                "reusable interactive shell modules are not permitted in the reviewed registry"
            )


BUILTIN_REVIEWED_MODULES = (
    ReviewedValidationModule(
        module_id="service.tcp-property-proof",
        title="TCP service reachability proof",
        proof_mode="tcp-property",
        required_service="tcp",
        required_evidence=("address", "port"),
    ),
    ReviewedValidationModule(
        module_id="service.tls-property-proof",
        title="TLS certificate property proof",
        proof_mode="tls-property",
        required_service="tls",
        required_evidence=("address", "port", "certificate_sha256"),
    ),
    ReviewedValidationModule(
        module_id="web.http-policy-proof",
        title="HTTP response-policy proof",
        proof_mode="http-policy",
        required_service="http",
        required_evidence=("origin",),
    ),
)


@dataclass(frozen=True)
class ValidationSession:
    session_id: str
    module_id: str
    target: str
    state: ValidationSessionState = ValidationSessionState.CREATED
    evidence_ids: tuple[str, ...] = ()
    cleanup_notes: tuple[str, ...] = ()

    def transition(
        self,
        state: ValidationSessionState,
        *,
        evidence_ids: tuple[str, ...] | None = None,
        cleanup_notes: tuple[str, ...] | None = None,
    ) -> "ValidationSession":
        allowed = {
            ValidationSessionState.CREATED: {ValidationSessionState.APPROVED, ValidationSessionState.FAILED},
            ValidationSessionState.APPROVED: {ValidationSessionState.RUNNING, ValidationSessionState.FAILED},
            ValidationSessionState.RUNNING: {
                ValidationSessionState.CONFIRMED,
                ValidationSessionState.NOT_CONFIRMED,
                ValidationSessionState.FAILED,
                ValidationSessionState.CLEANUP_REQUIRED,
            },
            ValidationSessionState.CLEANUP_REQUIRED: {ValidationSessionState.CLEANED, ValidationSessionState.FAILED},
        }
        if state not in allowed.get(self.state, set()):
            raise ValueError(
                f"invalid validation session transition: {self.state.value} -> {state.value}"
            )
        return ValidationSession(
            session_id=self.session_id,
            module_id=self.module_id,
            target=self.target,
            state=state,
            evidence_ids=self.evidence_ids if evidence_ids is None else evidence_ids,
            cleanup_notes=self.cleanup_notes if cleanup_notes is None else cleanup_notes,
        )
