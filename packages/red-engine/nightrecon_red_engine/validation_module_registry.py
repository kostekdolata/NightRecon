"""Reviewed controlled-validation module registry for Red Night.

Modules describe bounded proof properties and required evidence. They do not
embed exploit payloads or arbitrary command execution.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationPrecondition:
    name: str
    required: bool = True


@dataclass(frozen=True)
class ReviewedValidationModule:
    module_id: str
    title: str
    family: str
    proof_mode: str
    required_service: str
    preconditions: tuple[ValidationPrecondition, ...]
    evidence_fields: tuple[str, ...]
    cleanup_required: bool = False
    impact: str = "low"

    def __post_init__(self) -> None:
        if not self.module_id.strip():
            raise ValueError("module_id must not be empty")
        if self.family not in {
            "network",
            "tls",
            "web",
            "smb",
            "ssh",
            "database",
            "identity",
            "range-simulation",
        }:
            raise ValueError("unsupported validation family")
        if self.proof_mode not in {
            "property-proof",
            "authenticated-readonly",
            "policy-proof",
            "range-simulation",
        }:
            raise ValueError("unsupported proof mode")
        if self.impact not in {"low", "standard", "high"}:
            raise ValueError("impact must be low, standard, or high")


@dataclass(frozen=True)
class ValidationEligibility:
    module_id: str
    eligible: bool
    satisfied: tuple[str, ...]
    missing: tuple[str, ...]


BUILTIN_VALIDATION_MODULES = (
    ReviewedValidationModule(
        module_id="network.tcp-reachability",
        title="TCP reachability property proof",
        family="network",
        proof_mode="property-proof",
        required_service="tcp",
        preconditions=(ValidationPrecondition("authorized-target"),),
        evidence_fields=("address", "port", "scan-state"),
    ),
    ReviewedValidationModule(
        module_id="tls.certificate-policy",
        title="TLS certificate and protocol property proof",
        family="tls",
        proof_mode="property-proof",
        required_service="tls",
        preconditions=(
            ValidationPrecondition("authorized-target"),
            ValidationPrecondition("tls-reachable"),
        ),
        evidence_fields=(
            "certificate-sha256",
            "protocol-version",
            "hostname-validation",
        ),
    ),
    ReviewedValidationModule(
        module_id="web.security-policy",
        title="HTTP security policy proof",
        family="web",
        proof_mode="policy-proof",
        required_service="http",
        preconditions=(
            ValidationPrecondition("authorized-origin"),
            ValidationPrecondition("http-reachable"),
        ),
        evidence_fields=("status", "headers", "cookie-policy"),
    ),
    ReviewedValidationModule(
        module_id="smb.signing-policy",
        title="SMB signing policy proof",
        family="smb",
        proof_mode="authenticated-readonly",
        required_service="smb",
        preconditions=(
            ValidationPrecondition("authorized-target"),
            ValidationPrecondition("credential-reference"),
        ),
        evidence_fields=("server-identity", "signing-policy"),
    ),
    ReviewedValidationModule(
        module_id="ssh.server-policy",
        title="SSH server identity and algorithm policy proof",
        family="ssh",
        proof_mode="authenticated-readonly",
        required_service="ssh",
        preconditions=(
            ValidationPrecondition("authorized-target"),
            ValidationPrecondition("known-host-key"),
            ValidationPrecondition("credential-reference"),
        ),
        evidence_fields=("host-key", "server-version", "system-identity"),
    ),
    ReviewedValidationModule(
        module_id="database.metadata-policy",
        title="Database identity/schema policy proof",
        family="database",
        proof_mode="authenticated-readonly",
        required_service="database",
        preconditions=(
            ValidationPrecondition("authorized-target"),
            ValidationPrecondition("credential-reference"),
        ),
        evidence_fields=("server-version", "schema-inventory"),
    ),
    ReviewedValidationModule(
        module_id="identity.privilege-path-proof",
        title="Identity privilege-path evidence proof",
        family="identity",
        proof_mode="property-proof",
        required_service="identity",
        preconditions=(
            ValidationPrecondition("identity-evidence"),
            ValidationPrecondition("graph-built"),
        ),
        evidence_fields=("source-principal", "target-asset", "path-edges"),
    ),
    ReviewedValidationModule(
        module_id="range.post-exploitation-simulation",
        title="Cyber-range post-exploitation simulation",
        family="range-simulation",
        proof_mode="range-simulation",
        required_service="cyber-range",
        preconditions=(
            ValidationPrecondition("sandbox"),
            ValidationPrecondition("snapshot"),
            ValidationPrecondition("explicit-scenario"),
        ),
        evidence_fields=("scenario", "events", "rollback"),
        cleanup_required=True,
        impact="high",
    ),
)


_MODULES = {
    module.module_id: module
    for module in BUILTIN_VALIDATION_MODULES
}


def get_validation_module(module_id: str) -> ReviewedValidationModule:
    try:
        return _MODULES[module_id]
    except KeyError as exc:
        raise KeyError(f"unknown reviewed validation module: {module_id}") from exc


def evaluate_validation_eligibility(
    module: ReviewedValidationModule,
    evidence_flags: dict[str, bool],
) -> ValidationEligibility:
    satisfied = []
    missing = []
    for precondition in module.preconditions:
        present = bool(evidence_flags.get(precondition.name, False))
        if present:
            satisfied.append(precondition.name)
        elif precondition.required:
            missing.append(precondition.name)

    return ValidationEligibility(
        module_id=module.module_id,
        eligible=not missing,
        satisfied=tuple(sorted(satisfied)),
        missing=tuple(sorted(missing)),
    )
