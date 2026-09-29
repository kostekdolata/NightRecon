"""Durable validation evidence, cleanup, and deterministic retest lifecycle.

Batch 5 persists the bounded Batch 4 worker result as portable engagement
evidence, records an explicit cleanup outcome, and allows remediation state to
advance only from those persisted records.

Current reviewed v0.43 techniques are read-only and declare
side_effect_mode=none, so cleanup is deterministic and records
cleanup_state=not-required. A future side-effecting technique must introduce a
reviewed cleanup implementation before this lifecycle will accept it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Mapping, Any

from nightrecon_red_engine.controlled_validation import ValidationObservation
from nightrecon_red_engine.remediation_retest import RemediationStore, RetestOutcome
from nightrecon_red_engine.validation_adapter_contracts import (
    BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY,
    ValidationAdapterBinding,
    assert_contract_matches_technique,
    check_validation_observation_contract,
    validation_binding_id,
)
from nightrecon_red_engine.validation_techniques import (
    BUILTIN_VALIDATION_TECHNIQUE_REGISTRY,
)
from nightrecon_red_engine.validation_worker import (
    ValidationWorkerResult,
    ValidationWorkerState,
)
from nightrecon_shared_core.contracts import EngagementEnvelope, EvidenceRecord
from nightrecon_shared_core.workspace import LocalWorkspace


VALIDATION_EVIDENCE_TYPE = "validation.worker-result"
CLEANUP_EVIDENCE_TYPE = "validation.cleanup"
CLEANUP_NOT_REQUIRED = "not-required"

_NON_SUCCESS_STATES = frozenset({
    ValidationWorkerState.DENIED,
    ValidationWorkerState.REVOKED,
    ValidationWorkerState.TIMED_OUT,
    ValidationWorkerState.CONTRACT_REJECTED,
    ValidationWorkerState.ERROR,
})
_VALIDATION_DATA_FIELDS = frozenset({
    "binding_id",
    "eligibility_id",
    "candidate_id",
    "path_id",
    "technique_id",
    "contract_id",
    "target_node_id",
    "target_kind",
    "target",
    "state",
    "reason_code",
    "summary",
    "evidence",
    "actions_used",
    "remaining_actions",
    "adapter_kind",
    "execution_mode",
    "side_effect_mode",
    "cleanup_mode",
})
_CLEANUP_DATA_FIELDS = frozenset({
    "validation_evidence_id",
    "binding_id",
    "technique_id",
    "cleanup_mode",
    "side_effect_mode",
    "cleanup_state",
    "cleanup_actions",
})
_MAX_LIFECYCLE_RECORD_BYTES = 96 * 1024


@dataclass(frozen=True)
class ValidationEvidenceLifecycle:
    validation_record: EvidenceRecord
    cleanup_record: EvidenceRecord
    added_records: int
    identical_records: int

    @property
    def validation_evidence_id(self) -> str:
        return self.validation_record.evidence_id

    @property
    def cleanup_evidence_id(self) -> str:
        return self.cleanup_record.evidence_id

    @property
    def cleanup_state(self) -> str:
        return str(self.cleanup_record.data["cleanup_state"])


def _timestamp(value: datetime | None) -> datetime:
    current = datetime.now(timezone.utc) if value is None else value
    if current.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    return current


def _reviewed_binding(binding: ValidationAdapterBinding):
    technique = BUILTIN_VALIDATION_TECHNIQUE_REGISTRY.get(
        binding.technique_id
    )
    contract = BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY.for_technique(
        binding.technique_id
    )
    assert_contract_matches_technique(contract, technique)

    if binding.binding_id != validation_binding_id(
        binding.eligibility_id,
        binding.contract_id,
        binding.target_node_id,
    ):
        raise ValueError("validation binding identifier is stale or invalid")
    if binding.contract_id != contract.contract_id:
        raise ValueError("validation binding contract is stale")
    if binding.expected_evidence_keys != technique.evidence_keys:
        raise ValueError("validation binding evidence contract is stale")
    if binding.impact != technique.impact:
        raise ValueError("validation binding impact is stale")
    if binding.requires_approval != technique.requires_approval:
        raise ValueError("validation binding approval metadata is stale")
    if binding.adapter_kind != technique.adapter_kind:
        raise ValueError("validation binding adapter kind is stale")
    if binding.cleanup_mode != technique.cleanup_mode:
        raise ValueError("validation binding cleanup mode is stale")
    if binding.execution_mode != "contract-only":
        raise ValueError("validation binding must remain contract-only")
    if binding.side_effect_mode != "none":
        raise ValueError(
            "side-effecting validation requires a reviewed cleanup implementation"
        )
    return technique, contract


def _assert_result_matches_binding(
    binding: ValidationAdapterBinding,
    result: ValidationWorkerResult,
) -> None:
    _technique, contract = _reviewed_binding(binding)
    for value, field in (
        (result.engagement_id, "worker engagement_id"),
        (result.target, "worker target"),
        (result.reason_code, "worker reason_code"),
        (result.summary, "worker summary"),
    ):
        if not isinstance(value, str) or not value or value != value.strip():
            raise ValueError(f"{field} must be nonblank and trimmed")
    for value, field in (
        (result.actions_used, "actions_used"),
        (result.remaining_actions, "remaining_actions"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{field} must be a nonnegative integer")
    if result.binding_id != binding.binding_id:
        raise ValueError("worker result binding does not match selected binding")
    if result.technique_id != binding.technique_id:
        raise ValueError("worker result technique does not match selected binding")
    if result.state in {
        ValidationWorkerState.CONFIRMED,
        ValidationWorkerState.NOT_CONFIRMED,
    }:
        observation = ValidationObservation(
            confirmed=result.state is ValidationWorkerState.CONFIRMED,
            summary=result.summary,
            evidence=dict(result.evidence),
            limitations=result.limitations,
        )
        postconditions = check_validation_observation_contract(
            contract,
            observation,
        )
        if not postconditions.valid:
            raise ValueError(
                "worker result does not satisfy the reviewed evidence contract"
            )
    elif result.state in _NON_SUCCESS_STATES:
        if result.evidence:
            raise ValueError(
                "non-success worker results must not retain validation evidence"
            )
    else:
        raise ValueError("worker result state is not supported")


def _canonical_record_id(prefix: str, payload: Mapping[str, Any]) -> str:
    material = json.dumps(
        dict(payload),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return prefix + sha256(material).hexdigest()


def build_validation_result_evidence(
    binding: ValidationAdapterBinding,
    result: ValidationWorkerResult,
    *,
    observed_at: datetime | None = None,
) -> EvidenceRecord:
    """Convert one bounded worker result into deterministic portable evidence."""

    _assert_result_matches_binding(binding, result)
    current = _timestamp(observed_at)
    data = {
        "binding_id": binding.binding_id,
        "eligibility_id": binding.eligibility_id,
        "candidate_id": binding.candidate_id,
        "path_id": binding.path_id,
        "technique_id": binding.technique_id,
        "contract_id": binding.contract_id,
        "target_node_id": binding.target_node_id,
        "target_kind": binding.target_kind,
        "target": result.target,
        "state": result.state.value,
        "reason_code": result.reason_code,
        "summary": result.summary,
        "evidence": dict(result.evidence),
        "actions_used": result.actions_used,
        "remaining_actions": result.remaining_actions,
        "adapter_kind": binding.adapter_kind,
        "execution_mode": "isolated-worker",
        "side_effect_mode": binding.side_effect_mode,
        "cleanup_mode": binding.cleanup_mode,
    }
    limitations = result.limitations + (
        "Worker process identity is intentionally not persisted.",
        "Validation evidence is descriptive proof, not an exploitability verdict.",
    )
    identity = {
        "engagement_id": result.engagement_id,
        "observed_at": current.isoformat(),
        **data,
        "limitations": list(limitations),
    }
    record = EvidenceRecord(
        engagement_id=result.engagement_id,
        evidence_id=_canonical_record_id("validation-result-", identity),
        source_night="red",
        evidence_type=VALIDATION_EVIDENCE_TYPE,
        observed_at=current.isoformat(),
        provenance=f"validation-worker://{binding.binding_id}",
        data=data,
        limitations=limitations,
    )
    if len(record.to_json().encode("utf-8")) > _MAX_LIFECYCLE_RECORD_BYTES:
        raise ValueError("validation lifecycle evidence exceeds record byte ceiling")
    return record


def build_cleanup_evidence(
    binding: ValidationAdapterBinding,
    validation_record: EvidenceRecord,
    *,
    observed_at: datetime | None = None,
) -> EvidenceRecord:
    """Record the reviewed cleanup disposition for one persisted validation."""

    _reviewed_binding(binding)
    if validation_record.evidence_type != VALIDATION_EVIDENCE_TYPE:
        raise ValueError("cleanup requires a validation worker-result record")
    if validation_record.data.get("binding_id") != binding.binding_id:
        raise ValueError("cleanup validation record binding does not match")
    if binding.side_effect_mode != "none" or binding.cleanup_mode != "none":
        raise ValueError(
            "side-effecting validation requires a reviewed cleanup implementation"
        )

    current = _timestamp(observed_at)
    data = {
        "validation_evidence_id": validation_record.evidence_id,
        "binding_id": binding.binding_id,
        "technique_id": binding.technique_id,
        "cleanup_mode": binding.cleanup_mode,
        "side_effect_mode": binding.side_effect_mode,
        "cleanup_state": CLEANUP_NOT_REQUIRED,
        "cleanup_actions": 0,
    }
    limitations = (
        "No cleanup action was required because the reviewed technique "
        "declares no side effects.",
    )
    identity = {
        "engagement_id": validation_record.engagement_id,
        "observed_at": current.isoformat(),
        **data,
        "limitations": list(limitations),
    }
    record = EvidenceRecord(
        engagement_id=validation_record.engagement_id,
        evidence_id=_canonical_record_id("validation-cleanup-", identity),
        source_night="red",
        evidence_type=CLEANUP_EVIDENCE_TYPE,
        observed_at=current.isoformat(),
        provenance=f"validation-cleanup://{binding.binding_id}",
        data=data,
        limitations=limitations,
    )
    if len(record.to_json().encode("utf-8")) > _MAX_LIFECYCLE_RECORD_BYTES:
        raise ValueError("validation cleanup evidence exceeds record byte ceiling")
    return record


def persist_validation_evidence_lifecycle(
    workspace: LocalWorkspace,
    binding: ValidationAdapterBinding,
    result: ValidationWorkerResult,
    *,
    observed_at: datetime | None = None,
) -> ValidationEvidenceLifecycle:
    """Persist result + cleanup records atomically within the engagement store."""

    current = _timestamp(observed_at)
    if workspace.summary(result.engagement_id).engagement_id != result.engagement_id:
        raise ValueError("worker result engagement is not present in workspace")

    validation_record = build_validation_result_evidence(
        binding,
        result,
        observed_at=current,
    )
    cleanup_record = build_cleanup_evidence(
        binding,
        validation_record,
        observed_at=current,
    )
    metadata = workspace.envelope(result.engagement_id).metadata
    report = workspace.merge_envelope(EngagementEnvelope(
        engagement_id=result.engagement_id,
        records=(validation_record, cleanup_record),
        metadata=metadata,
    ))
    if not report.applied:
        raise ValueError("validation evidence lifecycle conflicts with workspace")
    return ValidationEvidenceLifecycle(
        validation_record=validation_record,
        cleanup_record=cleanup_record,
        added_records=report.added_records,
        identical_records=report.identical_records,
    )


def _required_data_text(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"persisted validation field is invalid: {key}")
    return value


def _validate_validation_record(record: EvidenceRecord) -> ValidationWorkerState:
    if record.source_night != "red":
        raise ValueError("validation lifecycle evidence must come from Red Night")
    if record.evidence_type != VALIDATION_EVIDENCE_TYPE:
        raise ValueError("retest validation evidence type is invalid")
    if set(record.data) != _VALIDATION_DATA_FIELDS:
        raise ValueError("persisted validation evidence schema is invalid")
    if not record.provenance.startswith("validation-worker://"):
        raise ValueError("persisted validation provenance is invalid")

    data = record.data
    binding_id = _required_data_text(data, "binding_id")
    eligibility_id = _required_data_text(data, "eligibility_id")
    technique_id = _required_data_text(data, "technique_id")
    contract_id = _required_data_text(data, "contract_id")
    target_node_id = _required_data_text(data, "target_node_id")
    target_kind = _required_data_text(data, "target_kind")
    _required_data_text(data, "candidate_id")
    _required_data_text(data, "path_id")
    _required_data_text(data, "target")
    _required_data_text(data, "reason_code")
    summary = _required_data_text(data, "summary")

    technique = BUILTIN_VALIDATION_TECHNIQUE_REGISTRY.get(technique_id)
    contract = BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY.for_technique(
        technique_id
    )
    assert_contract_matches_technique(contract, technique)
    if contract_id != contract.contract_id:
        raise ValueError("persisted validation contract is not reviewed")
    if target_kind not in technique.target_kinds:
        raise ValueError("persisted validation target kind is not reviewed")
    if data.get("adapter_kind") != technique.adapter_kind:
        raise ValueError("persisted validation adapter kind is invalid")
    if data.get("cleanup_mode") != technique.cleanup_mode:
        raise ValueError("persisted validation cleanup mode is invalid")
    if data.get("side_effect_mode") != "none":
        raise ValueError("persisted validation side-effect mode is invalid")
    if data.get("execution_mode") != "isolated-worker":
        raise ValueError("persisted validation execution mode is invalid")
    if binding_id != validation_binding_id(
        eligibility_id,
        contract_id,
        target_node_id,
    ):
        raise ValueError("persisted validation binding identifier is invalid")
    if record.provenance != f"validation-worker://{binding_id}":
        raise ValueError("persisted validation provenance does not match binding")

    try:
        state = ValidationWorkerState(_required_data_text(data, "state"))
    except ValueError as exc:
        raise ValueError("persisted validation state is invalid") from exc

    evidence = data.get("evidence")
    if not isinstance(evidence, Mapping):
        raise ValueError("persisted validation evidence payload is invalid")
    if state in {
        ValidationWorkerState.CONFIRMED,
        ValidationWorkerState.NOT_CONFIRMED,
    }:
        observation = ValidationObservation(
            confirmed=state is ValidationWorkerState.CONFIRMED,
            summary=summary,
            evidence=dict(evidence),
            limitations=record.limitations[:-2],
        )
        postconditions = check_validation_observation_contract(
            contract,
            observation,
        )
        if not postconditions.valid:
            raise ValueError(
                "persisted validation evidence violates reviewed postconditions"
            )
    elif state in _NON_SUCCESS_STATES:
        if evidence:
            raise ValueError(
                "persisted non-success validation must not contain evidence"
            )
    else:
        raise ValueError("persisted validation state is unsupported")

    for key in ("actions_used", "remaining_actions"):
        value = data.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(
                f"persisted validation action counter is invalid: {key}"
            )

    identity = {
        "engagement_id": record.engagement_id,
        "observed_at": record.observed_at,
        **dict(record.data),
        "limitations": list(record.limitations),
    }
    if record.evidence_id != _canonical_record_id(
        "validation-result-",
        identity,
    ):
        raise ValueError("persisted validation evidence identifier is invalid")
    if len(record.to_json().encode("utf-8")) > _MAX_LIFECYCLE_RECORD_BYTES:
        raise ValueError("persisted validation evidence exceeds byte ceiling")
    return state


def _validate_cleanup_record(
    record: EvidenceRecord,
    validation_record: EvidenceRecord,
) -> str:
    if record.source_night != "red":
        raise ValueError("validation cleanup evidence must come from Red Night")
    if record.evidence_type != CLEANUP_EVIDENCE_TYPE:
        raise ValueError("retest cleanup evidence type is invalid")
    if set(record.data) != _CLEANUP_DATA_FIELDS:
        raise ValueError("persisted validation cleanup schema is invalid")

    data = record.data
    binding_id = _required_data_text(data, "binding_id")
    technique_id = _required_data_text(data, "technique_id")
    cleanup_state = _required_data_text(data, "cleanup_state")
    if record.engagement_id != validation_record.engagement_id:
        raise ValueError("retest lifecycle records belong to different engagements")
    if data.get("validation_evidence_id") != validation_record.evidence_id:
        raise ValueError("cleanup record does not reference validation evidence")
    if binding_id != validation_record.data.get("binding_id"):
        raise ValueError("cleanup record binding does not match validation evidence")
    if technique_id != validation_record.data.get("technique_id"):
        raise ValueError("cleanup record technique does not match validation evidence")
    if data.get("cleanup_mode") != "none":
        raise ValueError("persisted validation cleanup mode is invalid")
    if data.get("side_effect_mode") != "none":
        raise ValueError("persisted validation cleanup side-effect mode is invalid")
    if cleanup_state != CLEANUP_NOT_REQUIRED:
        raise ValueError("persisted validation cleanup state is invalid")
    if data.get("cleanup_actions") != 0:
        raise ValueError("no-op cleanup must not report cleanup actions")
    if record.provenance != f"validation-cleanup://{binding_id}":
        raise ValueError("persisted cleanup provenance does not match binding")

    identity = {
        "engagement_id": record.engagement_id,
        "observed_at": record.observed_at,
        **dict(record.data),
        "limitations": list(record.limitations),
    }
    if record.evidence_id != _canonical_record_id(
        "validation-cleanup-",
        identity,
    ):
        raise ValueError("persisted cleanup evidence identifier is invalid")
    if len(record.to_json().encode("utf-8")) > _MAX_LIFECYCLE_RECORD_BYTES:
        raise ValueError("persisted cleanup evidence exceeds byte ceiling")
    return cleanup_state


@dataclass(frozen=True)
class ValidationLifecycleIntegrity:
    engagement_id: str
    validation_evidence_id: str
    cleanup_evidence_id: str
    binding_id: str
    technique_id: str
    state: str
    evidence_keys: tuple[str, ...]
    cleanup_state: str

    def to_dict(self) -> dict[str, object]:
        return {
            "engagement_id": self.engagement_id,
            "validation_evidence_id": self.validation_evidence_id,
            "cleanup_evidence_id": self.cleanup_evidence_id,
            "binding_id": self.binding_id,
            "technique_id": self.technique_id,
            "state": self.state,
            "evidence_keys": list(self.evidence_keys),
            "cleanup_state": self.cleanup_state,
        }


def validate_validation_lifecycle_records(
    validation_record: EvidenceRecord,
    cleanup_record: EvidenceRecord,
) -> ValidationLifecycleIntegrity:
    """Validate exact durable lifecycle records without changing any state."""

    state = _validate_validation_record(validation_record)
    cleanup_state = _validate_cleanup_record(
        cleanup_record,
        validation_record,
    )
    evidence = validation_record.data.get("evidence")
    if not isinstance(evidence, Mapping):
        raise ValueError("persisted validation evidence payload is invalid")
    return ValidationLifecycleIntegrity(
        engagement_id=validation_record.engagement_id,
        validation_evidence_id=validation_record.evidence_id,
        cleanup_evidence_id=cleanup_record.evidence_id,
        binding_id=_required_data_text(
            validation_record.data,
            "binding_id",
        ),
        technique_id=_required_data_text(
            validation_record.data,
            "technique_id",
        ),
        state=state.value,
        evidence_keys=tuple(sorted(evidence)),
        cleanup_state=cleanup_state,
    )


def _persisted_exact(
    workspace: LocalWorkspace,
    record: EvidenceRecord,
) -> None:
    existing = {
        item.evidence_id: item
        for item in workspace.envelope(record.engagement_id).records
    }.get(record.evidence_id)
    if existing is None:
        raise ValueError("validation lifecycle evidence is not persisted")
    if existing != record:
        raise ValueError("persisted validation lifecycle evidence has changed")


def record_persisted_validation_retest(
    workspace: LocalWorkspace,
    remediation_store: RemediationStore,
    finding_id: str,
    lifecycle: ValidationEvidenceLifecycle,
    *,
    now: datetime | None = None,
) -> RetestOutcome:
    """Drive remediation state only from exact persisted lifecycle evidence."""

    validation_record = lifecycle.validation_record
    cleanup_record = lifecycle.cleanup_record
    _persisted_exact(workspace, validation_record)
    _persisted_exact(workspace, cleanup_record)

    integrity = validate_validation_lifecycle_records(
        validation_record,
        cleanup_record,
    )
    validation_state = integrity.state
    cleanup_state = integrity.cleanup_state
    binding_id = integrity.binding_id

    return remediation_store.record_evidence_retest(
        finding_id,
        engagement_id=validation_record.engagement_id,
        validation_id=binding_id,
        validation_state=validation_state,
        validation_evidence_id=validation_record.evidence_id,
        cleanup_evidence_id=cleanup_record.evidence_id,
        cleanup_state=cleanup_state,
        now=now,
    )
