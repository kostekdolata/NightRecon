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
    identity = {
        "engagement_id": result.engagement_id,
        "observed_at": current.isoformat(),
        **data,
        "limitations": list(result.limitations),
    }
    return EvidenceRecord(
        engagement_id=result.engagement_id,
        evidence_id=_canonical_record_id("validation-result-", identity),
        source_night="red",
        evidence_type=VALIDATION_EVIDENCE_TYPE,
        observed_at=current.isoformat(),
        provenance=f"validation-worker://{binding.binding_id}",
        data=data,
        limitations=result.limitations + (
            "Worker process identity is intentionally not persisted.",
            "Validation evidence is descriptive proof, not an exploitability verdict.",
        ),
    )


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
    if validation_record.engagement_id != validation_record.engagement_id:
        raise ValueError("cleanup validation record engagement is invalid")
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
    identity = {
        "engagement_id": validation_record.engagement_id,
        "observed_at": current.isoformat(),
        **data,
    }
    return EvidenceRecord(
        engagement_id=validation_record.engagement_id,
        evidence_id=_canonical_record_id("validation-cleanup-", identity),
        source_night="red",
        evidence_type=CLEANUP_EVIDENCE_TYPE,
        observed_at=current.isoformat(),
        provenance=f"validation-cleanup://{binding.binding_id}",
        data=data,
        limitations=(
            "No cleanup action was required because the reviewed technique "
            "declares no side effects.",
        ),
    )


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

    if validation_record.evidence_type != VALIDATION_EVIDENCE_TYPE:
        raise ValueError("retest validation evidence type is invalid")
    if cleanup_record.evidence_type != CLEANUP_EVIDENCE_TYPE:
        raise ValueError("retest cleanup evidence type is invalid")
    if validation_record.engagement_id != cleanup_record.engagement_id:
        raise ValueError("retest lifecycle records belong to different engagements")
    if cleanup_record.data.get("validation_evidence_id") != (
        validation_record.evidence_id
    ):
        raise ValueError("cleanup record does not reference validation evidence")
    if cleanup_record.data.get("binding_id") != validation_record.data.get(
        "binding_id"
    ):
        raise ValueError("cleanup record binding does not match validation evidence")

    validation_state = validation_record.data.get("state")
    binding_id = validation_record.data.get("binding_id")
    cleanup_state = cleanup_record.data.get("cleanup_state")
    if not isinstance(validation_state, str):
        raise ValueError("validation evidence state is invalid")
    if not isinstance(binding_id, str):
        raise ValueError("validation evidence binding is invalid")
    if not isinstance(cleanup_state, str):
        raise ValueError("cleanup evidence state is invalid")

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
