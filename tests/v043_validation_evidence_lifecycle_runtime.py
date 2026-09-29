"""Deterministic v0.43 validation evidence/retest lifecycle gate."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile

from nightrecon_red_engine.remediation_retest import (
    RemediationStatus,
    RemediationStore,
)
from nightrecon_red_engine.validation_adapter_contracts import (
    ValidationAdapterBinding,
    validation_binding_id,
)
from nightrecon_red_engine.validation_evidence_lifecycle import (
    persist_validation_evidence_lifecycle,
    record_persisted_validation_retest,
)
from nightrecon_red_engine.validation_worker import (
    ValidationWorkerResult,
    ValidationWorkerState,
)
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.workspace import LocalWorkspace


NOW = datetime(2026, 9, 29, 21, 30, tzinfo=timezone.utc)
ELIGIBILITY_ID = "validation-eligibility-runtime"
CONTRACT_ID = "service.tcp-property-proof.contract.v1"
TARGET_NODE_ID = "graph-node-runtime"
BINDING = ValidationAdapterBinding(
    binding_id=validation_binding_id(
        ELIGIBILITY_ID,
        CONTRACT_ID,
        TARGET_NODE_ID,
    ),
    eligibility_id=ELIGIBILITY_ID,
    candidate_id="validation-candidate-runtime",
    path_id="atlas-runtime",
    technique_id="service.tcp-property-proof",
    contract_id=CONTRACT_ID,
    target_node_id=TARGET_NODE_ID,
    target_kind="service",
    expected_evidence_keys=("transport", "port", "state"),
    impact="standard",
    requires_approval=False,
    adapter_kind="read-only-proof",
    cleanup_mode="none",
    side_effect_mode="none",
)
RESULT = ValidationWorkerResult(
    engagement_id="eng-lifecycle-runtime",
    binding_id=BINDING.binding_id,
    technique_id=BINDING.technique_id,
    target="192.0.2.60",
    state=ValidationWorkerState.NOT_CONFIRMED,
    reason_code="not_confirmed",
    summary="Condition was not reproduced.",
    evidence={},
    limitations=("Deterministic runtime fixture.",),
    actions_used=1,
    remaining_actions=1,
    worker_pid=999,
)


def main():
    with tempfile.TemporaryDirectory() as root:
        workspace = LocalWorkspace(root)
        workspace.create_engagement(EngagementMetadata(
            engagement_id="eng-lifecycle-runtime",
            name="Lifecycle runtime",
            created_at="2026-09-29T20:00:00+00:00",
            authorization_reference="approval://eng-lifecycle-runtime",
            status="active",
        ))
        lifecycle = persist_validation_evidence_lifecycle(
            workspace,
            BINDING,
            RESULT,
            observed_at=NOW,
        )

        remediation = RemediationStore(Path(root) / "remediation.json")
        remediation.create(
            engagement_id="eng-lifecycle-runtime",
            finding_id="finding-runtime",
            title="Runtime finding",
            remediation="Apply approved fix.",
            now=NOW,
        )
        remediation.transition(
            "finding-runtime",
            RemediationStatus.IN_PROGRESS,
            now=NOW,
        )
        remediation.transition(
            "finding-runtime",
            RemediationStatus.READY_FOR_RETEST,
            now=NOW,
        )
        outcome = record_persisted_validation_retest(
            workspace,
            remediation,
            "finding-runtime",
            lifecycle,
            now=NOW,
        )
        finding = remediation.get("finding-runtime")

        assert lifecycle.added_records == 2
        assert lifecycle.cleanup_state == "not-required"
        assert outcome.conclusive is True
        assert outcome.resulting_status == "verified"
        assert finding.status is RemediationStatus.VERIFIED
        assert finding.last_validation_evidence_id == lifecycle.validation_evidence_id
        assert finding.last_cleanup_evidence_id == lifecycle.cleanup_evidence_id
        assert RESULT.worker_pid is not None
        assert str(RESULT.worker_pid) not in lifecycle.validation_record.to_json()

    print("v0.43 validation evidence/retest lifecycle runtime: passed")


if __name__ == "__main__":
    main()
