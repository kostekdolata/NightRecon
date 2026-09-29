"""v0.43 Batch 5 durable validation evidence and retest lifecycle tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from nightrecon_red_engine.remediation_retest import (
    RemediationStatus,
    RemediationStore,
)
from nightrecon_red_engine.validation_adapter_contracts import (
    ValidationAdapterBinding,
    validation_binding_id,
)
from nightrecon_red_engine.validation_evidence_lifecycle import (
    CLEANUP_NOT_REQUIRED,
    build_validation_result_evidence,
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


def binding():
    eligibility_id = "validation-eligibility-fixture"
    contract_id = "service.tcp-property-proof.contract.v1"
    target_node_id = "graph-node-fixture"
    return ValidationAdapterBinding(
        binding_id=validation_binding_id(
            eligibility_id,
            contract_id,
            target_node_id,
        ),
        eligibility_id=eligibility_id,
        candidate_id="validation-candidate-fixture",
        path_id="atlas-fixture",
        technique_id="service.tcp-property-proof",
        contract_id=contract_id,
        target_node_id=target_node_id,
        target_kind="service",
        expected_evidence_keys=("transport", "port", "state"),
        impact="standard",
        requires_approval=False,
        adapter_kind="read-only-proof",
        cleanup_mode="none",
        side_effect_mode="none",
    )


def worker_result(state=ValidationWorkerState.CONFIRMED):
    evidence = (
        {"transport": "tcp", "port": 443, "state": "open"}
        if state is ValidationWorkerState.CONFIRMED
        else {}
    )
    return ValidationWorkerResult(
        engagement_id="eng-lifecycle",
        binding_id=binding().binding_id,
        technique_id="service.tcp-property-proof",
        target="192.0.2.50",
        state=state,
        reason_code=(
            "validated"
            if state is ValidationWorkerState.CONFIRMED
            else state.value.replace("-", "_")
        ),
        summary="Deterministic lifecycle fixture.",
        evidence=evidence,
        limitations=("Fixture only.",),
        actions_used=1,
        remaining_actions=2,
        worker_pid=12345,
    )


def workspace(root):
    ws = LocalWorkspace(root)
    ws.create_engagement(EngagementMetadata(
        engagement_id="eng-lifecycle",
        name="Lifecycle lab",
        created_at="2026-09-29T20:00:00+00:00",
        authorization_reference="approval://eng-lifecycle",
        status="active",
    ))
    return ws


def ready_finding(root):
    store = RemediationStore(Path(root) / "remediation.json")
    store.create(
        engagement_id="eng-lifecycle",
        finding_id="finding-1",
        title="Finding",
        remediation="Apply the approved fix.",
        now=NOW,
    )
    store.transition(
        "finding-1",
        RemediationStatus.IN_PROGRESS,
        now=NOW,
    )
    store.transition(
        "finding-1",
        RemediationStatus.READY_FOR_RETEST,
        now=NOW,
    )
    return store


class ValidationEvidenceLifecycleTests(unittest.TestCase):
    def test_result_and_cleanup_are_deterministic_portable_evidence(self):
        first = build_validation_result_evidence(
            binding(),
            worker_result(),
            observed_at=NOW,
        )
        second = build_validation_result_evidence(
            binding(),
            worker_result(),
            observed_at=NOW,
        )

        self.assertEqual(first, second)
        self.assertEqual(first.evidence_type, "validation.worker-result")
        self.assertEqual(first.data["state"], "confirmed")
        self.assertNotIn("worker_pid", first.data)
        self.assertNotIn("12345", first.to_json())

    def test_persist_is_idempotent_and_cleanup_is_explicit(self):
        with tempfile.TemporaryDirectory() as root:
            ws = workspace(root)
            first = persist_validation_evidence_lifecycle(
                ws,
                binding(),
                worker_result(),
                observed_at=NOW,
            )
            second = persist_validation_evidence_lifecycle(
                ws,
                binding(),
                worker_result(),
                observed_at=NOW,
            )

            self.assertEqual(first.validation_record, second.validation_record)
            self.assertEqual(first.cleanup_record, second.cleanup_record)
            self.assertEqual(first.cleanup_state, CLEANUP_NOT_REQUIRED)
            self.assertEqual(first.added_records, 2)
            self.assertEqual(second.added_records, 0)
            self.assertEqual(second.identical_records, 2)
            self.assertEqual(first.cleanup_record.data["cleanup_actions"], 0)

    def test_not_confirmed_persisted_evidence_verifies_retest(self):
        result = worker_result(ValidationWorkerState.NOT_CONFIRMED)
        result = replace(
            result,
            reason_code="not_confirmed",
            summary="Previously observed condition was not reproduced.",
            evidence={},
        )
        with tempfile.TemporaryDirectory() as root:
            ws = workspace(root)
            lifecycle = persist_validation_evidence_lifecycle(
                ws,
                binding(),
                result,
                observed_at=NOW,
            )
            remediation = ready_finding(root)
            outcome = record_persisted_validation_retest(
                ws,
                remediation,
                "finding-1",
                lifecycle,
                now=NOW,
            )
            finding = remediation.get("finding-1")

        self.assertTrue(outcome.conclusive)
        self.assertEqual(outcome.resulting_status, "verified")
        self.assertEqual(finding.status, RemediationStatus.VERIFIED)
        self.assertEqual(
            finding.last_validation_evidence_id,
            lifecycle.validation_evidence_id,
        )
        self.assertEqual(
            finding.last_cleanup_evidence_id,
            lifecycle.cleanup_evidence_id,
        )
        self.assertEqual(finding.last_cleanup_state, "not-required")

    def test_confirmed_persisted_evidence_marks_regressed(self):
        with tempfile.TemporaryDirectory() as root:
            ws = workspace(root)
            lifecycle = persist_validation_evidence_lifecycle(
                ws,
                binding(),
                worker_result(),
                observed_at=NOW,
            )
            remediation = ready_finding(root)
            outcome = record_persisted_validation_retest(
                ws,
                remediation,
                "finding-1",
                lifecycle,
                now=NOW,
            )

        self.assertTrue(outcome.conclusive)
        self.assertEqual(outcome.resulting_status, "regressed")

    def test_revoked_retest_remains_inconclusive(self):
        with tempfile.TemporaryDirectory() as root:
            ws = workspace(root)
            lifecycle = persist_validation_evidence_lifecycle(
                ws,
                binding(),
                worker_result(ValidationWorkerState.REVOKED),
                observed_at=NOW,
            )
            remediation = ready_finding(root)
            outcome = record_persisted_validation_retest(
                ws,
                remediation,
                "finding-1",
                lifecycle,
                now=NOW,
            )

        self.assertFalse(outcome.conclusive)
        self.assertEqual(outcome.resulting_status, "ready-for-retest")
        self.assertEqual(
            remediation.get("finding-1").last_retest_state,
            "revoked",
        )

    def test_unpersisted_lifecycle_cannot_drive_retest(self):
        with tempfile.TemporaryDirectory() as root:
            ws = workspace(root)
            lifecycle = persist_validation_evidence_lifecycle(
                ws,
                binding(),
                worker_result(),
                observed_at=NOW,
            )
            other = workspace(Path(root) / "other")
            remediation = ready_finding(Path(root) / "rem")
            with self.assertRaisesRegex(ValueError, "not persisted"):
                record_persisted_validation_retest(
                    other,
                    remediation,
                    "finding-1",
                    lifecycle,
                    now=NOW,
                )

    def test_binding_drift_and_side_effecting_cleanup_fail_closed(self):
        forged = replace(binding(), binding_id="validation-binding-forged")
        with self.assertRaisesRegex(ValueError, "identifier"):
            build_validation_result_evidence(
                forged,
                replace(worker_result(), binding_id=forged.binding_id),
                observed_at=NOW,
            )

        side_effecting = replace(
            binding(),
            side_effect_mode="mutating",
        )
        with self.assertRaisesRegex(ValueError, "reviewed cleanup"):
            build_validation_result_evidence(
                side_effecting,
                replace(
                    worker_result(),
                    binding_id=side_effecting.binding_id,
                ),
                observed_at=NOW,
            )


if __name__ == "__main__":
    unittest.main()
