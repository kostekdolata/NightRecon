"""Tests for validation operation stop and evidence state."""

import unittest

from nightrecon_red_engine.validation_operation_plan import (
    build_validation_operation_plan,
)
from nightrecon_red_engine.validation_operation_state import (
    new_validation_operation_progress,
    record_validation_operation_outcome,
    request_validation_operation_stop,
)
from nightrecon_red_engine.validation_worker import ValidationWorkerState

from dataclasses import replace

from nightrecon_red_engine.validation_adapter_contracts import ValidationAdapterBinding


def binding(name, technique="service.tcp-property-proof"):
    return ValidationAdapterBinding(
        binding_id=f"binding-{name}",
        eligibility_id=f"eligibility-{name}",
        candidate_id=f"candidate-{name}",
        path_id=f"path-{name}",
        technique_id=technique,
        contract_id=f"{technique}.contract.v1",
        target_node_id=f"node-{name}",
        target_kind="service" if technique.startswith("service.") else "web",
        expected_evidence_keys=(
            ("transport", "port", "state")
            if technique == "service.tcp-property-proof"
            else ("status_code", "security_headers")
        ),
        impact="standard",
        requires_approval=False,
        adapter_kind="read-only-proof",
        cleanup_mode="none",
        side_effect_mode="none",
    )



class ValidationOperationStateTests(unittest.TestCase):
    def test_outcomes_must_follow_explicit_plan_order(self):
        plan = build_validation_operation_plan((binding("a"), binding("b")))
        progress = new_validation_operation_progress(plan)

        with self.assertRaisesRegex(ValueError, "explicit plan order"):
            record_validation_operation_outcome(
                plan,
                progress,
                binding_id="binding-b",
                worker_state=ValidationWorkerState.CONFIRMED,
                validation_evidence_id="validation-b",
                cleanup_evidence_id="cleanup-b",
                cleanup_state="not-required",
            )

    def test_stop_blocks_further_outcomes(self):
        plan = build_validation_operation_plan((binding("a"),))
        progress = request_validation_operation_stop(
            plan,
            new_validation_operation_progress(plan),
            reason="operator stop",
        )

        with self.assertRaisesRegex(ValueError, "stopped"):
            record_validation_operation_outcome(
                plan,
                progress,
                binding_id="binding-a",
                worker_state=ValidationWorkerState.CONFIRMED,
                validation_evidence_id="validation-a",
                cleanup_evidence_id="cleanup-a",
                cleanup_state="not-required",
            )

    def test_records_persisted_evidence_references_only(self):
        plan = build_validation_operation_plan((binding("a"),))
        progress = record_validation_operation_outcome(
            plan,
            new_validation_operation_progress(plan),
            binding_id="binding-a",
            worker_state=ValidationWorkerState.CONFIRMED,
            validation_evidence_id="validation-a",
            cleanup_evidence_id="cleanup-a",
            cleanup_state="not-required",
        )

        self.assertEqual(
            progress.outcomes[0].validation_evidence_id,
            "validation-a",
        )
        self.assertEqual(
            progress.outcomes[0].cleanup_evidence_id,
            "cleanup-a",
        )


if __name__ == "__main__":
    unittest.main()
