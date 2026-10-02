"""Tests for secret-safe validation operation handoff."""

import unittest

from nightrecon_red_engine.validation_operation_handoff import (
    build_validation_operation_handoff,
)
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



class ValidationOperationHandoffTests(unittest.TestCase):
    def test_completed_handoff_references_evidence_without_authority(self):
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

        handoff = build_validation_operation_handoff(plan, progress)

        self.assertEqual(handoff.status, "complete")
        self.assertEqual(handoff.authorization_effect, "none")
        self.assertEqual(
            handoff.validation_evidence_ids,
            ("validation-a",),
        )
        self.assertEqual(handoff.attack_ids, ("T1046",))

    def test_stopped_handoff_keeps_pending_bindings(self):
        plan = build_validation_operation_plan((binding("a"), binding("b")))
        progress = request_validation_operation_stop(
            plan,
            new_validation_operation_progress(plan),
            reason="operator stop",
        )

        handoff = build_validation_operation_handoff(plan, progress)

        self.assertEqual(handoff.status, "stopped")
        self.assertEqual(
            handoff.pending_binding_ids,
            ("binding-a", "binding-b"),
        )
        self.assertEqual(handoff.stop_reason, "operator stop")


if __name__ == "__main__":
    unittest.main()
