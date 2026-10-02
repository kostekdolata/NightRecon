"""Tests for explicit validation operation plans."""

import unittest

from nightrecon_red_engine.validation_operation_plan import (
    build_validation_operation_plan,
)

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



class ValidationOperationPlanTests(unittest.TestCase):
    def test_plan_preserves_explicit_order_and_attack_review(self):
        plan = build_validation_operation_plan((
            binding("a"),
            binding("b", "web.http-policy-proof"),
        ))

        self.assertEqual(
            [item.binding_id for item in plan.steps],
            ["binding-a", "binding-b"],
        )
        self.assertEqual(plan.attack_ids, ("T1046",))
        self.assertEqual(plan.authorization_effect, "none")
        self.assertIn("grants no authorization", plan.interpretation)

    def test_duplicate_binding_fails_closed(self):
        item = binding("a")

        with self.assertRaisesRegex(ValueError, "unique"):
            build_validation_operation_plan((item, item))

    def test_side_effecting_binding_is_rejected(self):
        item = replace(binding("a"), side_effect_mode="writes-state")

        with self.assertRaisesRegex(ValueError, "side-effecting"):
            build_validation_operation_plan((item,))


if __name__ == "__main__":
    unittest.main()
