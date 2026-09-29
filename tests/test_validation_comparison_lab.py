"""v0.43 Batch 6 controlled validation comparison lab tests."""

from __future__ import annotations

from datetime import datetime, timezone
import unittest

from nightrecon_red_engine.validation_adapter_contracts import (
    BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY,
    ValidationAdapterBinding,
    validation_binding_id,
)
from nightrecon_red_engine.validation_comparison_lab import (
    ExpectedValidationScenario,
    ValidationComparisonExpectation,
    run_controlled_validation_fixture_comparison,
)
from nightrecon_red_engine.validation_evidence_lifecycle import (
    ValidationEvidenceLifecycle,
    build_cleanup_evidence,
    build_validation_result_evidence,
)
from nightrecon_red_engine.validation_techniques import (
    BUILTIN_VALIDATION_TECHNIQUE_REGISTRY,
)
from nightrecon_red_engine.validation_worker import (
    ValidationWorkerResult,
    ValidationWorkerState,
)


NOW = datetime(2026, 9, 29, 22, 20, tzinfo=timezone.utc)


def binding(technique_id, target_kind):
    technique = BUILTIN_VALIDATION_TECHNIQUE_REGISTRY.get(technique_id)
    contract = BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY.for_technique(
        technique_id
    )
    eligibility_id = f"validation-eligibility-{technique_id}"
    target_node_id = f"graph-node-{technique_id}"
    return ValidationAdapterBinding(
        binding_id=validation_binding_id(
            eligibility_id,
            contract.contract_id,
            target_node_id,
        ),
        eligibility_id=eligibility_id,
        candidate_id=f"validation-candidate-{technique_id}",
        path_id=f"atlas-{technique_id}",
        technique_id=technique_id,
        contract_id=contract.contract_id,
        target_node_id=target_node_id,
        target_kind=target_kind,
        expected_evidence_keys=technique.evidence_keys,
        impact=technique.impact,
        requires_approval=technique.requires_approval,
        adapter_kind=technique.adapter_kind,
        cleanup_mode=technique.cleanup_mode,
        side_effect_mode="none",
    )


def lifecycle(technique_id, target_kind, evidence):
    selected = binding(technique_id, target_kind)
    result = ValidationWorkerResult(
        engagement_id="eng-comparison",
        binding_id=selected.binding_id,
        technique_id=technique_id,
        target="192.0.2.70",
        state=ValidationWorkerState.CONFIRMED,
        reason_code="validated",
        summary="Controlled comparison fixture.",
        evidence=evidence,
        limitations=("Fixture only.",),
        actions_used=1,
        remaining_actions=2,
        worker_pid=999,
    )
    validation = build_validation_result_evidence(
        selected,
        result,
        observed_at=NOW,
    )
    cleanup = build_cleanup_evidence(
        selected,
        validation,
        observed_at=NOW,
    )
    return ValidationEvidenceLifecycle(
        validation_record=validation,
        cleanup_record=cleanup,
        added_records=2,
        identical_records=0,
    )


def all_lifecycles():
    return (
        lifecycle(
            "service.tcp-property-proof",
            "service",
            {"transport": "tcp", "port": 443, "state": "open"},
        ),
        lifecycle(
            "service.tls-property-proof",
            "service",
            {
                "tls_version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "certificate_sha256": "a" * 64,
            },
        ),
        lifecycle(
            "web.http-policy-proof",
            "web",
            {
                "status_code": 200,
                "security_headers": (
                    "content-security-policy",
                    "x-content-type-options",
                ),
            },
        ),
    )


def exact_expectation():
    return ValidationComparisonExpectation(
        scenarios=(
            ExpectedValidationScenario(
                "service.tcp-property-proof",
                "confirmed",
                ("port", "state", "transport"),
                "not-required",
                "related",
                ("T1046",),
            ),
            ExpectedValidationScenario(
                "service.tls-property-proof",
                "confirmed",
                ("certificate_sha256", "cipher", "tls_version"),
                "not-required",
                "reviewed-unmapped",
                (),
            ),
            ExpectedValidationScenario(
                "web.http-policy-proof",
                "confirmed",
                ("security_headers", "status_code"),
                "not-required",
                "reviewed-unmapped",
                (),
            ),
        ),
        operator_steps=3,
    )


class ValidationComparisonLabTests(unittest.TestCase):
    def test_exact_fixture_matches_without_invention_or_parity_claim(self):
        result = run_controlled_validation_fixture_comparison(
            all_lifecycles(),
            exact_expectation(),
        )

        self.assertEqual(result.expected_scenarios, 3)
        self.assertEqual(result.matched_scenarios, 3)
        self.assertEqual(result.missed_scenarios, 0)
        self.assertEqual(result.invented_scenarios, 0)
        self.assertEqual(result.lifecycle_complete_scenarios, 3)
        self.assertEqual(result.related_attack_scenarios, 1)
        self.assertEqual(result.reviewed_unmapped_scenarios, 2)
        self.assertEqual(result.operator_steps, 3)
        self.assertEqual(len(result.comparison_sha256), 64)
        self.assertGreaterEqual(result.duration_ms, 0.0)
        self.assertIn("do not establish", result.interpretation)

    def test_comparison_fingerprint_excludes_runtime(self):
        first = run_controlled_validation_fixture_comparison(
            all_lifecycles(),
            exact_expectation(),
        )
        second = run_controlled_validation_fixture_comparison(
            all_lifecycles(),
            exact_expectation(),
        )

        self.assertEqual(first.comparison_sha256, second.comparison_sha256)

    def test_missing_and_invented_scenarios_are_measured(self):
        expected = ValidationComparisonExpectation(
            scenarios=exact_expectation().scenarios[:2],
            operator_steps=2,
        )
        result = run_controlled_validation_fixture_comparison(
            (
                all_lifecycles()[0],
                all_lifecycles()[2],
            ),
            expected,
        )

        self.assertEqual(result.matched_scenarios, 1)
        self.assertEqual(result.missed_scenarios, 1)
        self.assertEqual(result.invented_scenarios, 1)

    def test_duplicate_actual_scenario_fails_closed(self):
        item = all_lifecycles()[0]
        with self.assertRaisesRegex(ValueError, "must be unique"):
            run_controlled_validation_fixture_comparison(
                (item, item),
                exact_expectation(),
            )


if __name__ == "__main__":
    unittest.main()
