"""Deterministic v0.43 ATT&CK review + comparison lab runtime gate."""

from __future__ import annotations

from datetime import datetime, timezone

from nightrecon_red_engine.validation_adapter_contracts import (
    BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY,
    ValidationAdapterBinding,
    validation_binding_id,
)
from nightrecon_red_engine.validation_attack_review import (
    assert_attack_review_coverage,
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


def make_lifecycle(technique_id, target_kind, evidence):
    technique = BUILTIN_VALIDATION_TECHNIQUE_REGISTRY.get(technique_id)
    contract = BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY.for_technique(
        technique_id
    )
    eligibility_id = f"validation-eligibility-{technique_id}"
    target_node_id = f"graph-node-{technique_id}"
    binding = ValidationAdapterBinding(
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
    result = ValidationWorkerResult(
        engagement_id="eng-comparison-runtime",
        binding_id=binding.binding_id,
        technique_id=technique_id,
        target="192.0.2.80",
        state=ValidationWorkerState.CONFIRMED,
        reason_code="validated",
        summary="Runtime comparison fixture.",
        evidence=evidence,
        limitations=("Fixture only.",),
        actions_used=1,
        remaining_actions=1,
        worker_pid=123,
    )
    validation = build_validation_result_evidence(
        binding,
        result,
        observed_at=NOW,
    )
    cleanup = build_cleanup_evidence(
        binding,
        validation,
        observed_at=NOW,
    )
    return ValidationEvidenceLifecycle(
        validation_record=validation,
        cleanup_record=cleanup,
        added_records=2,
        identical_records=0,
    )


def main():
    assert_attack_review_coverage()
    lifecycles = (
        make_lifecycle(
            "service.tcp-property-proof",
            "service",
            {"transport": "tcp", "port": 443, "state": "open"},
        ),
        make_lifecycle(
            "service.tls-property-proof",
            "service",
            {
                "tls_version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "certificate_sha256": "b" * 64,
            },
        ),
        make_lifecycle(
            "web.http-policy-proof",
            "web",
            {
                "status_code": 200,
                "security_headers": ("content-security-policy",),
            },
        ),
    )
    expectation = ValidationComparisonExpectation(
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
    result = run_controlled_validation_fixture_comparison(
        lifecycles,
        expectation,
    )
    assert result.matched_scenarios == 3
    assert result.missed_scenarios == 0
    assert result.invented_scenarios == 0
    assert result.related_attack_scenarios == 1
    assert result.reviewed_unmapped_scenarios == 2
    assert len(result.comparison_sha256) == 64
    assert "do not establish" in result.interpretation
    print("v0.43 ATT&CK review/comparison lab runtime: passed")


if __name__ == "__main__":
    main()
