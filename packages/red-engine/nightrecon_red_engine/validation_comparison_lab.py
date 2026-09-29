"""Deterministic controlled-validation comparison lab for v0.43.

This is a fixture comparison over already-reviewed durable validation lifecycle
records. It does not invoke a worker or external specialist product and must not
be used to claim parity with Caldera, Metasploit, Cobalt Strike, or ATT&CK.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from time import perf_counter

from nightrecon_red_engine.validation_attack_review import (
    BUILTIN_VALIDATION_ATTACK_REVIEW_REGISTRY,
    ValidationAttackReviewRegistry,
)
from nightrecon_red_engine.validation_evidence_lifecycle import (
    ValidationEvidenceLifecycle,
    validate_validation_lifecycle_records,
)


COMPARISON_INTERPRETATION = (
    "Controlled fixture comparison only. Results measure exact NightRecon "
    "reviewed lifecycle expectations and ATT&CK review metadata; they do not "
    "establish feature parity, technique-equivalence, detection coverage, or "
    "operational equivalence with Caldera, Metasploit, Cobalt Strike, ATT&CK, "
    "or another specialist product."
)


@dataclass(frozen=True, order=True)
class ExpectedValidationScenario:
    technique_id: str
    state: str
    evidence_keys: tuple[str, ...]
    cleanup_state: str
    attack_disposition: str
    attack_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ValidationComparisonExpectation:
    scenarios: tuple[ExpectedValidationScenario, ...]
    operator_steps: int

    def __post_init__(self) -> None:
        if isinstance(self.operator_steps, bool) or not isinstance(
            self.operator_steps, int
        ) or self.operator_steps < 0:
            raise ValueError("operator_steps must be a nonnegative integer")
        if len(self.scenarios) != len(set(self.scenarios)):
            raise ValueError("expected validation scenarios must be unique")


@dataclass(frozen=True)
class ValidationComparisonResult:
    expected_scenarios: int
    matched_scenarios: int
    missed_scenarios: int
    invented_scenarios: int
    lifecycle_complete_scenarios: int
    related_attack_scenarios: int
    reviewed_unmapped_scenarios: int
    operator_steps: int
    duration_ms: float
    comparison_sha256: str
    interpretation: str = COMPARISON_INTERPRETATION

    def to_dict(self) -> dict[str, object]:
        return {
            "expected_scenarios": self.expected_scenarios,
            "matched_scenarios": self.matched_scenarios,
            "missed_scenarios": self.missed_scenarios,
            "invented_scenarios": self.invented_scenarios,
            "lifecycle_complete_scenarios": self.lifecycle_complete_scenarios,
            "related_attack_scenarios": self.related_attack_scenarios,
            "reviewed_unmapped_scenarios": self.reviewed_unmapped_scenarios,
            "operator_steps": self.operator_steps,
            "duration_ms": self.duration_ms,
            "comparison_sha256": self.comparison_sha256,
            "interpretation": self.interpretation,
        }


def _scenario_from_lifecycle(
    lifecycle: ValidationEvidenceLifecycle,
    *,
    attack_reviews: ValidationAttackReviewRegistry,
) -> ExpectedValidationScenario:
    integrity = validate_validation_lifecycle_records(
        lifecycle.validation_record,
        lifecycle.cleanup_record,
    )
    review = attack_reviews.get(integrity.technique_id)
    return ExpectedValidationScenario(
        technique_id=integrity.technique_id,
        state=integrity.state,
        evidence_keys=integrity.evidence_keys,
        cleanup_state=integrity.cleanup_state,
        attack_disposition=review.disposition,
        attack_ids=review.attack_ids,
    )


def run_controlled_validation_fixture_comparison(
    lifecycles: tuple[ValidationEvidenceLifecycle, ...],
    expectation: ValidationComparisonExpectation,
    *,
    attack_reviews: ValidationAttackReviewRegistry = (
        BUILTIN_VALIDATION_ATTACK_REVIEW_REGISTRY
    ),
) -> ValidationComparisonResult:
    started = perf_counter()

    actual = tuple(sorted(
        _scenario_from_lifecycle(item, attack_reviews=attack_reviews)
        for item in lifecycles
    ))
    if len(actual) != len(set(actual)):
        raise ValueError("actual validation scenarios must be unique")

    expected_set = set(expectation.scenarios)
    actual_set = set(actual)
    matched = actual_set & expected_set
    missed = expected_set - actual_set
    invented = actual_set - expected_set

    related = sum(
        item.attack_disposition == "related"
        for item in actual
    )
    unmapped = sum(
        item.attack_disposition == "reviewed-unmapped"
        for item in actual
    )

    fingerprint_payload = {
        "expected": [
            {
                "technique_id": item.technique_id,
                "state": item.state,
                "evidence_keys": list(item.evidence_keys),
                "cleanup_state": item.cleanup_state,
                "attack_disposition": item.attack_disposition,
                "attack_ids": list(item.attack_ids),
            }
            for item in sorted(expectation.scenarios)
        ],
        "actual": [
            {
                "technique_id": item.technique_id,
                "state": item.state,
                "evidence_keys": list(item.evidence_keys),
                "cleanup_state": item.cleanup_state,
                "attack_disposition": item.attack_disposition,
                "attack_ids": list(item.attack_ids),
            }
            for item in actual
        ],
        "operator_steps": expectation.operator_steps,
    }
    comparison_sha256 = sha256(
        json.dumps(
            fingerprint_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    duration_ms = (perf_counter() - started) * 1000.0

    return ValidationComparisonResult(
        expected_scenarios=len(expected_set),
        matched_scenarios=len(matched),
        missed_scenarios=len(missed),
        invented_scenarios=len(invented),
        lifecycle_complete_scenarios=len(actual),
        related_attack_scenarios=related,
        reviewed_unmapped_scenarios=unmapped,
        operator_steps=expectation.operator_steps,
        duration_ms=duration_ms,
        comparison_sha256=comparison_sha256,
    )
