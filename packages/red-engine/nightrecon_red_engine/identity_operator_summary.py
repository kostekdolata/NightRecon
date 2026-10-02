"""Operator-facing synthesis for Red Night identity assessment evidence."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.identity_benchmark_acceptance import (
    IdentityBenchmarkAcceptance,
)
from nightrecon_red_engine.identity_coverage_review import IdentityCoverageReview


@dataclass(frozen=True)
class IdentityOperatorSummary:
    """Concise identity assessment status for professional review."""

    headline: str
    evidence_summary: str
    benchmark_summary: str
    relationship_themes: tuple[str, ...]
    limitations: tuple[str, ...]
    next_actions: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "headline": self.headline,
            "evidence_summary": self.evidence_summary,
            "benchmark_summary": self.benchmark_summary,
            "relationship_themes": list(self.relationship_themes),
            "limitations": list(self.limitations),
            "next_actions": list(self.next_actions),
        }


def build_identity_operator_summary(
    coverage: IdentityCoverageReview,
    benchmark: IdentityBenchmarkAcceptance,
) -> IdentityOperatorSummary:
    """Compose evidence coverage and deterministic benchmark results."""

    if coverage.level == "empty":
        headline = "Identity assessment has no collected evidence"
    elif coverage.level == "limited":
        headline = "Identity assessment evidence is incomplete"
    elif benchmark.fixture_gate == "fixture-passed":
        headline = "Identity evidence collected with deterministic fixture proof"
    else:
        headline = "Identity evidence collected with benchmark review required"

    themes = tuple(
        f"{name}: {count}"
        for name, count in coverage.relationship_types
    )
    limitations = tuple(dict.fromkeys((
        *coverage.limitations,
        *coverage.open_acceptance_gates,
    )))
    actions = tuple(dict.fromkeys((
        *benchmark.next_actions,
        *(
            ("Complete broader read-only ACL/security-descriptor coverage.",)
            if coverage.permissions == 0
            else ()
        ),
    )))

    return IdentityOperatorSummary(
        headline=headline,
        evidence_summary=coverage.summary,
        benchmark_summary=benchmark.summary,
        relationship_themes=themes,
        limitations=limitations,
        next_actions=actions,
    )
