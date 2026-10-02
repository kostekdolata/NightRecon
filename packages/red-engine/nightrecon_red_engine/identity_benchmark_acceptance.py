"""Acceptance interpretation for deterministic identity benchmarks."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.identity_benchmark import IdentityBenchmarkResult


@dataclass(frozen=True)
class IdentityBenchmarkAcceptance:
    """Interpret fixture benchmark evidence without claiming specialist parity."""

    fixture_gate: str
    summary: str
    missed_evidence: int
    invented_evidence: int
    provider_truncated: bool
    external_comparison_required: bool
    next_actions: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "fixture_gate": self.fixture_gate,
            "summary": self.summary,
            "missed_evidence": self.missed_evidence,
            "invented_evidence": self.invented_evidence,
            "provider_truncated": self.provider_truncated,
            "external_comparison_required": self.external_comparison_required,
            "next_actions": list(self.next_actions),
        }


def build_identity_benchmark_acceptance(
    benchmark: IdentityBenchmarkResult,
) -> IdentityBenchmarkAcceptance:
    """Evaluate deterministic benchmark quality while keeping live comparison open."""

    if not isinstance(benchmark, IdentityBenchmarkResult):
        raise ValueError("benchmark must be IdentityBenchmarkResult")

    missed = (
        benchmark.missed_identities
        + benchmark.missed_groups
        + benchmark.missed_memberships
        + benchmark.missed_roles
        + benchmark.missed_relationships
    )
    invented = (
        benchmark.invented_identities
        + benchmark.invented_groups
        + benchmark.invented_memberships
        + benchmark.invented_roles
        + benchmark.invented_relationships
    )

    if benchmark.truncated:
        gate = "incomplete"
        summary = (
            "The deterministic identity benchmark is incomplete because the "
            "provider reported truncation or bounded-collection limits."
        )
    elif missed or invented or benchmark.unresolved_members:
        gate = "needs-review"
        summary = (
            "The deterministic identity benchmark contains missed, unexpected, "
            "or unresolved evidence that requires review."
        )
    else:
        gate = "fixture-passed"
        summary = (
            "The deterministic no-network identity fixture matched its explicit "
            "expectation. This does not establish specialist-tool parity."
        )

    actions = [
        "Run an authorized live specialist comparison before making parity claims.",
    ]
    if missed:
        actions.append("Investigate missed expected identity evidence.")
    if invented:
        actions.append("Investigate unexpected identity evidence.")
    if benchmark.unresolved_members:
        actions.append("Resolve or explain unresolved membership references.")
    if benchmark.truncated:
        actions.append("Repeat the benchmark without provider truncation.")

    return IdentityBenchmarkAcceptance(
        fixture_gate=gate,
        summary=summary,
        missed_evidence=missed,
        invented_evidence=invented,
        provider_truncated=benchmark.truncated,
        external_comparison_required=True,
        next_actions=tuple(actions),
    )
