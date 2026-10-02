"""Operator-facing summary for deterministic Red Night network benchmarks."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.network_benchmark import NetworkBenchmarkResult


@dataclass(frozen=True)
class NetworkBenchmarkReport:
    headline: str
    summary: str
    coverage_notes: tuple[str, ...]
    safety_notes: tuple[str, ...]
    comparison_sha256: str
    duration_ms: float

    def to_dict(self) -> dict[str, object]:
        return {
            "headline": self.headline,
            "summary": self.summary,
            "coverage_notes": list(self.coverage_notes),
            "safety_notes": list(self.safety_notes),
            "comparison_sha256": self.comparison_sha256,
            "duration_ms": self.duration_ms,
        }


def build_network_benchmark_report(
    result: NetworkBenchmarkResult,
) -> NetworkBenchmarkReport:
    """Translate raw benchmark metrics into evidence-honest operator feedback."""

    gaps = (
        result.missed_tcp_open
        + result.missed_udp_open
        + result.missed_services
        + result.missed_operating_systems
    )
    unexpected = (
        result.invented_tcp_open
        + result.invented_udp_open
        + result.invented_services
        + result.conflicting_operating_systems
    )

    if result.scope_violation_count:
        headline = "Network benchmark detected scope-boundary violations"
    elif gaps or unexpected:
        headline = "Network benchmark detected evidence differences"
    elif result.ambiguous_udp_expected_open:
        headline = "Network benchmark matched with unresolved UDP ambiguity"
    else:
        headline = "Network benchmark matched the explicit lab expectation"

    coverage_notes = (
        f"TCP missed={result.missed_tcp_open}, unexpected={result.invented_tcp_open}.",
        (
            "UDP missed="
            f"{result.missed_udp_open}, unexpected={result.invented_udp_open}, "
            f"expected-open ambiguous={result.ambiguous_udp_expected_open}."
        ),
        f"Services missed={result.missed_services}, unexpected={result.invented_services}.",
        (
            "OS expected="
            f"{result.expected_operating_systems}, matched={result.matched_operating_systems}, "
            f"missed={result.missed_operating_systems}, conflicting={result.conflicting_operating_systems}."
        ),
    )
    safety_notes = (
        f"Scope violations observed={result.scope_violation_count}.",
        "Runtime is reported separately and is excluded from the deterministic comparison fingerprint.",
        result.interpretation,
    )

    return NetworkBenchmarkReport(
        headline=headline,
        summary=(
            f"Compared explicit lab expectations across TCP, UDP, service identity, "
            f"and OS evidence in {result.duration_ms:.3f} ms."
        ),
        coverage_notes=coverage_notes,
        safety_notes=safety_notes,
        comparison_sha256=result.comparison_sha256,
        duration_ms=result.duration_ms,
    )
