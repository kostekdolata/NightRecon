"""Read-only, redacted operator report for supplied offline network benchmarks.

This renderer never performs network activity or grants authorization. It
publishes no run identifiers, authorization references, targets, or raw evidence.
"""
from __future__ import annotations

from .network_benchmark import NetworkBenchmarkResult
from .network_benchmark_provenance import (
    NetworkBenchmarkProvenance,
    review_network_benchmark_quality_ranges,
)

_METRICS = (
    ("TCP open", "matched_tcp_open", "missed_tcp_open", "invented_tcp_open"),
    ("UDP open", "matched_udp_open", "missed_udp_open", "invented_udp_open"),
    ("Services", "matched_services", "missed_services", "invented_services"),
    (
        "Operating systems", "matched_operating_systems",
        "missed_operating_systems", "conflicting_operating_systems",
    ),
)


def render_network_benchmark_quality_report(
    observations: tuple[tuple[NetworkBenchmarkProvenance, NetworkBenchmarkResult], ...],
) -> str:
    """Render a deterministic, non-secret Markdown review for 2–32 lab runs.

    Uses the existing integrity, compatibility, independence and scope gates.
    Blocked input never emits aggregate metrics. A clean result remains
    *unverified* rather than claiming external specialist parity.
    """
    if not isinstance(observations, tuple):
        raise TypeError("Offline benchmark report observations must be a tuple")
    review = review_network_benchmark_quality_ranges(observations)
    status = review["status"]
    lines = [
        "# Red Night — Offline Network Benchmark Quality Review",
        "",
        f"**Status:** `{status}`",
        f"**Submitted observations:** {review['observation_count']}",
        f"**Operator review required:** {'yes' if review['requires_review'] else 'no'}",
        "**Authorization effect:** none",
        "",
    ]
    if status == "blocked":
        lines.extend((
            "## Aggregate results withheld",
            "",
            "The supplied evidence did not pass all integrity, scope, lab-setup "
            "and independent-run checks. No quality metrics are published. "
            "Correct the evidence and repeat the offline review.",
            "",
        ))
    else:
        lines.extend((
            "## Observed count ranges",
            "",
            "| Category | Matched min–max | Missed min–max | "
            "Unexpected/conflicting min–max |",
            "| --- | ---: | ---: | ---: |",
        ))
        ranges = review["quality_ranges"]
        for name, matched, missed, unexpected in _METRICS:
            def span(field: str) -> str:
                values = ranges[field]
                return f"{values['min']}–{values['max']}"
            lines.append(
                f"| {name} | {span(matched)} | {span(missed)} | "
                f"{span(unexpected)} |"
            )
        lines.extend(("",))
        if status == "review_required":
            lines.extend((
                "## Review required",
                "",
                "Observations changed across comparable lab runs. Investigate "
                "the differences before drawing quality conclusions.",
                "",
            ))
    lines.extend((
        "## Evidence limitations",
        "",
        "- These counts come from operator-supplied offline observations; "
        "their ground truth has not been independently verified.",
        "- Matching counts do not prove accuracy, repeatability under other "
        "conditions, or parity with Nmap or another specialist.",
        "- No scan, authorization, target expansion, or intrusive operation "
        "is permitted or performed by this report.",
        "- Run identifiers, authorization references, target addresses and "
        "raw evidence are deliberately omitted.",
        "",
    ))
    return "\n".join(lines)
