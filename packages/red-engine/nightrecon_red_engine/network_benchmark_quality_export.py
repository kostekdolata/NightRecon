"""Versioned, redacted JSON export for offline Red network quality reviews.

This module never scans, authorizes, or exports raw observations. The same
integrity, lab compatibility, scope, and independent-run gates used by the
operator Markdown report govern all machine-readable aggregates.
"""
from __future__ import annotations

import json

from .network_benchmark import NetworkBenchmarkResult
from .network_benchmark_provenance import (
    NetworkBenchmarkProvenance,
    review_network_benchmark_quality_ranges,
)

_FIELDS = (
    "matched_tcp_open", "missed_tcp_open", "invented_tcp_open",
    "matched_udp_open", "missed_udp_open", "invented_udp_open",
    "matched_services", "missed_services", "invented_services",
    "matched_operating_systems", "missed_operating_systems",
    "conflicting_operating_systems",
)
_LIMITATIONS = (
    "Operator-supplied offline observations are not independently verified ground truth.",
    "Observed counts do not establish specialist-tool parity or exploitability.",
    "Export conveys no authorization or permission to execute scans.",
)


def build_network_benchmark_quality_export(
    observations: tuple[tuple[NetworkBenchmarkProvenance, NetworkBenchmarkResult], ...],
) -> dict[str, object]:
    """Build a versioned portable report with no raw evidence or identifiers.

    Ineligible inputs yield no partial counts. All output fields are explicitly
    selected rather than copied from operator-supplied evidence objects.
    """
    if not isinstance(observations, tuple):
        raise TypeError("Offline benchmark export observations must be a tuple")
    review = review_network_benchmark_quality_ranges(observations)
    blocked = review["status"] == "blocked"
    ranges = review["quality_ranges"]
    if blocked:
        metrics = None
    else:
        if not isinstance(ranges, dict) or set(ranges) != set(_FIELDS):
            raise ValueError("Offline benchmark quality ranges are incomplete")
        metrics = {
            field: {"min": int(ranges[field]["min"]), "max": int(ranges[field]["max"])}
            for field in _FIELDS
        }
    return {
        "schema_version": 1,
        "report_type": "red-offline-network-benchmark-quality",
        "status": review["status"],
        "observation_count": review["observation_count"],
        "requires_review": review["requires_review"],
        "authorization_effect": "none",
        "aggregate_metrics": metrics,
        "limitations": list(_LIMITATIONS),
    }


def render_network_benchmark_quality_json(
    observations: tuple[tuple[NetworkBenchmarkProvenance, NetworkBenchmarkResult], ...],
) -> str:
    """Render stable JSON suitable for offline archival or cross-tool review."""
    return json.dumps(
        build_network_benchmark_quality_export(observations),
        sort_keys=True, ensure_ascii=True, separators=(",", ":"),
    ) + "\n"
