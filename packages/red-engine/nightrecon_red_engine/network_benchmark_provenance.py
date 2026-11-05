"""Metadata-only provenance for independent Red Night network benchmark runs.

The supplied metadata is operator assertion, never engagement authorization,
proof of ground truth, or independent specialist-tool parity. This module
cannot run a scan, load credentials, or access a network.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import ipaddress
import hashlib
import json
import re

from .network_benchmark import NetworkBenchmarkResult

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-fA-F]{64}$")
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+:/()-]{0,95}$")


def _sha(value: str, field: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"{field} must be a SHA-256 hex digest")
    return value.lower()


@dataclass(frozen=True)
class NetworkBenchmarkProvenance:
    lab_run_id: str
    authorization_reference: str
    environment_sha256: str
    ground_truth_sha256: str
    configuration_sha256: str
    benchmark_sha256: str
    observed_at: str
    comparator_name: str | None
    comparator_version: str | None
    evidence_fingerprint: str
    scope_violation_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": 1,
            "type": "network-benchmark-provenance",
            "lab_run_id": self.lab_run_id,
            "authorization_reference": self.authorization_reference,
            "environment_sha256": self.environment_sha256,
            "ground_truth_sha256": self.ground_truth_sha256,
            "configuration_sha256": self.configuration_sha256,
            "benchmark_sha256": self.benchmark_sha256,
            "observed_at": self.observed_at,
            "comparator_name": self.comparator_name,
            "comparator_version": self.comparator_version,
            "evidence_fingerprint": self.evidence_fingerprint,
            "scope_violation_count": self.scope_violation_count,
            "authorization_effect": "none",
            "interpretation": (
                "Operator-provided metadata identifies a fixture or authorized lab comparison. "
                "It is not independent proof of authorization, target scope, ground truth, "
                "tool execution, external benchmark parity, or superiority."
            ),
        }


def record_network_benchmark_provenance(
    result: NetworkBenchmarkResult,
    *,
    lab_run_id: str,
    authorization_reference: str,
    environment_sha256: str,
    ground_truth_sha256: str,
    configuration_sha256: str,
    observed_at: str,
    comparator_name: str | None = None,
    comparator_version: str | None = None,
) -> NetworkBenchmarkProvenance:
    """Bind an existing benchmark result to explicit, non-secret lab metadata.

    Stable fingerprint excludes wall-clock time and measured runtime, allowing
    a repeat with identical observations and lab setup to compare exactly.
    The operator's authorization reference cannot grant or extend permissions.
    """
    if not isinstance(result, NetworkBenchmarkResult):
        raise TypeError("Expected an existing network benchmark result")
    if not all(isinstance(x, str) and _ID.fullmatch(x)
               for x in (lab_run_id, authorization_reference)):
        raise ValueError("Invalid lab run or authorization reference")
    if not isinstance(observed_at, str):
        raise ValueError("observed_at must be a timezone-aware ISO timestamp")
    try:
        stamp = datetime.fromisoformat(observed_at)
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError("naive timestamp")
    except (ValueError, OverflowError) as exc:
        raise ValueError("observed_at must be a timezone-aware ISO timestamp") from exc
    if (comparator_name is None) != (comparator_version is None):
        raise ValueError("Comparator name and version must be supplied together")
    if comparator_name is not None and not all(
        isinstance(x, str) and _LABEL.fullmatch(x)
        for x in (comparator_name, comparator_version)
    ):
        raise ValueError("Comparator metadata must be short, non-secret labels")
    violations = result.scope_violations
    if not isinstance(violations, tuple) or len(violations) != len(set(
        item for item in violations if isinstance(item, str)
    )):
        raise ValueError("Scope violations must be unique evidence labels")
    for item in violations:
        if not isinstance(item, str):
            raise ValueError("Scope violations must be valid evidence labels")
        kind, separator, address = item.partition(":")
        if not separator or kind not in {"tcp", "udp", "service", "os"}:
            raise ValueError("Scope violations must be valid evidence labels")
        try:
            canonical_address = str(ipaddress.ip_address(address))
        except ValueError as exc:
            raise ValueError("Scope violations must be valid evidence labels") from exc
        if address != canonical_address:
            raise ValueError("Scope violations must be canonical evidence labels")
    environment = _sha(environment_sha256, "environment_sha256")
    truth = _sha(ground_truth_sha256, "ground_truth_sha256")
    configuration = _sha(configuration_sha256, "configuration_sha256")
    benchmark = _sha(result.comparison_sha256, "benchmark_sha256")
    if type(result.scope_violation_count) is not int or result.scope_violation_count < 0:
        raise ValueError("Invalid scope violation count")
    if (not isinstance(result.scope_violations, tuple)
            or len(result.scope_violations) != result.scope_violation_count):
        raise ValueError("Scope violation count does not match evidence")
    fingerprint_input = {
        "schema": 1,
        "authorization_reference": authorization_reference,
        "environment_sha256": environment,
        "ground_truth_sha256": truth,
        "configuration_sha256": configuration,
        "benchmark_sha256": benchmark,
        "comparator_name": comparator_name,
        "comparator_version": comparator_version,
        "scope_violation_count": result.scope_violation_count,
    }
    fingerprint = hashlib.sha256(json.dumps(
        fingerprint_input, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    return NetworkBenchmarkProvenance(
        lab_run_id=lab_run_id,
        authorization_reference=authorization_reference,
        environment_sha256=environment,
        ground_truth_sha256=truth,
        configuration_sha256=configuration,
        benchmark_sha256=benchmark,
        observed_at=stamp.isoformat(),
        comparator_name=comparator_name,
        comparator_version=comparator_version,
        evidence_fingerprint=fingerprint,
        scope_violation_count=result.scope_violation_count,
    )
