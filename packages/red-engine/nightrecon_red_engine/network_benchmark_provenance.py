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
import hmac
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
            "schema": 2,
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
    if type(result.scope_violation_count) is not int or result.scope_violation_count < 0:
        raise ValueError("Invalid scope violation count")
    if (not isinstance(result.scope_violations, tuple)
            or len(result.scope_violations) != result.scope_violation_count):
        raise ValueError("Scope violation count does not match evidence")
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
    fingerprint_input = {
        "schema": 2,
        "authorization_reference": authorization_reference,
        "environment_sha256": environment,
        "ground_truth_sha256": truth,
        "configuration_sha256": configuration,
        "benchmark_sha256": benchmark,
        "comparator_name": comparator_name,
        "comparator_version": comparator_version,
        "scope_violation_count": result.scope_violation_count,
        "scope_violations": list(violations),
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


def verify_network_benchmark_provenance(
    provenance: NetworkBenchmarkProvenance,
    result: NetworkBenchmarkResult,
) -> bool:
    """Recompute a provenance record against the supplied benchmark observations.

    This is an offline consistency check, not cryptographic authentication,
    independent ground-truth verification, or an authorization decision.
    """
    if not isinstance(provenance, NetworkBenchmarkProvenance):
        raise TypeError("Expected a network benchmark provenance record")
    if not isinstance(result, NetworkBenchmarkResult):
        raise TypeError("Expected an existing network benchmark result")
    try:
        expected = record_network_benchmark_provenance(
            result,
            lab_run_id=provenance.lab_run_id,
            authorization_reference=provenance.authorization_reference,
            environment_sha256=provenance.environment_sha256,
            ground_truth_sha256=provenance.ground_truth_sha256,
            configuration_sha256=provenance.configuration_sha256,
            observed_at=provenance.observed_at,
            comparator_name=provenance.comparator_name,
            comparator_version=provenance.comparator_version,
        )
    except (TypeError, ValueError):
        return False
    return provenance == expected


def report_network_benchmark_provenance_status(
    provenance: NetworkBenchmarkProvenance,
    result: NetworkBenchmarkResult,
) -> dict[str, object]:
    """Produce a safe, non-authoritative status for offline report consumers.

    Consistency never implies authorization or independent evidence validation.
    A scope violation always prevents a clean status even when provenance matches.
    """
    consistent = verify_network_benchmark_provenance(provenance, result)
    if not consistent:
        status = "inconsistent"
    elif provenance.scope_violation_count:
        status = "scope_violations_observed"
    else:
        status = "consistent_unverified"
    return {
        "schema": 1,
        "type": "network-benchmark-provenance-status",
        "status": status,
        "consistent": consistent,
        "evidence_fingerprint": (
            provenance.evidence_fingerprint if consistent else None
        ),
        "scope_violation_count": (
            provenance.scope_violation_count if consistent else None
        ),
        "authorization_effect": "none",
        "interpretation": (
            "Offline consistency is not independent proof of authorization, "
            "target scope, ground truth, specialist-tool parity, or safe execution."
        ),
    }


def report_network_benchmark_evidence_summary(
    provenance: NetworkBenchmarkProvenance,
    result: NetworkBenchmarkResult,
) -> dict[str, object]:
    """Build a metadata-only export for a downstream reporting integration.

    Fail closed: inconsistent provenance cannot be linked to benchmark metrics.
    This export is not an authorization, exploitability, or parity verdict.
    """
    status = report_network_benchmark_provenance_status(provenance, result)
    if not status["consistent"]:
        metrics = None
    else:
        metrics = {
            "expected_tcp_open": result.expected_tcp_open,
            "matched_tcp_open": result.matched_tcp_open,
            "missed_tcp_open": result.missed_tcp_open,
            "invented_tcp_open": result.invented_tcp_open,
            "expected_udp_open": result.expected_udp_open,
            "matched_udp_open": result.matched_udp_open,
            "missed_udp_open": result.missed_udp_open,
            "invented_udp_open": result.invented_udp_open,
            "ambiguous_udp_expected_open": result.ambiguous_udp_expected_open,
            "expected_services": result.expected_services,
            "matched_services": result.matched_services,
            "missed_services": result.missed_services,
            "invented_services": result.invented_services,
            "expected_operating_systems": result.expected_operating_systems,
            "matched_operating_systems": result.matched_operating_systems,
            "missed_operating_systems": result.missed_operating_systems,
            "conflicting_operating_systems": result.conflicting_operating_systems,
            "scope_violation_count": result.scope_violation_count,
        }
    return {
        "schema": 1,
        "type": "network-benchmark-evidence-summary",
        "provenance_status": status,
        "metrics": metrics,
        "authorization_effect": "none",
        "interpretation": (
            "Counts are descriptive observations from an operator-supplied lab "
            "comparison, not independent verification, specialist-tool parity, "
            "exploitability, or permission to scan."
        ),
    }


def export_network_benchmark_evidence_json(
    provenance: NetworkBenchmarkProvenance,
    result: NetworkBenchmarkResult,
) -> str:
    """Serialize the offline evidence summary deterministically for report ingestion.

    This is not a signed attestation. Inconsistent evidence remains redacted by
    the underlying summary and non-finite numbers cannot enter JSON output.
    """
    summary = report_network_benchmark_evidence_summary(provenance, result)
    return json.dumps(
        summary, sort_keys=True, separators=(",", ":"), allow_nan=False,
    )


def fingerprint_network_benchmark_evidence_export(
    provenance: NetworkBenchmarkProvenance,
    result: NetworkBenchmarkResult,
) -> str:
    """SHA-256 digest of the exact canonical JSON report export bytes.

    Useful for detecting accidental report changes across offline integrations.
    This is not a signature, trusted attestation, or authorization proof. Any
    inconsistent evidence remains redacted before its export is hashed.
    """
    payload = export_network_benchmark_evidence_json(provenance, result)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_network_benchmark_evidence_export_digest(
    payload: str,
    expected_sha256: str,
) -> bool:
    """Check the exact canonical offline report JSON against an expected digest.

    The digest detects accidental changes only: it is not a signature,
    provenance authentication, independent validation, or scan authorization.
    Reject noncanonical, malformed, and oversized exports fail-closed.
    """
    if not isinstance(payload, str):
        raise TypeError("Expected a JSON export string")
    if not isinstance(expected_sha256, str):
        return False
    if not _SHA.fullmatch(expected_sha256):
        return False
    try:
        encoded = payload.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if len(encoded) > 1_048_576:
        return False
    try:
        parsed = json.loads(payload)
        if not isinstance(parsed, dict):
            return False
        if parsed.get("type") != "network-benchmark-evidence-summary":
            return False
        canonical = json.dumps(
            parsed, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError, RecursionError):
        return False
    if canonical != payload:
        return False
    actual_sha256 = hashlib.sha256(encoded).hexdigest()
    return hmac.compare_digest(actual_sha256, expected_sha256.lower())


def inspect_network_benchmark_evidence_export(
    payload: str,
    expected_sha256: str,
) -> dict[str, object]:
    """Fail-closed offline intake for a canonical report export.

    Checks a caller-supplied checksum and the report's safety-critical shape.
    This cannot establish source authenticity, authorization, or lab truth.
    """
    rejected = {
        "schema": 1,
        "type": "network-benchmark-evidence-intake",
        "accepted": False,
        "status": "rejected",
        "metrics": None,
        "authorization_effect": "none",
    }
    if not verify_network_benchmark_evidence_export_digest(
        payload, expected_sha256,
    ):
        return rejected
    try:
        report = json.loads(payload)
        status = report["provenance_status"]
        metrics = report["metrics"]
        if (type(report) is not dict
                or set(report) != {
                    "schema", "type", "provenance_status", "metrics",
                    "authorization_effect", "interpretation",
                }
                or type(report.get("schema")) is not int
                or report["schema"] != 1
                or report.get("type") != "network-benchmark-evidence-summary"
                or report.get("authorization_effect") != "none"
                or not isinstance(report.get("interpretation"), str)
                or type(status) is not dict
                or set(status) != {
                    "schema", "type", "status", "consistent",
                    "evidence_fingerprint", "scope_violation_count",
                    "authorization_effect", "interpretation",
                }
                or type(status.get("schema")) is not int
                or status["schema"] != 1
                or status.get("type") != "network-benchmark-provenance-status"
                or status.get("authorization_effect") != "none"
                or not isinstance(status.get("interpretation"), str)):
            return rejected
        label = status.get("status")
        consistent = status.get("consistent")
        fingerprint = status.get("evidence_fingerprint")
        count = status.get("scope_violation_count")
        if label == "inconsistent":
            if consistent is not False or fingerprint is not None or count is not None or metrics is not None:
                return rejected
        elif label in {"consistent_unverified", "scope_violations_observed"}:
            if (consistent is not True
                    or not isinstance(fingerprint, str)
                    or not _SHA.fullmatch(fingerprint)
                    or type(count) is not int
                    or count < 0
                    or (count == 0) != (label == "consistent_unverified")
                    or not isinstance(metrics, dict)
                    or type(metrics.get("scope_violation_count")) is not int
                    or metrics["scope_violation_count"] != count
                    or set(metrics) != {"expected_tcp_open", "matched_tcp_open", "missed_tcp_open", "invented_tcp_open", "expected_udp_open", "matched_udp_open", "missed_udp_open", "invented_udp_open", "ambiguous_udp_expected_open", "expected_services", "matched_services", "missed_services", "invented_services", "expected_operating_systems", "matched_operating_systems", "missed_operating_systems", "conflicting_operating_systems", "scope_violation_count"}
                    or any(type(value) is not int or value < 0
                           for value in metrics.values())):
                return rejected
        else:
            return rejected
    except (KeyError, TypeError, ValueError):
        return rejected
    return {
        "schema": 1,
        "type": "network-benchmark-evidence-intake",
        "accepted": True,
        "status": label,
        "metrics": metrics,
        "authorization_effect": "none",
    }


def inspect_network_benchmark_evidence_batch(
    exports: list[tuple[str, str]],
) -> dict[str, object]:
    """Bounded, offline intake of independent report exports in input order.

    Every entry is checked by the existing fail-closed single-export intake.
    A rejected entry cannot expose metrics, and one accepted entry never
    authorizes another. This does not execute scans or grant permissions.
    """
    if type(exports) is not list or len(exports) > 32:
        raise ValueError("Expected a list of at most 32 evidence exports")
    entries = []
    for item in exports:
        if type(item) is not tuple or len(item) != 2:
            raise ValueError("Each export must be a (payload, sha256) tuple")
        payload, digest = item
        if not isinstance(payload, str) or not isinstance(digest, str):
            raise ValueError("Each export requires a JSON string and SHA-256 string")
        entries.append(inspect_network_benchmark_evidence_export(payload, digest))
    accepted_count = sum(entry["accepted"] for entry in entries)
    status_counts = {
        "consistent_unverified": 0,
        "scope_violations_observed": 0,
        "inconsistent": 0,
        "rejected": 0,
    }
    for entry in entries:
        status_counts[entry["status"]] += 1
    return {
        "schema": 1,
        "type": "network-benchmark-evidence-batch-intake",
        "accepted": bool(entries) and accepted_count == len(entries),
        "accepted_count": accepted_count,
        "rejected_count": len(entries) - accepted_count,
        "status_counts": status_counts,
        "evidence_review_entry_indices": [
            index for index, entry in enumerate(entries)
            if entry["status"] != "consistent_unverified"
        ],
        "evidence_review_count": (
            status_counts["scope_violations_observed"]
            + status_counts["inconsistent"]
            + status_counts["rejected"]
        ),
        "requires_evidence_review": bool(entries) and (
            status_counts["scope_violations_observed"] > 0
            or status_counts["inconsistent"] > 0
            or status_counts["rejected"] > 0
        ),
        "evidence_review_reasons": [
            label for label in (
                "scope_violations_observed", "inconsistent", "rejected"
            ) if status_counts[label] > 0
        ],
        "entries": entries,
        "authorization_effect": "none",
    }
