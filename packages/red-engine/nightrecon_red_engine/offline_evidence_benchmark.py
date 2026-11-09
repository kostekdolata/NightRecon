"""Deterministic synthetic quality scoring for the Tier 1 offline evidence review.

Fixture expectations are independently supplied; imported observations remain
unverified and this benchmark never establishes specialist parity or authorization.
"""
from __future__ import annotations

import hashlib
import json

from .offline_tool_correlation import OfflineCorrelationError

_TOOLS = frozenset({"Amass", "ProjectDiscovery httpx", "Greenbone/OpenVAS"})


def benchmark_offline_evidence(review: dict, *, expected_pairs: tuple[tuple[str, str], ...],
                               allowed_hosts: tuple[str, ...], max_pairs: int = 10000) -> dict:
    """Score observed host/tool pairs against explicit synthetic fixture truth."""
    if type(max_pairs) is not int or not 0 < max_pairs <= 10000:
        raise OfflineCorrelationError("Invalid benchmark budget")
    if (not isinstance(allowed_hosts, tuple) or not allowed_hosts
            or len(allowed_hosts) > 256
            or any(not isinstance(host, str) or not host or len(host) > 253
                   for host in allowed_hosts)
            or len(set(allowed_hosts)) != len(allowed_hosts)):
        raise OfflineCorrelationError("Exact benchmark scope required")
    scope = set(allowed_hosts)
    if not isinstance(expected_pairs, tuple) or len(expected_pairs) > max_pairs:
        raise OfflineCorrelationError("Invalid expected pairs")
    expected = set()
    for pair in expected_pairs:
        if (not isinstance(pair, tuple) or len(pair) != 2
                or not isinstance(pair[0], str) or pair[0] not in scope
                or not isinstance(pair[1], str) or pair[1] not in _TOOLS
                or pair in expected):
            raise OfflineCorrelationError("Invalid, duplicate or out-of-scope expectation")
        expected.add(pair)
    if (not isinstance(review, dict)
            or review.get("schema") != "red.tier1_offline_evidence_review.v1"
            or review.get("authority") != "untrusted_offline_review_not_execution_authorization"):
        raise OfflineCorrelationError("Invalid offline review")
    report = review.get("report")
    if (not isinstance(report, dict)
            or report.get("schema") != "red.offline_correlation_review.v1"
            or report.get("authority") != "untrusted_offline_review"
            or not isinstance(report.get("hosts"), list)
            or type(report.get("host_count")) is not int
            or report["host_count"] != len(report["hosts"])
            or type(report.get("observation_count")) is not int):
        raise OfflineCorrelationError("Invalid review report")
    observed = set()
    seen_hosts = set()
    total = 0
    for host_entry in report["hosts"]:
        if not isinstance(host_entry, dict):
            raise OfflineCorrelationError("Invalid host evidence")
        host = host_entry.get("host")
        if not isinstance(host, str) or host not in scope or host in seen_hosts:
            raise OfflineCorrelationError("Out-of-scope or duplicate host")
        seen_hosts.add(host)
        entries = host_entry.get("evidence")
        if (host_entry.get("finding_status") != "not_assessed"
                or not isinstance(entries, list)
                or type(host_entry.get("observation_count")) is not int
                or host_entry["observation_count"] != len(entries)):
            raise OfflineCorrelationError("Unsupported evidence classification")
        total += len(entries)
        if total > max_pairs:
            raise OfflineCorrelationError("Evidence budget exceeded")
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("tool") not in _TOOLS:
                raise OfflineCorrelationError("Unknown tool")
            if (not isinstance(entry.get("artifact_sha256"), str)
                    or len(entry["artifact_sha256"]) != 64
                    or any(ch not in "0123456789abcdef" for ch in entry["artifact_sha256"])
                    or type(entry.get("record_index")) is not int
                    or entry["record_index"] < 0):
                raise OfflineCorrelationError("Invalid evidence provenance")
            observed.add((host, entry["tool"]))
        if host_entry.get("source_tools") != sorted({tool for h, tool in observed if h == host}):
            raise OfflineCorrelationError("Source tools mismatch")
    if report["observation_count"] != total:
        raise OfflineCorrelationError("Observation count mismatch")
    tp, fp, fn = len(observed & expected), len(observed - expected), len(expected - observed)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    result = {
        "schema": "red.offline_evidence_fixture_benchmark.v1",
        "fixture_type": "synthetic_only",
        "true_positive_pairs": tp,
        "false_positive_pairs": fp,
        "false_negative_pairs": fn,
        "precision": precision,
        "recall": recall,
        "expected_pairs": len(expected),
        "observed_pairs": len(observed),
        "observation_count": total,
        "limitations": "Host/tool presence only; not finding accuracy, vulnerability validation or specialist parity.",
    }
    payload = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    result["fingerprint_sha256"] = hashlib.sha256(payload).hexdigest()
    return result
