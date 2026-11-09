"""Offline before/after evidence comparison, not remediation verification.

Only independently scoped, previously imported unverified host/tool observations.
No execution, network access, approval or authority is derived from changes.
"""
from __future__ import annotations

import hashlib
import json

from .offline_tool_correlation import OfflineCorrelationError

_TOOLS = frozenset({"Amass", "ProjectDiscovery httpx", "Greenbone/OpenVAS"})


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _extract(review, scope, max_observations):
    if (not isinstance(review, dict)
            or review.get("schema") != "red.tier1_offline_evidence_review.v1"
            or review.get("authority") != "untrusted_offline_review_not_execution_authorization"):
        raise OfflineCorrelationError("Invalid offline review")
    report = review.get("report")
    if (not isinstance(report, dict)
            or report.get("schema") != "red.offline_correlation_review.v1"
            or report.get("authority") != "untrusted_offline_review"):
        raise OfflineCorrelationError("Invalid report")
    digest = report.get("report_sha256")
    unsigned = {key: value for key, value in report.items() if key != "report_sha256"}
    if (not isinstance(digest, str) or len(digest) != 64
            or digest != hashlib.sha256(_canonical(unsigned)).hexdigest()):
        raise OfflineCorrelationError("Report integrity mismatch")
    hosts = report.get("hosts")
    if (not isinstance(hosts, list) or len(hosts) > 1000
            or type(report.get("host_count")) is not int
            or report["host_count"] != len(hosts)
            or type(report.get("observation_count")) is not int):
        raise OfflineCorrelationError("Invalid report counts")
    pairs = set()
    seen = set()
    total = 0
    for host_entry in hosts:
        if not isinstance(host_entry, dict):
            raise OfflineCorrelationError("Invalid host")
        host = host_entry.get("host")
        if not isinstance(host, str) or host not in scope or host in seen:
            raise OfflineCorrelationError("Out-of-scope or duplicate host")
        seen.add(host)
        evidence = host_entry.get("evidence")
        if (host_entry.get("finding_status") != "not_assessed"
                or not isinstance(evidence, list)
                or type(host_entry.get("observation_count")) is not int
                or host_entry["observation_count"] != len(evidence)):
            raise OfflineCorrelationError("Invalid observation status")
        total += len(evidence)
        if total > max_observations:
            raise OfflineCorrelationError("Observation budget exceeded")
        tools = set()
        for item in evidence:
            if not isinstance(item, dict) or item.get("tool") not in _TOOLS:
                raise OfflineCorrelationError("Unsupported tool")
            sha, index = item.get("artifact_sha256"), item.get("record_index")
            if (not isinstance(sha, str) or len(sha) != 64
                    or any(c not in "0123456789abcdef" for c in sha)
                    or type(index) is not int or index < 0):
                raise OfflineCorrelationError("Invalid provenance")
            tools.add(item["tool"])
            pairs.add((host, item["tool"]))
        if host_entry.get("source_tools") != sorted(tools):
            raise OfflineCorrelationError("Source mismatch")
    if total != report["observation_count"]:
        raise OfflineCorrelationError("Observation count mismatch")
    return pairs, digest


def compare_offline_retests(before: dict, after: dict, *,
                            allowed_hosts: tuple[str, ...],
                            max_observations: int = 10000) -> dict:
    """Compare observed host/tool presence, never assert remediation or exploitability."""
    if (not isinstance(allowed_hosts, tuple) or not allowed_hosts
            or len(allowed_hosts) > 256
            or any(not isinstance(host, str) or not 0 < len(host) <= 253
                   for host in allowed_hosts)
            or len(set(allowed_hosts)) != len(allowed_hosts)):
        raise OfflineCorrelationError("Explicit exact scope required")
    if type(max_observations) is not int or not 0 < max_observations <= 10000:
        raise OfflineCorrelationError("Invalid comparison budget")
    scope = set(allowed_hosts)
    old, old_digest = _extract(before, scope, max_observations)
    new, new_digest = _extract(after, scope, max_observations)
    def rows(pairs):
        return [{"host": host, "source_tool": tool} for host, tool in sorted(pairs)]
    result = {
        "schema": "red.offline_retest_comparison.v1",
        "authority": "untrusted_offline_comparison",
        "before_report_sha256": old_digest,
        "after_report_sha256": new_digest,
        "persisting": rows(old & new),
        "no_longer_observed": rows(old - new),
        "newly_observed": rows(new - old),
        "limitations": "Changes in unverified host/tool observations do not prove remediation, exploitability or authorization.",
    }
    result["comparison_sha256"] = hashlib.sha256(_canonical(result)).hexdigest()
    return result
