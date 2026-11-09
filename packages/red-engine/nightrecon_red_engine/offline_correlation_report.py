"""Deterministic operator review from validated offline host correlation.

No execution, authorization, exploitability assessment or filesystem access.
"""
from __future__ import annotations

import hashlib
import json
import re

from .offline_tool_correlation import OfflineCorrelationError

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TOOLS = {"Amass", "ProjectDiscovery httpx", "Greenbone/OpenVAS"}


def render_offline_correlation_report(correlation: dict, *, max_hosts: int = 1000,
                                      max_observations: int = 10000) -> dict:
    """Produce bounded JSON-ready operator evidence without promoting tool claims."""
    if type(max_hosts) is not int or not 0 < max_hosts <= 10000:
        raise OfflineCorrelationError("Invalid host budget")
    if type(max_observations) is not int or not 0 < max_observations <= 100000:
        raise OfflineCorrelationError("Invalid observation budget")
    if not isinstance(correlation, dict) or correlation.get("authority") != "untrusted_offline_correlation":
        raise OfflineCorrelationError("Untrusted correlation envelope")
    hosts = correlation.get("hosts")
    if not isinstance(hosts, list) or len(hosts) > max_hosts:
        raise OfflineCorrelationError("Host budget exceeded")
    if type(correlation.get("host_count")) is not int or correlation["host_count"] != len(hosts):
        raise OfflineCorrelationError("Host count mismatch")
    output = []
    seen = set()
    total = 0
    for entry in hosts:
        if not isinstance(entry, dict):
            raise OfflineCorrelationError("Malformed host")
        host = entry.get("host")
        if not isinstance(host, str) or not 0 < len(host) <= 253 or host in seen:
            raise OfflineCorrelationError("Invalid or duplicate host")
        seen.add(host)
        observations = entry.get("observations")
        if entry.get("verdict") != "not_assessed" or not isinstance(observations, list):
            raise OfflineCorrelationError("Unsupported verdict or observations")
        total += len(observations)
        if total > max_observations:
            raise OfflineCorrelationError("Observation budget exceeded")
        refs = []
        for item in observations:
            if not isinstance(item, dict) or item.get("classification") != "unverified_tool_observation":
                raise OfflineCorrelationError("Unsupported observation")
            tool, sha, source, index = (item.get("source_tool"), item.get("sha256"),
                                        item.get("source_name"), item.get("record_index"))
            if tool not in _TOOLS or not isinstance(sha, str) or not _SHA.fullmatch(sha):
                raise OfflineCorrelationError("Invalid provenance")
            if not isinstance(source, str) or not 0 < len(source) <= 256:
                raise OfflineCorrelationError("Invalid source name")
            if type(index) is not int or index < 0:
                raise OfflineCorrelationError("Invalid record index")
            refs.append({"tool": tool, "artifact_sha256": sha, "record_index": index})
        if entry.get("source_tools") != sorted({ref["tool"] for ref in refs}):
            raise OfflineCorrelationError("Source tool mismatch")
        output.append({"host": host, "observation_count": len(refs),
                       "source_tools": entry["source_tools"], "evidence": refs,
                       "finding_status": "not_assessed"})
    if type(correlation.get("observation_count")) is not int or correlation["observation_count"] != total:
        raise OfflineCorrelationError("Observation count mismatch")
    output.sort(key=lambda item: item["host"])
    report = {"schema": "red.offline_correlation_review.v1",
              "authority": "untrusted_offline_review", "host_count": len(output),
              "observation_count": total, "hosts": output,
              "limitations": ["Offline imports are unverified observations.",
                              "No authorization, vulnerability, exploitability or remediation claim is established."]}
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    report["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    return report
