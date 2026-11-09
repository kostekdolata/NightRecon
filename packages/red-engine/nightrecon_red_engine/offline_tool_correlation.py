"""Correlate previously validated offline tool imports without granting authority.

No tool execution, network access, filesystem access or engagement mutation.
"""
from __future__ import annotations

import re


class OfflineCorrelationError(ValueError):
    """Invalid, untrusted, excessive or out-of-scope imported evidence."""


_TOOLS = {"Amass", "ProjectDiscovery httpx", "Greenbone/OpenVAS"}
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def correlate_offline_hosts(imports: tuple[dict, ...], *, allowed_hosts: tuple[str, ...],
                            max_imports: int = 32, max_observations: int = 10_000) -> dict:
    """Group exact-host observations with per-artifact provenance and no verdict promotion.

    Importers must already have validated raw input. This boundary rechecks their
    untrusted envelopes and each host against an independent exact allowlist.
    """
    if not isinstance(imports, tuple) or not 0 < len(imports) <= max_imports or max_imports <= 0:
        raise OfflineCorrelationError("Invalid import budget")
    if not isinstance(allowed_hosts, tuple) or not allowed_hosts or any(
        not isinstance(h, str) or not h or len(h) > 253 for h in allowed_hosts
    ):
        raise OfflineCorrelationError("Explicit exact host scope required")
    if type(max_observations) is not int or max_observations <= 0:
        raise OfflineCorrelationError("Invalid observation budget")
    scope = set(allowed_hosts)
    grouped = {}
    count = 0
    for document in imports:
        if not isinstance(document, dict) or document.get("source_tool") not in _TOOLS:
            raise OfflineCorrelationError("Unsupported import")
        tool = document["source_tool"]
        items = document.get("observations")
        if (document.get("authority") != "untrusted_offline_import"
                or not isinstance(items, list)
                or type(document.get("record_count")) is not int
                or document["record_count"] != len(items)
                or not isinstance(document.get("sha256"), str)
                or not _SHA.fullmatch(document["sha256"])
                or not isinstance(document.get("source_name"), str)
                or not 0 < len(document["source_name"]) <= 256):
            raise OfflineCorrelationError("Invalid import provenance")
        count += len(items)
        if count > max_observations:
            raise OfflineCorrelationError("Observation budget exceeded")
        for index, item in enumerate(items):
            if not isinstance(item, dict) or item.get("classification") != "unverified_tool_observation":
                raise OfflineCorrelationError("Unsupported observation classification")
            if tool == "Amass":
                host = item.get("name")
            else:
                host = item.get("host")
            if not isinstance(host, str) or host not in scope:
                raise OfflineCorrelationError("Observation outside exact host scope")
            # Do not copy untrusted descriptions, URLs or claims into the summary.
            grouped.setdefault(host, []).append({
                "source_tool": tool,
                "source_name": document["source_name"],
                "sha256": document["sha256"],
                "record_index": index,
                "classification": "unverified_tool_observation",
            })
    return {
        "authority": "untrusted_offline_correlation",
        "host_count": len(grouped),
        "observation_count": count,
        "hosts": [
            {"host": host, "observations": grouped[host],
             "source_tools": sorted({entry["source_tool"] for entry in grouped[host]}),
             "verdict": "not_assessed"}
            for host in sorted(grouped)
        ],
        "limitations": "Imported observations do not prove vulnerability, exploitability or authorization.",
    }
