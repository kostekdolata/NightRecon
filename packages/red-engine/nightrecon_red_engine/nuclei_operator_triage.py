"""Offline operator triage of imported Nuclei observations; no execution or finding promotion."""
from __future__ import annotations

import hashlib
import json
import re


class NucleiTriageError(ValueError):
    """Invalid or untrusted operator triage input."""


def build_nuclei_triage(imported: dict, *, decisions: dict | None = None,
                       max_observations: int = 512) -> dict:
    """Deduplicate imported alerts and apply explicit review dispositions.

    A reviewed alert remains an unverified external observation. The operator
    cannot use this interface to assert exploitation or remediation.
    """
    if (type(imported) is not dict
            or imported.get("schema") != "red.nuclei_offline_evidence.v1"
            or imported.get("external_execution") is not False
            or imported.get("integration_verified") is not False
            or imported.get("confirmed_findings") != 0
            or type(imported.get("engagement_id")) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", imported["engagement_id"]) is None
            or type(imported.get("source_sha256")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", imported["source_sha256"]) is None
            or type(imported.get("observations")) is not list
            or type(max_observations) is not int or not 0 < max_observations <= 4096
            or not 0 < len(imported["observations"]) <= max_observations
            or type(imported.get("observation_count")) is not int
            or imported["observation_count"] != len(imported["observations"])
            or type(decisions) not in (dict, type(None))):
        raise NucleiTriageError("Invalid imported evidence or review budget")
    grouped = {}
    for row in imported["observations"]:
        if (type(row) is not dict
                or set(row) != {"template_id", "host", "severity_claimed", "classification"}
                or type(row["template_id"]) is not str
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", row["template_id"]) is None
                or type(row["host"]) is not str
                or not re.fullmatch(r"[a-z0-9.:-]{1,253}", row["host"])
                or row["severity_claimed"] not in ("info", "low", "medium", "high", "critical")
                or row["classification"] != "unverified_external_observation"):
            raise NucleiTriageError("Invalid untrusted observation")
        key = (row["host"], row["template_id"], row["severity_claimed"])
        grouped[key] = grouped.get(key, 0) + 1
    items = []
    for (host, template, severity), count in sorted(grouped.items()):
        key = hashlib.sha256(json.dumps([host, template, severity], separators=(",", ":")).encode()).hexdigest()
        items.append({"observation_id": key, "host": host, "template_id": template,
                      "severity_claimed": severity, "occurrences": count,
                      "classification": "unverified_external_observation"})
    decisions = {} if decisions is None else decisions
    if (any(type(k) is not str or type(v) is not str
            or v not in ("needs_review", "dismissed", "follow_up_required")
            for k, v in decisions.items())
            or set(decisions) - {item["observation_id"] for item in items}):
        raise NucleiTriageError("Unknown observation or invalid disposition")
    for item in items:
        item["operator_disposition"] = decisions.get(item["observation_id"], "needs_review")
    report = {"schema": "red.nuclei_operator_triage.v1",
              "engagement_id": imported["engagement_id"],
              "source_sha256": imported["source_sha256"],
              "observation_count": len(imported["observations"]),
              "unique_observation_count": len(items), "observations": items,
              "confirmed_findings": 0, "external_execution": False,
              "limitations": "Review dispositions do not verify exploitation, severity, or remediation."}
    report["report_sha256"] = hashlib.sha256(
        json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return report
