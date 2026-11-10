"""Deterministic, non-executable cross-tool review of offline Nuclei/ZAP evidence."""
from __future__ import annotations

import hashlib
import json
import re

from .nuclei_offline_jsonl_import import _host
from .tier1_offline_plan import Tier1PlanError, plan_tier1


class CrossToolReviewError(ValueError):
    """Invalid, untrusted or out-of-scope offline evidence."""


def _digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _validate(workflow: dict, tool: str, schema: str, targets: tuple[str, ...],
              max_records: int) -> tuple[dict, list[dict]]:
    if not isinstance(workflow, dict) or workflow.get("authority") != "review_only_not_execution_authorization":
        raise CrossToolReviewError("Invalid workflow authority")
    report = workflow.get("report")
    if not isinstance(report, dict) or report.get("schema") != schema:
        raise CrossToolReviewError("Invalid report schema")
    if report.get("source_tool") != tool or report.get("authority") != "untrusted_offline_review":
        raise CrossToolReviewError("Invalid report source or authority")
    if report.get("finding_status") != "not_assessed":
        raise CrossToolReviewError("Unexpected finding promotion")
    digest = report.get("report_sha256")
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    if not isinstance(digest, str) or digest != _digest(body):
        raise CrossToolReviewError("Report integrity mismatch")
    artifact = report.get("artifact_sha256")
    if not isinstance(artifact, str) or re.fullmatch(r"[0-9a-f]{64}", artifact) is None:
        raise CrossToolReviewError("Invalid artifact provenance")
    entries = report.get("observations")
    if (not isinstance(entries, list) or len(entries) > max_records
            or report.get("observation_count") != len(entries)):
        raise CrossToolReviewError("Invalid observation budget or count")
    key = "template_id" if tool == "Nuclei" else "plugin_id"
    for entry in entries:
        if (not isinstance(entry, dict) or entry.get("host") not in targets
                or entry.get("classification") != "unverified_tool_observation"
                or entry.get("artifact_sha256") != artifact
                or not isinstance(entry.get(key), str) or not entry[key]
                or type(entry.get("record_index")) is not int
                or not 0 <= entry["record_index"] < max_records):
            raise CrossToolReviewError("Invalid or out-of-scope observation")
    if len({entry["record_index"] for entry in entries}) != len(entries):
        raise CrossToolReviewError("Duplicate record provenance")
    return report, entries


def correlate_nuclei_zap_offline(*, nuclei_workflow: dict, zap_workflow: dict,
                                targets: tuple[str, ...], allowed_targets: tuple[str, ...],
                                engagement_authorized: bool, capabilities: dict,
                                max_records: int = 4096) -> dict:
    """Correlate exact-host observations only; never infer vulnerability agreement."""
    plan = plan_tier1(objective="web_findings", targets=targets,
                      allowed_targets=allowed_targets, capabilities=capabilities,
                      engagement_authorized=engagement_authorized)
    if (len(plan["steps"]) != 2
            or [s["tool"] for s in plan["steps"]] != ["Nuclei", "OWASP ZAP"]
            or any(s["executable"] for s in plan["steps"])):
        raise Tier1PlanError("Unexpected executable cross-tool plan")
    if (max_records < 1 or not targets or len(set(targets)) != len(targets)
            or any(_host(host) != host for host in targets)
            or any(_host(host) != host for host in allowed_targets)):
        raise CrossToolReviewError("Invalid canonical scope or budget")
    nr, ne = _validate(nuclei_workflow, "Nuclei", "red.nuclei_offline_review.v1", targets, max_records)
    zr, ze = _validate(zap_workflow, "OWASP ZAP", "red.zap_offline_review.v1", targets, max_records)
    hosts = sorted({item["host"] for item in ne} | {item["host"] for item in ze})
    groups = [{"host": host,
               "nuclei_template_ids": sorted({e["template_id"] for e in ne if e["host"] == host}),
               "zap_plugin_ids": sorted({e["plugin_id"] for e in ze if e["host"] == host}),
               "interpretation": "co_occurrence_only_not_same_vulnerability"}
              for host in hosts]
    report = {"schema": "red.tier1_cross_tool_offline.v1",
              "authority": "untrusted_offline_review",
              "finding_status": "not_assessed",
              "source_report_sha256": {"Nuclei": nr["report_sha256"], "OWASP ZAP": zr["report_sha256"]},
              "source_artifact_sha256": {"Nuclei": nr["artifact_sha256"], "OWASP ZAP": zr["artifact_sha256"]},
              "nuclei_observation_count": len(ne), "zap_observation_count": len(ze),
              "host_groups": groups,
              "limitations": "Shared host is not matching vulnerability evidence; no exploitability, remediation, or authorization is proven."}
    report["report_sha256"] = _digest(report)
    return {"schema": "red.tier1_cross_tool_workflow.v1",
            "authority": "review_only_not_execution_authorization",
            "plan": plan, "report": report}
