"""Engagement-bound OWASP ZAP offline alert review; no tool execution."""
from __future__ import annotations

import hashlib
import json

from .nuclei_offline_jsonl_import import _host
from .tier1_offline_plan import Tier1PlanError, plan_tier1
from .zap_offline_json_import import import_zap_json


def review_zap_offline_json(*, payload: bytes, targets: tuple[str, ...],
                            allowed_targets: tuple[str, ...], capabilities: dict,
                            engagement_authorized: bool,
                            source_name: str = "zap.json",
                            max_bytes: int = 2_000_000,
                            max_records: int = 4096) -> dict:
    """Preserve untrusted ZAP observations under an independently guarded plan."""
    plan = plan_tier1(objective="web_findings", targets=targets,
                      allowed_targets=allowed_targets, capabilities=capabilities,
                      engagement_authorized=engagement_authorized)
    steps = plan["steps"]
    if (len(steps) != 2 or [step["tool"] for step in steps] !=
            ["Nuclei", "OWASP ZAP"] or any(step["executable"] for step in steps)):
        raise Tier1PlanError("Unexpected non-executable web finding plan")
    if (any(_host(host) != host for host in targets)
            or any(_host(host) != host for host in allowed_targets)):
        raise Tier1PlanError("Noncanonical exact host scope")
    imported = import_zap_json(payload, allowed_hosts=targets,
                               source_name=source_name, max_bytes=max_bytes,
                               max_records=max_records)
    entries = sorted((
        {"host": item["host"], "plugin_id": item["plugin_id"],
         "reported_riskcode": item["reported_riskcode"],
         "classification": "unverified_tool_observation",
         "artifact_sha256": imported["sha256"],
         "record_index": item["record_index"]}
        for item in imported["observations"]
    ), key=lambda item: (item["host"], item["plugin_id"], item["record_index"]))
    report = {
        "schema": "red.zap_offline_review.v1",
        "authority": "untrusted_offline_review",
        "source_tool": "OWASP ZAP",
        "artifact_sha256": imported["sha256"],
        "observation_count": len(entries),
        "observations": entries,
        "finding_status": "not_assessed",
        "limitations": "ZAP alerts and risk codes are unverified; no vulnerability, exploitability, authorization or remediation is proven.",
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    report["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    return {"schema": "red.zap_offline_workflow.v1",
            "authority": "review_only_not_execution_authorization",
            "plan": plan, "report": report}
