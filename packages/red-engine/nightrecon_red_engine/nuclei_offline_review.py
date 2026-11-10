"""Engagement-bound, non-executable Nuclei evidence review.

Imported template matches are observations, never confirmed vulnerabilities.
"""
from __future__ import annotations

import hashlib
import json

from .nuclei_offline_jsonl_import import import_nuclei_jsonl
from .tier1_offline_plan import plan_tier1, Tier1PlanError


def review_nuclei_offline_jsonl(*, payload: bytes, targets: tuple[str, ...],
                                allowed_targets: tuple[str, ...], capabilities: dict,
                                engagement_authorized: bool,
                                source_name: str = "nuclei.jsonl",
                                max_bytes: int = 2_000_000,
                                max_records: int = 4096) -> dict:
    """Review exact-host offline evidence under independent engagement scope.

    Planning always stays non-executable, even if all capabilities appear present.
    """
    plan = plan_tier1(objective="web_findings", targets=targets,
                      allowed_targets=allowed_targets, capabilities=capabilities,
                      engagement_authorized=engagement_authorized)
    steps = plan["steps"]
    if (len(steps) != 2 or steps[0]["tool"] != "Nuclei"
            or steps[1]["tool"] != "OWASP ZAP"
            or any(step["executable"] for step in steps)):
        raise Tier1PlanError("Unexpected non-executable web finding plan")
    # The importer normalizes IP literals and validates every imported host.
    # Requiring canonical targets here avoids planner/importer scope disagreement.
    from .nuclei_offline_jsonl_import import _host
    if (any(_host(host) != host for host in targets)
            or any(_host(host) != host for host in allowed_targets)):
        raise Tier1PlanError("Noncanonical exact host scope")
    imported = import_nuclei_jsonl(payload, allowed_hosts=targets,
                                   source_name=source_name, max_bytes=max_bytes,
                                   max_records=max_records)
    entries = sorted((
        {"host": item["host"], "template_id": item["template_id"],
         "reported_severity": item["reported_severity"],
         "classification": "unverified_tool_observation",
         "artifact_sha256": imported["sha256"], "record_index": index}
        for index, item in enumerate(imported["observations"])
    ), key=lambda item: (item["host"], item["template_id"], item["record_index"]))
    report = {
        "schema": "red.nuclei_offline_review.v1",
        "authority": "untrusted_offline_review",
        "source_tool": "Nuclei",
        "artifact_sha256": imported["sha256"],
        "observation_count": len(entries),
        "observations": entries,
        "finding_status": "not_assessed",
        "limitations": "Template matches and tool severity are unverified; no vulnerability, exploitability, authorization or remediation is proven.",
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    report["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    return {"schema": "red.nuclei_offline_workflow.v1",
            "authority": "review_only_not_execution_authorization",
            "plan": plan, "report": report}
