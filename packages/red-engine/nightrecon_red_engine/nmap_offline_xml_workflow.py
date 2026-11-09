"""Engagement-bound offline Nmap XML review; no scanner or network execution."""
from __future__ import annotations

import hashlib
import ipaddress
import json

from .nmap_offline_xml_import import import_nmap_xml, NmapOfflineImportError
from .tier1_offline_plan import plan_tier1, Tier1PlanError


def review_nmap_offline_xml(*, payload: bytes, targets: tuple[str, ...],
                            allowed_targets: tuple[str, ...], capabilities: dict,
                            engagement_authorized: bool, source_name: str = "nmap.xml",
                            max_hosts: int = 256, max_ports: int = 4096) -> dict:
    """Review exact-IP, untrusted offline observations with a blocked execution plan.

    No DNS expansion, CIDR inference, tool execution or vulnerability verdicts.
    """
    plan = plan_tier1(objective="network_inventory", targets=targets,
                      allowed_targets=allowed_targets, capabilities=capabilities,
                      engagement_authorized=engagement_authorized)
    if len(plan["steps"]) != 1 or plan["steps"][0]["tool"] != "Nmap" or plan["steps"][0]["executable"]:
        raise Tier1PlanError("Unexpected Nmap planning contract")
    try:
        selected = tuple(str(ipaddress.ip_address(value)) for value in targets)
        permitted = tuple(str(ipaddress.ip_address(value)) for value in allowed_targets)
    except (ValueError, TypeError) as exc:
        raise Tier1PlanError("Nmap offline review requires exact IP targets") from exc
    if len(set(selected)) != len(selected) or len(set(permitted)) != len(permitted):
        raise Tier1PlanError("Duplicate normalized IP target")
    if not set(selected).issubset(permitted):
        raise Tier1PlanError("Selected IP target outside allowed scope")
    imported = import_nmap_xml(payload, allowed_addresses=selected,
                               source_name=source_name, max_hosts=max_hosts,
                               max_ports=max_ports)
    observations = imported["observations"]
    # Imported states are observations, not findings or remediation results.
    entries = sorted(({"address": item["address"], "protocol": item["protocol"],
                       "port": item["port"], "observed_state": item["observed_state"],
                       "classification": "unverified_tool_observation",
                       "artifact_sha256": imported["sha256"], "record_index": i}
                      for i, item in enumerate(observations)),
                     key=lambda item: (item["address"], item["protocol"], item["port"], item["record_index"]))
    report = {"schema": "red.nmap_offline_review.v1",
              "authority": "untrusted_offline_review",
              "source_tool": "Nmap", "artifact_sha256": imported["sha256"],
              "observation_count": len(entries), "observations": entries,
              "finding_status": "not_assessed",
              "limitations": "Offline port states do not prove current exposure, vulnerability, exploitability, authorization or remediation."}
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    report["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    return {"schema": "red.nmap_offline_workflow.v1",
            "authority": "review_only_not_execution_authorization",
            "plan": plan, "report": report}
