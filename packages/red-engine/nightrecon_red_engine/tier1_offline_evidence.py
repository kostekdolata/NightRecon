"""Engagement-bound, non-executable Tier 1 offline evidence review.

Existing planner and import contracts remain independent. Imported observations
never grant authorization, execution privileges or confirmed finding status.
"""
from __future__ import annotations

from .tier1_offline_plan import Tier1PlanError, plan_tier1
from .offline_tool_correlation import OfflineCorrelationError, correlate_offline_hosts
from .offline_correlation_report import render_offline_correlation_report

_IMPORT_OBJECTIVES = {
    "Amass": "domain_inventory",
    "ProjectDiscovery httpx": "web_inventory",
    "Greenbone/OpenVAS": "vulnerability_review",
}


def review_tier1_offline_evidence(*, imports: tuple[dict, ...],
                                  targets: tuple[str, ...],
                                  allowed_targets: tuple[str, ...],
                                  capabilities: dict,
                                  engagement_authorized: bool,
                                  max_observations: int = 10000) -> dict:
    """Plan every imported tool against explicit scope, then correlate and report.

    Plans are never executable. A missing capability does not fabricate tool
    availability: pre-existing offline evidence may still be reviewed, with the
    planning blockers preserved. No tool is launched or probed.
    """
    if (not isinstance(imports, tuple) or not 0 < len(imports) <= 32
            or type(max_observations) is not int or not 0 < max_observations <= 10000):
        raise OfflineCorrelationError("Invalid offline review budget")
    tools = []
    for item in imports:
        if not isinstance(item, dict) or item.get("source_tool") not in _IMPORT_OBJECTIVES:
            raise OfflineCorrelationError("Unsupported offline import source")
        tool = item["source_tool"]
        if tool not in tools:
            tools.append(tool)
    plans = []
    for tool in sorted(tools):
        plan = plan_tier1(objective=_IMPORT_OBJECTIVES[tool], targets=targets,
                          allowed_targets=allowed_targets, capabilities=capabilities,
                          engagement_authorized=engagement_authorized)
        if len(plan["steps"]) != 1 or plan["steps"][0]["tool"] != tool:
            raise Tier1PlanError("Unexpected planning contract")
        plans.append(plan["steps"][0])
    # Import scope is the selected targets, never the wider engagement allowlist.
    correlation = correlate_offline_hosts(imports, allowed_hosts=targets,
                                          max_observations=max_observations)
    report = render_offline_correlation_report(correlation,
                                               max_observations=max_observations)
    return {
        "schema": "red.tier1_offline_evidence_review.v1",
        "authority": "untrusted_offline_review_not_execution_authorization",
        "plans": plans,
        "report": report,
        "limitations": "Offline imported evidence is not a scan, approval or exploitability proof.",
    }
