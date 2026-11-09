"""Fail-closed Tier 1 capability and engagement-bound planning contract.

Pure offline planning. Never resolves executables, starts processes or grants approval.
"""
from __future__ import annotations

import ipaddress
import re

TIER1 = ("Nmap", "Amass", "ProjectDiscovery httpx", "Nuclei",
         "Greenbone/OpenVAS", "OWASP ZAP", "Wireshark/TShark")
OBJECTIVES = {
    "network_inventory": ("Nmap",),
    "domain_inventory": ("Amass",),
    "web_inventory": ("ProjectDiscovery httpx",),
    "web_findings": ("Nuclei", "OWASP ZAP"),
    "vulnerability_review": ("Greenbone/OpenVAS",),
    "offline_packet_review": ("Wireshark/TShark",),
}
_NETWORK = {"Nmap", "Amass", "ProjectDiscovery httpx", "Nuclei",
            "Greenbone/OpenVAS", "OWASP ZAP"}
_HOST = re.compile(r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z")


class Tier1PlanError(ValueError):
    """Invalid or unauthorized planning input."""


def _host(value: str) -> bool:
    if not isinstance(value, str) or not _HOST.fullmatch(value):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return all(0 < len(label) <= 63 and not label.startswith("-")
                   and not label.endswith("-") for label in value.split("."))


def plan_tier1(*, objective: str, targets: tuple[str, ...],
               allowed_targets: tuple[str, ...], capabilities: dict,
               engagement_authorized: bool, intrusive_approval: bool = False) -> dict:
    """Return explicit non-executable plan with unavailable/approval blockers.

    Scope is exact-match only; no CIDR, wildcard, suffix or DNS expansion.
    Caller-provided capability states are untrusted hints, never execution proof.
    """
    if not isinstance(objective, str) or objective not in OBJECTIVES:
        raise Tier1PlanError("Unsupported objective")
    if (type(engagement_authorized) is not bool or not engagement_authorized
            or type(intrusive_approval) is not bool):
        raise Tier1PlanError("Explicit engagement authorization required")
    if (not isinstance(targets, tuple) or not 0 < len(targets) <= 32
            or not isinstance(allowed_targets, tuple) or not 0 < len(allowed_targets) <= 256
            or any(not _host(x) for x in targets + allowed_targets)
            or len(set(targets)) != len(targets)
            or not set(targets).issubset(allowed_targets)):
        raise Tier1PlanError("Targets must be exact independently allowlisted hosts")
    if not isinstance(capabilities, dict) or set(capabilities) - set(TIER1):
        raise Tier1PlanError("Unregistered capability")
    for tool, state in capabilities.items():
        if (not isinstance(state, dict)
                or set(state) != {"available", "platform_supported", "prerequisites_met"}
                or any(type(v) is not bool for v in state.values())):
            raise Tier1PlanError("Invalid capability state")
    steps = []
    for tool in OBJECTIVES[objective]:
        state = capabilities.get(tool)
        missing = [] if state is not None else ["capability_not_registered"]
        if state is not None:
            missing.extend(key for key in ("available", "platform_supported", "prerequisites_met")
                           if not state[key])
        # Every active-network tool remains blocked until a separate policy/executor
        # checks scope, authorization, technique approval and live budgets.
        requires_live_gate = tool in _NETWORK
        if requires_live_gate:
            missing.append("guarded_executor_and_live_policy_required")
        steps.append({"tool": tool, "targets": list(targets),
                      "selection_reason": objective,
                      "status": "blocked" if missing else "offline_plan_only",
                      "blockers": missing,
                      "requires_separate_intrusive_approval": tool in
                      {"Nuclei", "Greenbone/OpenVAS", "OWASP ZAP"},
                      "executable": False})
    return {"schema": "red.tier1_offline_plan.v1",
            "authority": "planning_only_not_execution_authorization",
            "objective": objective, "steps": steps,
            "limitations": "No tool installation, runtime availability, approval or execution is proven."}
