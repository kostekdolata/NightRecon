"""Fail-closed, execution-free selection of the locked Red Night tool inventory.

This module does not discover binaries, grant authorization, or execute tools.
The caller must supply independently verified capability and engagement facts.
"""
from __future__ import annotations

from dataclasses import dataclass

TOOLS = (
    "Nmap", "Amass", "ProjectDiscovery httpx", "Nuclei", "Greenbone/OpenVAS",
    "OWASP ZAP", "Wireshark/TShark", "Metasploit Framework", "BloodHound CE",
    "Impacket", "Prowler", "Trivy", "Semgrep", "MobSF", "Ghidra",
    "Volatility 3", "MITRE CALDERA", "Kismet", "Binwalk", "garak",
)
INTRUSIVE = frozenset(("Metasploit Framework", "MITRE CALDERA"))
NETWORK = frozenset(("Nmap", "Amass", "ProjectDiscovery httpx", "Nuclei",
                     "Greenbone/OpenVAS", "OWASP ZAP", "Impacket", "Kismet", "garak"))


@dataclass(frozen=True)
class Capability:
    name: str
    available: bool
    prerequisites_verified: bool
    platform_supported: bool


@dataclass(frozen=True)
class Engagement:
    approved_targets: frozenset[str]
    approved_tools: frozenset[str]
    intrusive_approvals: frozenset[str]
    max_actions: int
    stopped: bool = False


def plan_tools(requested: tuple[str, ...], target: str, engagement: Engagement,
               capabilities: tuple[Capability, ...]) -> dict:
    """Return explainable eligibility; never return executable instructions."""
    if not isinstance(engagement, Engagement) or type(engagement.max_actions) is not int:
        raise ValueError("Invalid engagement")
    if not isinstance(target, str) or not target or target not in engagement.approved_targets:
        raise ValueError("Target outside exact engagement scope")
    if engagement.stopped or engagement.max_actions <= 0:
        raise ValueError("Engagement stopped or action budget exhausted")
    if not isinstance(requested, tuple) or not requested or len(requested) > engagement.max_actions:
        raise ValueError("Invalid or over-budget tool request")
    if len(set(requested)) != len(requested) or any(x not in TOOLS for x in requested):
        raise ValueError("Unknown or duplicate tool")
    if not isinstance(capabilities, tuple) or any(not isinstance(x, Capability) for x in capabilities):
        raise ValueError("Invalid capability evidence")
    if len(set(x.name for x in capabilities)) != len(capabilities):
        raise ValueError("Duplicate capability evidence")
    by_name = {x.name: x for x in capabilities}
    results = []
    for name in requested:
        evidence = by_name.get(name)
        if name not in engagement.approved_tools:
            reason = "tool_not_authorized"
        elif name in INTRUSIVE and name not in engagement.intrusive_approvals:
            reason = "intrusive_approval_missing"
        elif evidence is None or evidence.name not in TOOLS:
            reason = "capability_not_verified"
        elif not all(type(x) is bool for x in
                     (evidence.available, evidence.prerequisites_verified, evidence.platform_supported)):
            reason = "invalid_capability_facts"
        elif not evidence.platform_supported:
            reason = "platform_unsupported"
        elif not evidence.available:
            reason = "tool_unavailable"
        elif not evidence.prerequisites_verified:
            reason = "prerequisites_unverified"
        else:
            reason = "eligible_for_separate_execution_authorization"
        results.append({"tool": name, "eligible": reason.startswith("eligible_"),
                        "reason": reason, "action_class":
                        "intrusive" if name in INTRUSIVE else
                        "network_active_or_service" if name in NETWORK else "offline_or_external"})
    return {"schema": "red.tool_selection.v1", "target": target,
            "execution_authorized": False, "results": results,
            "limitations": "Eligibility only; no executable command, authorization grant, or tool execution"}
