"""Fail-closed governed external-tool execution planning.

No arbitrary command strings or shell. This phase authorises and audits
requests but deliberately does not invoke operating-system subprocesses.
Live execution must separately implement atomic reservation, revocation,
per-target validation and bounded sandbox workers.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path

from nightrecon_shared_core.engagement_policy import (
    FileEngagementPolicyStore, append_authorization_audit, evaluate_action,
)

@dataclass(frozen=True)
class ToolDefinition:
    name: str
    capability: str
    impact: str
    mode: str

# Fixed, non-executing capabilities. No arbitrary executable paths or arguments.
TOOLS = {
    "nmap-discovery": ToolDefinition("nmap-discovery", "external.nmap.discovery", "standard", "plan-only"),
    "tshark-inspection": ToolDefinition("tshark-inspection", "external.tshark.inspect", "low", "plan-only"),
    "web-safe-check": ToolDefinition("web-safe-check", "external.web.safe_check", "standard", "plan-only"),
}

@dataclass(frozen=True)
class ToolPlan:
    tool: str
    target: str
    authorised: bool
    reason_code: str
    mode: str


def plan_governed_tool(
    *,
    tool: str,
    target: str,
    engagement_id: str,
    engagement_status: str,
    policy_store: FileEngagementPolicyStore,
    audit_path: str | Path,
    approved: bool = False,
) -> ToolPlan:
    """Evaluate live shared policy; fail closed if missing or audit cannot persist."""
    definition = TOOLS.get(tool)
    if definition is None:
        raise ValueError("Unknown external tool")
    policy = policy_store.policy(engagement_id)
    if policy is None:
        raise PermissionError("Missing engagement authorisation policy")
    decision = evaluate_action(
        policy,
        engagement_status=engagement_status,
        capability=definition.capability,
        target=target,
        impact=definition.impact,
        approval_present=approved,
    )
    # Always append the decision to the authoritative shared audit trail.
    # Failure to persist blocks even an otherwise authorised plan.
    append_authorization_audit(audit_path, decision)
    return ToolPlan(
        tool=tool,
        target=decision.target,
        authorised=decision.allowed,
        reason_code=decision.reason_code,
        mode=definition.mode,
    )
