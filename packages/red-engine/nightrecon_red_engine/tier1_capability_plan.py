"""Inert Tier 1 integration planning; never launches third-party tools or network requests.

A plan is NOT authorization, an executor registration, or proof of integration.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

TIER1 = {
    "nmap": ("network", True),
    "amass": ("domain", True),
    "httpx": ("web", True),
    "nuclei": ("web", True),
    "greenbone": ("network", True),
    "zap": ("web", True),
    "tshark": ("capture", False),
}
SUPPORTED_PLATFORMS = frozenset(("windows", "linux"))


class Tier1PlanError(ValueError):
    """Invalid planning input or scope."""


def plan_tier1_tools(*, engagement_id: str, authorized_targets: tuple[str, ...],
                     selected_tools: tuple[str, ...], available_tools: Mapping[str, bool],
                     platform: str, intrusive_approval: bool = False,
                     max_tools: int = 7) -> dict:
    """Return explainable, non-executable, fail-closed capability decisions.

    available_tools represents independently attested prerequisites, NOT
    arbitrary PATH discovery. Even a ready decision cannot start a tool.
    """
    if (not isinstance(engagement_id, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", engagement_id)
            or platform not in SUPPORTED_PLATFORMS
            or type(max_tools) is not int or not 1 <= max_tools <= 7
            or type(intrusive_approval) is not bool
            or not isinstance(authorized_targets, tuple)
            or not 0 < len(authorized_targets) <= 256
            or not all(isinstance(t, str) and 0 < len(t) <= 2048
                       and t == t.strip() and not any(ord(c) < 33 for c in t)
                       for t in authorized_targets)
            or len(set(authorized_targets)) != len(authorized_targets)
            or not isinstance(selected_tools, tuple)
            or not 0 < len(selected_tools) <= max_tools
            or len(set(selected_tools)) != len(selected_tools)
            or any(t not in TIER1 for t in selected_tools)
            or not isinstance(available_tools, Mapping)
            or any(k not in TIER1 or type(v) is not bool
                   for k, v in available_tools.items())):
        raise Tier1PlanError("Invalid engagement, scope, platform or tool budget")
    decisions = []
    for tool in selected_tools:
        domain, intrusive = TIER1[tool]
        prerequisite = available_tools.get(tool) is True
        if not prerequisite:
            reason = "trusted_prerequisite_not_attested"
        elif intrusive and not intrusive_approval:
            reason = "explicit_intrusive_approval_required"
        else:
            reason = "prerequisites_only_no_executor_or_authorization"
        decisions.append({
            "tool": tool, "domain": domain,
            "prerequisite_attested": prerequisite,
            "intrusive_approval_recorded": intrusive_approval if intrusive else False,
            "selection_reason": reason,
            "execution_allowed": False,
            "integration_verified": False,
        })
    return {
        "schema": "red.tier1_inert_capability_plan.v1",
        "engagement_id": engagement_id,
        "platform": platform,
        "target_count": len(authorized_targets),
        "selected_count": len(decisions),
        "decisions": decisions,
        "execution_allowed": False,
        "limitations": (
            "Inert planning only; no target authorization record, trusted executor, "
            "sandbox, cancellation, audit or tool integration is established."
        ),
    }
