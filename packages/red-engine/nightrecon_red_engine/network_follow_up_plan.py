"""High-level follow-up action planning for Red Night network assessments."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from nightrecon_red_engine.network_assessment_bundle import (
    NetworkAssessmentBundle,
)


@dataclass(frozen=True)
class NetworkFollowUpAction:
    """One recurring evidence-backed follow-up action."""

    action: str
    host_count: int
    hosts: tuple[str, ...]


@dataclass(frozen=True)
class NetworkFollowUpPlan:
    """Bounded engagement-wide follow-up plan."""

    headline: str
    summary: str
    actions: tuple[NetworkFollowUpAction, ...]
    interpretation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "headline": self.headline,
            "summary": self.summary,
            "actions": [
                {
                    "action": item.action,
                    "host_count": item.host_count,
                    "hosts": list(item.hosts),
                }
                for item in self.actions
            ],
            "interpretation": self.interpretation,
        }


def build_network_follow_up_plan(
    bundles: tuple[NetworkAssessmentBundle, ...],
    *,
    max_actions: int = 8,
) -> NetworkFollowUpPlan:
    """Aggregate recurring next actions by frequency, not risk scoring."""

    if max_actions < 1:
        raise ValueError("max_actions must be at least 1.")

    if not bundles:
        return NetworkFollowUpPlan(
            headline="No network follow-up plan available",
            summary="No host assessment bundles were supplied.",
            actions=(),
            interpretation=(
                "Actions are derived from assessment evidence frequency and "
                "coverage gaps; they are not a security risk ranking."
            ),
        )

    action_hosts: dict[str, set[str]] = {}
    for bundle in bundles:
        for action in bundle.executive_assessment.recommended_next_actions:
            action_hosts.setdefault(action, set()).add(bundle.host)

    ranked = sorted(
        action_hosts.items(),
        key=lambda item: (-len(item[1]), item[0]),
    )

    actions = tuple(
        NetworkFollowUpAction(
            action=action,
            host_count=len(hosts),
            hosts=tuple(sorted(hosts)),
        )
        for action, hosts in ranked[:max_actions]
    )

    if actions:
        headline = "Network assessment follow-up plan"
        summary = (
            f"{len(actions)} recurring or host-specific follow-up action(s) "
            "were consolidated from the assessed evidence."
        )
    else:
        headline = "No additional network follow-up action identified"
        summary = (
            "The supplied assessment bundles contain no explicit next-action "
            "recommendations."
        )

    return NetworkFollowUpPlan(
        headline=headline,
        summary=summary,
        actions=actions,
        interpretation=(
            "Actions are ordered by how many assessed hosts produced the same "
            "recommendation, not by exploitability, likelihood, or impact."
        ),
    )
