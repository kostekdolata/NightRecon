"""Consolidated engagement network brief for Red Night."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.network_engagement_change import (
    NetworkEngagementDelta,
)
from nightrecon_red_engine.network_engagement_executive import (
    NetworkEngagementExecutive,
)
from nightrecon_red_engine.network_follow_up_plan import NetworkFollowUpPlan
from nightrecon_red_engine.network_review_readiness import (
    NetworkReviewReadiness,
)


@dataclass(frozen=True)
class NetworkEngagementBrief:
    """Single high-level engagement output for operators and reporting."""

    headline: str
    executive_summary: str
    review_readiness: str
    recurring_observations: tuple[str, ...]
    change_summary: str
    follow_up_actions: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "headline": self.headline,
            "executive_summary": self.executive_summary,
            "review_readiness": self.review_readiness,
            "recurring_observations": list(self.recurring_observations),
            "change_summary": self.change_summary,
            "follow_up_actions": list(self.follow_up_actions),
            "limitations": list(self.limitations),
        }


def build_network_engagement_brief(
    *,
    executive: NetworkEngagementExecutive,
    readiness: NetworkReviewReadiness,
    follow_up_plan: NetworkFollowUpPlan,
    delta: NetworkEngagementDelta | None = None,
) -> NetworkEngagementBrief:
    """Combine engagement outputs into one concise operator-facing brief."""

    recurring = tuple(
        f"{observation} ({count} host(s))"
        for observation, count in executive.recurring_observations[:6]
    )

    if delta is None:
        change_summary = (
            "No prior engagement comparison was supplied for change analysis."
        )
    else:
        change_summary = delta.summary

    limitations: list[str] = []
    if readiness.level != "ready":
        limitations.extend(readiness.review_notes)
    if executive.hosts_with_limitations:
        limitations.append(
            f"{len(executive.hosts_with_limitations)} assessed host(s) have "
            "explicit evidence limitations."
        )

    follow_up_actions = tuple(
        item.action for item in follow_up_plan.actions[:6]
    )

    return NetworkEngagementBrief(
        headline=executive.headline,
        executive_summary=executive.summary,
        review_readiness=readiness.summary,
        recurring_observations=recurring,
        change_summary=change_summary,
        follow_up_actions=follow_up_actions,
        limitations=tuple(dict.fromkeys(limitations)),
    )
