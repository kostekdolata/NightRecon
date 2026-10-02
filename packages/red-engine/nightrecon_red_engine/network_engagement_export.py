"""Stable high-level engagement export surface for Red Night."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.network_change_executive import NetworkChangeExecutive
from nightrecon_red_engine.network_engagement_brief import NetworkEngagementBrief
from nightrecon_red_engine.network_evidence_concentration import (
    NetworkEvidenceConcentration,
)
from nightrecon_red_engine.network_follow_up_plan import NetworkFollowUpPlan
from nightrecon_red_engine.network_review_readiness import NetworkReviewReadiness


@dataclass(frozen=True)
class NetworkEngagementExport:
    """Compact serializable engagement output for UI/API/report consumers."""

    brief: NetworkEngagementBrief
    readiness: NetworkReviewReadiness
    concentration: NetworkEvidenceConcentration
    follow_up_plan: NetworkFollowUpPlan
    change: NetworkChangeExecutive | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "brief": self.brief.to_dict(),
            "readiness": self.readiness.to_dict(),
            "concentration": self.concentration.to_dict(),
            "follow_up_plan": self.follow_up_plan.to_dict(),
            "change": self.change.to_dict() if self.change is not None else None,
        }


def build_network_engagement_export(
    *,
    brief: NetworkEngagementBrief,
    readiness: NetworkReviewReadiness,
    concentration: NetworkEvidenceConcentration,
    follow_up_plan: NetworkFollowUpPlan,
    change: NetworkChangeExecutive | None = None,
) -> NetworkEngagementExport:
    """Return a stable composition object for downstream consumers."""

    return NetworkEngagementExport(
        brief=brief,
        readiness=readiness,
        concentration=concentration,
        follow_up_plan=follow_up_plan,
        change=change,
    )
