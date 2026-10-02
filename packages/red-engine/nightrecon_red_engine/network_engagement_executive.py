"""Engagement-level executive roll-up for Red Night network assessments."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from nightrecon_red_engine.network_assessment_bundle import (
    NetworkAssessmentBundle,
)


@dataclass(frozen=True)
class NetworkEngagementExecutive:
    """Aggregate multiple host bundles into a concise engagement view."""

    headline: str
    summary: str
    hosts_assessed: int
    completeness_counts: tuple[tuple[str, int], ...]
    recurring_observations: tuple[tuple[str, int], ...]
    hosts_with_limitations: tuple[str, ...]
    recommended_next_actions: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "headline": self.headline,
            "summary": self.summary,
            "hosts_assessed": self.hosts_assessed,
            "completeness_counts": [
                {"level": level, "host_count": count}
                for level, count in self.completeness_counts
            ],
            "recurring_observations": [
                {"observation": observation, "host_count": count}
                for observation, count in self.recurring_observations
            ],
            "hosts_with_limitations": list(self.hosts_with_limitations),
            "recommended_next_actions": list(
                self.recommended_next_actions
            ),
        }


def build_network_engagement_executive(
    bundles: tuple[NetworkAssessmentBundle, ...],
) -> NetworkEngagementExecutive:
    """Build a deterministic engagement-wide executive summary."""

    if not bundles:
        return NetworkEngagementExecutive(
            headline="No network assessment bundles available",
            summary=(
                "No host assessment bundles were supplied, so an "
                "engagement-level network view cannot yet be produced."
            ),
            hosts_assessed=0,
            completeness_counts=(),
            recurring_observations=(),
            hosts_with_limitations=(),
            recommended_next_actions=(
                "Complete host-level network assessments before drawing "
                "engagement-wide conclusions.",
            ),
        )

    seen: set[str] = set()
    completeness = Counter()
    observations = Counter()
    actions = Counter()
    limitation_hosts: list[str] = []

    for bundle in bundles:
        if bundle.host in seen:
            raise ValueError(
                f"Duplicate host assessment bundle supplied: {bundle.host!r}."
            )
        seen.add(bundle.host)

        completeness[bundle.completeness.level] += 1
        observations.update(
            bundle.executive_assessment.key_observations
        )
        actions.update(
            bundle.executive_assessment.recommended_next_actions
        )
        if bundle.executive_assessment.limitations:
            limitation_hosts.append(bundle.host)

    recurring = tuple(
        (observation, count)
        for observation, count in sorted(
            observations.items(),
            key=lambda item: (-item[1], item[0]),
        )
        if count >= 2
    )

    comprehensive = completeness.get("comprehensive", 0)
    partial = completeness.get("partial", 0)
    limited = completeness.get("limited", 0)
    hosts_assessed = len(bundles)

    if limited:
        headline = "Engagement network evidence remains incomplete"
        summary = (
            f"{hosts_assessed} host(s) were assessed: {comprehensive} "
            f"comprehensive, {partial} partial, and {limited} limited. "
            "The engagement view should be interpreted with the identified "
            "coverage limitations."
        )
    elif recurring:
        headline = "Recurring network exposure themes span the engagement"
        summary = (
            f"{hosts_assessed} host(s) were assessed and repeated exposure "
            "observations are present across multiple hosts."
        )
    else:
        headline = "Engagement network assessment consolidated"
        summary = (
            f"{hosts_assessed} host(s) were assessed with no recurring "
            "high-level observation repeated across multiple hosts."
        )

    ranked_actions = tuple(
        action
        for action, _ in sorted(
            actions.items(),
            key=lambda item: (-item[1], item[0]),
        )
    )

    return NetworkEngagementExecutive(
        headline=headline,
        summary=summary,
        hosts_assessed=hosts_assessed,
        completeness_counts=tuple(sorted(completeness.items())),
        recurring_observations=recurring[:8],
        hosts_with_limitations=tuple(sorted(limitation_hosts)),
        recommended_next_actions=ranked_actions[:8],
    )
