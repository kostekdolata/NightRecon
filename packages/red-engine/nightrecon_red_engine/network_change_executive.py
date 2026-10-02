"""Executive engagement-change summary for repeated network assessments."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.network_engagement_change import NetworkEngagementDelta


@dataclass(frozen=True)
class NetworkChangeExecutive:
    """Concise interpretation of an engagement-wide assessment delta."""

    headline: str
    summary: str
    changed_hosts: tuple[str, ...]
    newly_observed_themes: tuple[str, ...]
    no_longer_observed_themes: tuple[str, ...]
    evidence_regressions: tuple[str, ...]
    next_actions: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "headline": self.headline,
            "summary": self.summary,
            "changed_hosts": list(self.changed_hosts),
            "newly_observed_themes": list(self.newly_observed_themes),
            "no_longer_observed_themes": list(
                self.no_longer_observed_themes
            ),
            "evidence_regressions": list(self.evidence_regressions),
            "next_actions": list(self.next_actions),
        }


def build_network_change_executive(
    delta: NetworkEngagementDelta,
) -> NetworkChangeExecutive:
    """Convert detailed engagement deltas into a concise review summary."""

    newly_observed = tuple(
        f"{category} on {count} host(s)"
        for category, count in delta.added_exposure_categories
    )
    no_longer_observed = tuple(
        f"{category} on {count} host(s)"
        for category, count in delta.removed_exposure_categories
    )
    regressions = tuple(
        f"New coverage gap(s) on {host}"
        for host in delta.new_coverage_gap_hosts
    )

    if delta.hosts_changed:
        headline = "Engagement network posture changed"
        summary = (
            f"{len(delta.hosts_changed)} of {delta.hosts_compared} compared "
            "host(s) changed in exposure, evidence coverage, or confidence."
        )
    else:
        headline = "No material engagement network change detected"
        summary = delta.summary

    return NetworkChangeExecutive(
        headline=headline,
        summary=summary,
        changed_hosts=delta.hosts_changed,
        newly_observed_themes=newly_observed,
        no_longer_observed_themes=no_longer_observed,
        evidence_regressions=regressions,
        next_actions=delta.recommended_next_actions[:6],
    )
