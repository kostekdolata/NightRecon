"""Engagement-wide change synthesis for repeated Red Night assessments."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from nightrecon_red_engine.network_change_intelligence import (
    NetworkAssessmentDelta,
)


@dataclass(frozen=True)
class HostNetworkDelta:
    """Bind one host identifier to its assessment delta."""

    host: str
    delta: NetworkAssessmentDelta


@dataclass(frozen=True)
class NetworkEngagementDelta:
    """Summarize meaningful changes across multiple hosts."""

    headline: str
    summary: str
    hosts_compared: int
    hosts_changed: tuple[str, ...]
    added_exposure_categories: tuple[tuple[str, int], ...]
    removed_exposure_categories: tuple[tuple[str, int], ...]
    new_coverage_gap_hosts: tuple[str, ...]
    recommended_next_actions: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "headline": self.headline,
            "summary": self.summary,
            "hosts_compared": self.hosts_compared,
            "hosts_changed": list(self.hosts_changed),
            "added_exposure_categories": [
                {"category": category, "host_count": count}
                for category, count in self.added_exposure_categories
            ],
            "removed_exposure_categories": [
                {"category": category, "host_count": count}
                for category, count in self.removed_exposure_categories
            ],
            "new_coverage_gap_hosts": list(self.new_coverage_gap_hosts),
            "recommended_next_actions": list(
                self.recommended_next_actions
            ),
        }


def build_network_engagement_delta(
    host_deltas: tuple[HostNetworkDelta, ...],
) -> NetworkEngagementDelta:
    """Aggregate per-host deltas without introducing risk scoring."""

    if not host_deltas:
        return NetworkEngagementDelta(
            headline="No network assessment comparisons available",
            summary="No host-level deltas were supplied.",
            hosts_compared=0,
            hosts_changed=(),
            added_exposure_categories=(),
            removed_exposure_categories=(),
            new_coverage_gap_hosts=(),
            recommended_next_actions=(
                "Retain a current assessment baseline for future comparison.",
            ),
        )

    seen: set[str] = set()
    changed: list[str] = []
    new_gap_hosts: list[str] = []
    added = Counter()
    removed = Counter()
    actions = Counter()

    for item in host_deltas:
        if not item.host:
            raise ValueError("Host identifier must not be empty.")
        if item.host in seen:
            raise ValueError(f"Duplicate host delta supplied: {item.host!r}.")
        seen.add(item.host)

        delta = item.delta
        has_change = bool(
            delta.added_exposure_categories
            or delta.removed_exposure_categories
            or delta.new_coverage_gaps
            or delta.resolved_coverage_gaps
            or "changed from" in delta.confidence_change
        )
        if has_change:
            changed.append(item.host)

        if delta.new_coverage_gaps:
            new_gap_hosts.append(item.host)

        added.update(delta.added_exposure_categories)
        removed.update(delta.removed_exposure_categories)
        actions.update(delta.recommended_next_actions)

    hosts_compared = len(host_deltas)
    if changed:
        headline = "Network assessment changes span the engagement"
        summary = (
            f"{len(changed)} of {hosts_compared} compared host(s) show "
            "high-level exposure, evidence, or confidence changes."
        )
    else:
        headline = "No material engagement-wide network change detected"
        summary = (
            f"All {hosts_compared} compared host(s) retain the same high-level "
            "exposure categories, coverage gaps, and confidence state."
        )

    ranked_actions = tuple(
        action
        for action, _ in sorted(
            actions.items(),
            key=lambda item: (-item[1], item[0]),
        )
    )

    return NetworkEngagementDelta(
        headline=headline,
        summary=summary,
        hosts_compared=hosts_compared,
        hosts_changed=tuple(sorted(changed)),
        added_exposure_categories=tuple(sorted(added.items())),
        removed_exposure_categories=tuple(sorted(removed.items())),
        new_coverage_gap_hosts=tuple(sorted(new_gap_hosts)),
        recommended_next_actions=ranked_actions[:8],
    )
