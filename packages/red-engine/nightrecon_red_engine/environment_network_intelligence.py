"""Environment-wide high-level network intelligence for Red Night.

This layer aggregates per-host network assessment intelligence into concise
operator-facing engagement feedback. It remains descriptive and evidence-led.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from nightrecon_red_engine.network_assessment_intelligence import (
    NetworkAssessmentIntelligence,
)


ENVIRONMENT_NETWORK_INTERPRETATION = (
    "Environment-wide synthesis of host assessment evidence. Host counts, "
    "exposure themes, and confidence distribution are descriptive and do not "
    "establish exploitability, compromise, likelihood, or business impact."
)


@dataclass(frozen=True)
class HostNetworkAssessment:
    """Bind a host identifier to its high-level network assessment."""

    host: str
    assessment: NetworkAssessmentIntelligence


@dataclass(frozen=True)
class EnvironmentNetworkIntelligence:
    """High-level environment view for operator decision support."""

    headline: str
    overview: str
    hosts_assessed: int
    exposure_theme_counts: tuple[tuple[str, int], ...]
    confidence_counts: tuple[tuple[str, int], ...]
    attention_hosts: tuple[tuple[str, tuple[str, ...]], ...]
    shared_coverage_gaps: tuple[str, ...]
    recommended_next_actions: tuple[str, ...]
    interpretation: str = ENVIRONMENT_NETWORK_INTERPRETATION

    def to_dict(self) -> dict[str, object]:
        return {
            "headline": self.headline,
            "overview": self.overview,
            "hosts_assessed": self.hosts_assessed,
            "exposure_theme_counts": [
                {"theme": theme, "host_count": count}
                for theme, count in self.exposure_theme_counts
            ],
            "confidence_counts": [
                {"confidence": confidence, "host_count": count}
                for confidence, count in self.confidence_counts
            ],
            "attention_hosts": [
                {"host": host, "reasons": list(reasons)}
                for host, reasons in self.attention_hosts
            ],
            "shared_coverage_gaps": list(self.shared_coverage_gaps),
            "recommended_next_actions": list(self.recommended_next_actions),
            "interpretation": self.interpretation,
        }


def build_environment_network_intelligence(
    hosts: tuple[HostNetworkAssessment, ...],
) -> EnvironmentNetworkIntelligence:
    """Aggregate host-level intelligence into an engagement-wide view."""

    if not hosts:
        return EnvironmentNetworkIntelligence(
            headline="No host network assessments available",
            overview=(
                "No host-level network intelligence was supplied, so the "
                "environment-wide network posture cannot yet be characterized."
            ),
            hosts_assessed=0,
            exposure_theme_counts=(),
            confidence_counts=(),
            attention_hosts=(),
            shared_coverage_gaps=(
                "No host-level network assessment evidence is available.",
            ),
            recommended_next_actions=(
                "Complete bounded host/network assessment coverage before "
                "drawing environment-wide conclusions.",
            ),
        )

    seen_hosts: set[str] = set()
    theme_counts: Counter[str] = Counter()
    confidence_counts: Counter[str] = Counter()
    gap_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    attention: list[tuple[str, tuple[str, ...]]] = []

    for item in hosts:
        if not item.host:
            raise ValueError("Host identifier must not be empty.")
        if item.host in seen_hosts:
            raise ValueError(
                f"Duplicate host assessment supplied: {item.host!r}."
            )
        seen_hosts.add(item.host)

        assessment = item.assessment
        confidence_counts[assessment.confidence] += 1
        theme_counts.update(assessment.exposure_categories)
        gap_counts.update(assessment.coverage_gaps)
        action_counts.update(assessment.recommended_next_actions)

        reasons: list[str] = []
        if len(assessment.exposure_categories) >= 3:
            reasons.append("multiple exposure categories observed")
        if "remote-administration" in assessment.exposure_categories:
            reasons.append("remote administration exposure present")
        if "data-services" in assessment.exposure_categories:
            reasons.append("data/file service exposure present")
        if assessment.confidence == "limited":
            reasons.append("assessment confidence is limited")
        if len(assessment.coverage_gaps) >= 2:
            reasons.append("multiple coverage gaps remain")

        if reasons:
            attention.append((item.host, tuple(reasons)))

    hosts_assessed = len(hosts)
    broad_hosts = sum(
        1
        for item in hosts
        if len(item.assessment.exposure_categories) >= 3
    )
    limited_hosts = confidence_counts.get("limited", 0)

    if broad_hosts:
        headline = "Broad network exposure spans the assessed environment"
        overview = (
            f"{broad_hosts} of {hosts_assessed} assessed host(s) expose three "
            "or more network service categories. Environment review should "
            "focus on reducing unnecessary reachability, validating trust "
            "boundaries, and completing evidence gaps on the highlighted hosts."
        )
    elif theme_counts:
        headline = "Network exposure is present across the assessed environment"
        overview = (
            "Multiple host assessments confirm network service exposure. The "
            "environment view highlights recurring exposure themes and hosts "
            "where access-control, segmentation, or evidence completeness "
            "deserve focused review."
        )
    else:
        headline = "No responsive network exposure confirmed across assessed hosts"
        overview = (
            "The supplied host assessments do not confirm responsive network "
            "services. This is a coverage result rather than proof that the "
            "environment has no reachable services."
        )

    shared_gaps = tuple(
        gap
        for gap, count in sorted(
            gap_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )
        if count >= 2
    )

    ranked_actions = tuple(
        action
        for action, _ in sorted(
            action_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )
    )

    if limited_hosts and not shared_gaps:
        shared_gaps = (
            f"{limited_hosts} host assessment(s) have limited confidence.",
        )

    if not ranked_actions:
        ranked_actions = (
            "Correlate network evidence with vulnerability, identity, "
            "application, and asset context before drawing conclusions.",
        )

    return EnvironmentNetworkIntelligence(
        headline=headline,
        overview=overview,
        hosts_assessed=hosts_assessed,
        exposure_theme_counts=tuple(sorted(theme_counts.items())),
        confidence_counts=tuple(sorted(confidence_counts.items())),
        attention_hosts=tuple(sorted(attention, key=lambda item: item[0])),
        shared_coverage_gaps=shared_gaps,
        recommended_next_actions=ranked_actions,
    )
