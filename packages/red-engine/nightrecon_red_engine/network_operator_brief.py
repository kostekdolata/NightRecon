"""Concise operator brief derived from environment-wide network intelligence."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.environment_network_intelligence import (
    EnvironmentNetworkIntelligence,
)


@dataclass(frozen=True)
class NetworkOperatorBrief:
    """High-level network assessment brief for rapid operator consumption."""

    executive_summary: str
    primary_focus_areas: tuple[str, ...]
    hosts_for_review: tuple[str, ...]
    confidence_statement: str
    coverage_statement: str
    next_actions: tuple[str, ...]
    interpretation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "executive_summary": self.executive_summary,
            "primary_focus_areas": list(self.primary_focus_areas),
            "hosts_for_review": list(self.hosts_for_review),
            "confidence_statement": self.confidence_statement,
            "coverage_statement": self.coverage_statement,
            "next_actions": list(self.next_actions),
            "interpretation": self.interpretation,
        }


_THEME_LABELS = {
    "remote-administration": "Remote administration exposure",
    "data-services": "Data and file-service exposure",
    "web-services": "Web service exposure",
    "infrastructure-services": "Infrastructure service exposure",
}


def build_network_operator_brief(
    intelligence: EnvironmentNetworkIntelligence,
    *,
    max_focus_areas: int = 4,
    max_hosts: int = 8,
    max_actions: int = 5,
) -> NetworkOperatorBrief:
    """Produce a concise, deterministic brief without introducing risk scoring."""

    if max_focus_areas < 1:
        raise ValueError("max_focus_areas must be at least 1.")
    if max_hosts < 1:
        raise ValueError("max_hosts must be at least 1.")
    if max_actions < 1:
        raise ValueError("max_actions must be at least 1.")

    ranked_themes = sorted(
        intelligence.exposure_theme_counts,
        key=lambda item: (-item[1], item[0]),
    )
    primary_focus_areas = tuple(
        (
            f"{_THEME_LABELS.get(theme, theme)} is present on "
            f"{count} assessed host(s)."
        )
        for theme, count in ranked_themes[:max_focus_areas]
    )

    if not primary_focus_areas:
        primary_focus_areas = (
            "No recurring responsive network exposure theme was confirmed "
            "in the supplied host assessments.",
        )

    hosts_for_review = tuple(
        host
        for host, _ in intelligence.attention_hosts[:max_hosts]
    )

    confidence = dict(intelligence.confidence_counts)
    high = confidence.get("high", 0)
    moderate = confidence.get("moderate", 0)
    limited = confidence.get("limited", 0)

    if intelligence.hosts_assessed == 0:
        confidence_statement = (
            "Confidence cannot be characterized because no host assessments "
            "are available."
        )
    elif limited:
        confidence_statement = (
            f"Assessment confidence is mixed: {high} high, {moderate} moderate, "
            f"and {limited} limited-confidence host assessment(s)."
        )
    elif moderate:
        confidence_statement = (
            f"Assessment confidence is generally supported: {high} high and "
            f"{moderate} moderate-confidence host assessment(s)."
        )
    else:
        confidence_statement = (
            f"All {high} assessed host(s) currently have high-confidence "
            "network assessment evidence."
        )

    if intelligence.shared_coverage_gaps:
        coverage_statement = (
            "Shared evidence gaps remain: "
            + " ".join(intelligence.shared_coverage_gaps)
        )
    elif intelligence.hosts_assessed:
        coverage_statement = (
            "No recurring cross-host coverage gap was identified in the "
            "supplied network assessment evidence."
        )
    else:
        coverage_statement = (
            "Environment-wide coverage is incomplete because no host-level "
            "network assessment evidence is available."
        )

    next_actions = intelligence.recommended_next_actions[:max_actions]

    return NetworkOperatorBrief(
        executive_summary=(
            f"{intelligence.headline}. {intelligence.overview}"
        ),
        primary_focus_areas=primary_focus_areas,
        hosts_for_review=hosts_for_review,
        confidence_statement=confidence_statement,
        coverage_statement=coverage_statement,
        next_actions=next_actions,
        interpretation=intelligence.interpretation,
    )
