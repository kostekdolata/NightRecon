"""High-level change intelligence for repeated network assessments."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.network_assessment_intelligence import (
    NetworkAssessmentIntelligence,
)


@dataclass(frozen=True)
class NetworkAssessmentDelta:
    """Describe meaningful changes between two host network assessments."""

    headline: str
    overview: str
    added_exposure_categories: tuple[str, ...]
    removed_exposure_categories: tuple[str, ...]
    new_coverage_gaps: tuple[str, ...]
    resolved_coverage_gaps: tuple[str, ...]
    confidence_change: str
    recommended_next_actions: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "headline": self.headline,
            "overview": self.overview,
            "added_exposure_categories": list(
                self.added_exposure_categories
            ),
            "removed_exposure_categories": list(
                self.removed_exposure_categories
            ),
            "new_coverage_gaps": list(self.new_coverage_gaps),
            "resolved_coverage_gaps": list(self.resolved_coverage_gaps),
            "confidence_change": self.confidence_change,
            "recommended_next_actions": list(
                self.recommended_next_actions
            ),
        }


def compare_network_assessments(
    previous: NetworkAssessmentIntelligence,
    current: NetworkAssessmentIntelligence,
) -> NetworkAssessmentDelta:
    """Return deterministic, non-scored changes between assessments."""

    previous_categories = set(previous.exposure_categories)
    current_categories = set(current.exposure_categories)
    added = tuple(sorted(current_categories - previous_categories))
    removed = tuple(sorted(previous_categories - current_categories))

    previous_gaps = set(previous.coverage_gaps)
    current_gaps = set(current.coverage_gaps)
    new_gaps = tuple(sorted(current_gaps - previous_gaps))
    resolved_gaps = tuple(sorted(previous_gaps - current_gaps))

    if previous.confidence == current.confidence:
        confidence_change = (
            f"Assessment confidence remains {current.confidence}."
        )
    else:
        confidence_change = (
            f"Assessment confidence changed from {previous.confidence} "
            f"to {current.confidence}."
        )

    changes = len(added) + len(removed) + len(new_gaps) + len(resolved_gaps)
    if changes == 0 and previous.confidence == current.confidence:
        headline = "No material high-level network assessment change detected"
        overview = (
            "Exposure categories, coverage gaps, and assessment confidence "
            "are unchanged in the supplied comparison."
        )
    else:
        headline = "Network assessment change detected"
        overview = (
            "The latest assessment differs from the previous high-level "
            "network view. Review changed exposure and evidence coverage "
            "before deciding whether operational follow-up is required."
        )

    actions: list[str] = []
    if added:
        actions.append(
            "Validate newly observed exposure categories against intended "
            "service deployment and network reachability."
        )
    if new_gaps:
        actions.append(
            "Close newly introduced evidence gaps before relying on the "
            "latest assessment for broader conclusions."
        )
    if removed:
        actions.append(
            "Confirm removed exposure categories reflect an intended change "
            "rather than reduced scan or evidence coverage."
        )
    if not actions:
        actions.append(
            "Retain the comparison as baseline evidence for the next "
            "authorized assessment."
        )

    return NetworkAssessmentDelta(
        headline=headline,
        overview=overview,
        added_exposure_categories=added,
        removed_exposure_categories=removed,
        new_coverage_gaps=new_gaps,
        resolved_coverage_gaps=resolved_gaps,
        confidence_change=confidence_change,
        recommended_next_actions=tuple(actions),
    )
