"""Evidence-concentration analysis for engagement network assessments."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from nightrecon_red_engine.network_assessment_bundle import NetworkAssessmentBundle


@dataclass(frozen=True)
class NetworkEvidenceConcentration:
    """Describe where recurring evidence clusters across assessed hosts."""

    headline: str
    summary: str
    recurring_exposure_categories: tuple[tuple[str, int], ...]
    recurring_context_observations: tuple[tuple[str, int], ...]
    concentration_hosts: tuple[tuple[str, int], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "headline": self.headline,
            "summary": self.summary,
            "recurring_exposure_categories": [
                {"category": category, "host_count": count}
                for category, count in self.recurring_exposure_categories
            ],
            "recurring_context_observations": [
                {"observation": observation, "host_count": count}
                for observation, count in self.recurring_context_observations
            ],
            "concentration_hosts": [
                {"host": host, "signal_count": count}
                for host, count in self.concentration_hosts
            ],
        }


def build_network_evidence_concentration(
    bundles: tuple[NetworkAssessmentBundle, ...],
) -> NetworkEvidenceConcentration:
    """Aggregate recurring evidence without assigning a risk score."""

    if not bundles:
        return NetworkEvidenceConcentration(
            headline="No network evidence concentration available",
            summary="No host assessment bundles were supplied.",
            recurring_exposure_categories=(),
            recurring_context_observations=(),
            concentration_hosts=(),
        )

    seen: set[str] = set()
    exposure = Counter()
    context = Counter()
    host_signals: list[tuple[str, int]] = []

    for bundle in bundles:
        if bundle.host in seen:
            raise ValueError(
                f"Duplicate host assessment bundle supplied: {bundle.host!r}."
            )
        seen.add(bundle.host)

        exposure.update(bundle.assessment.exposure_categories)
        context.update(bundle.context.notable_context)

        signal_count = (
            len(bundle.assessment.exposure_categories)
            + len(bundle.context.notable_context)
            + len(bundle.executive_assessment.limitations)
        )
        host_signals.append((bundle.host, signal_count))

    recurring_exposure = tuple(
        (category, count)
        for category, count in sorted(
            exposure.items(),
            key=lambda item: (-item[1], item[0]),
        )
        if count >= 2
    )
    recurring_context = tuple(
        (observation, count)
        for observation, count in sorted(
            context.items(),
            key=lambda item: (-item[1], item[0]),
        )
        if count >= 2
    )
    concentration_hosts = tuple(sorted(
        host_signals,
        key=lambda item: (-item[1], item[0]),
    ))

    if recurring_exposure or recurring_context:
        headline = "Recurring network evidence clusters across the engagement"
        summary = (
            "Repeated exposure categories or correlated context appear on "
            "multiple assessed hosts and can be reviewed as shared themes."
        )
    else:
        headline = "Network evidence is primarily host-specific"
        summary = (
            "No recurring high-level exposure or correlated context appears "
            "on multiple assessed hosts in the supplied evidence."
        )

    return NetworkEvidenceConcentration(
        headline=headline,
        summary=summary,
        recurring_exposure_categories=recurring_exposure[:8],
        recurring_context_observations=recurring_context[:8],
        concentration_hosts=concentration_hosts[:12],
    )
