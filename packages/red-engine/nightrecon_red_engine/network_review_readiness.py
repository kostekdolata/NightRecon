"""Engagement review-readiness synthesis for Red Night network assessments."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from nightrecon_red_engine.network_assessment_bundle import (
    NetworkAssessmentBundle,
)


@dataclass(frozen=True)
class NetworkReviewReadiness:
    """Describe whether engagement evidence is ready for high-level review."""

    level: str
    summary: str
    hosts_assessed: int
    hosts_ready: tuple[str, ...]
    hosts_needing_more_evidence: tuple[str, ...]
    recurring_missing_layers: tuple[tuple[str, int], ...]
    review_notes: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "level": self.level,
            "summary": self.summary,
            "hosts_assessed": self.hosts_assessed,
            "hosts_ready": list(self.hosts_ready),
            "hosts_needing_more_evidence": list(
                self.hosts_needing_more_evidence
            ),
            "recurring_missing_layers": [
                {"layer": layer, "host_count": count}
                for layer, count in self.recurring_missing_layers
            ],
            "review_notes": list(self.review_notes),
        }


def build_network_review_readiness(
    bundles: tuple[NetworkAssessmentBundle, ...],
) -> NetworkReviewReadiness:
    """Summarize evidence readiness without producing a security risk score."""

    if not bundles:
        return NetworkReviewReadiness(
            level="not-ready",
            summary=(
                "No host assessment bundles are available for engagement "
                "review."
            ),
            hosts_assessed=0,
            hosts_ready=(),
            hosts_needing_more_evidence=(),
            recurring_missing_layers=(),
            review_notes=(
                "Complete host-level network assessments before review.",
            ),
        )

    seen: set[str] = set()
    ready: list[str] = []
    needs_evidence: list[str] = []
    missing = Counter()

    for bundle in bundles:
        if bundle.host in seen:
            raise ValueError(
                f"Duplicate host assessment bundle supplied: {bundle.host!r}."
            )
        seen.add(bundle.host)

        if bundle.completeness.level == "comprehensive":
            ready.append(bundle.host)
        else:
            needs_evidence.append(bundle.host)

        missing.update(bundle.completeness.missing_layers)

    hosts_assessed = len(bundles)
    ready_count = len(ready)

    if ready_count == hosts_assessed:
        level = "ready"
        summary = (
            "All assessed hosts have comprehensive core network evidence "
            "for high-level engagement review."
        )
    elif ready_count:
        level = "partially-ready"
        summary = (
            f"{ready_count} of {hosts_assessed} assessed host(s) have "
            "comprehensive evidence; remaining hosts need additional "
            "coverage before the engagement view is complete."
        )
    else:
        level = "not-ready"
        summary = (
            "No assessed host currently has all core evidence layers "
            "represented."
        )

    recurring = tuple(sorted(
        missing.items(),
        key=lambda item: (-item[1], item[0]),
    ))

    notes: list[str] = []
    if recurring:
        notes.append(
            "Recurring missing evidence is concentrated in: "
            + ", ".join(layer for layer, _ in recurring[:4])
            + "."
        )
    if needs_evidence:
        notes.append(
            f"{len(needs_evidence)} host(s) should receive evidence-completion "
            "follow-up before relying on the engagement summary as complete."
        )

    return NetworkReviewReadiness(
        level=level,
        summary=summary,
        hosts_assessed=hosts_assessed,
        hosts_ready=tuple(sorted(ready)),
        hosts_needing_more_evidence=tuple(sorted(needs_evidence)),
        recurring_missing_layers=recurring,
        review_notes=tuple(notes),
    )
