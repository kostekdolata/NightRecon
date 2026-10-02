"""Executive network assessment synthesis for Red Night."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.network_context_intelligence import (
    NetworkContextIntelligence,
)
from nightrecon_red_engine.network_evidence_completeness import (
    NetworkEvidenceCompleteness,
)
from nightrecon_red_engine.network_operator_brief import NetworkOperatorBrief


@dataclass(frozen=True)
class NetworkExecutiveAssessment:
    """Single top-level assessment view for operators and reports."""

    headline: str
    summary: str
    key_observations: tuple[str, ...]
    evidence_completeness: str
    operator_focus: tuple[str, ...]
    recommended_next_actions: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "headline": self.headline,
            "summary": self.summary,
            "key_observations": list(self.key_observations),
            "evidence_completeness": self.evidence_completeness,
            "operator_focus": list(self.operator_focus),
            "recommended_next_actions": list(
                self.recommended_next_actions
            ),
            "limitations": list(self.limitations),
        }


def build_network_executive_assessment(
    *,
    operator_brief: NetworkOperatorBrief,
    context: NetworkContextIntelligence,
    completeness: NetworkEvidenceCompleteness,
) -> NetworkExecutiveAssessment:
    """Combine exposure, context, and completeness into one concise view."""

    observations: list[str] = []
    observations.extend(operator_brief.primary_focus_areas)
    observations.extend(context.notable_context)

    actions = tuple(dict.fromkeys(
        operator_brief.next_actions
        + context.recommended_next_actions
    ))

    limitations: list[str] = []
    if completeness.missing_layers:
        limitations.append(
            "Missing evidence layers: "
            + ", ".join(completeness.missing_layers)
            + "."
        )
    limitations.extend(context.coverage_gaps)

    if context.notable_context:
        headline = "Network exposure with correlated security context"
        summary = (
            f"{operator_brief.executive_summary} "
            f"{context.overview} "
            f"Evidence completeness is {completeness.level}."
        )
    else:
        headline = "Network exposure assessment"
        summary = (
            f"{operator_brief.executive_summary} "
            f"Evidence completeness is {completeness.level}; correlated "
            "vulnerability or threat context is not currently confirmed."
        )

    return NetworkExecutiveAssessment(
        headline=headline,
        summary=summary,
        key_observations=tuple(observations[:8]),
        evidence_completeness=completeness.level,
        operator_focus=operator_brief.hosts_for_review,
        recommended_next_actions=actions[:6],
        limitations=tuple(dict.fromkeys(limitations)),
    )
