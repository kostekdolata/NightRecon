"""Deterministic cross-domain exposure review and structural concentration.

The review is descriptive. It reports evidence gaps, candidate availability,
remediation/retest state, and path concentration without producing a risk score,
likelihood estimate, exploitability verdict, or execution decision.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from nightrecon_red_engine.attack_path_atlas import AttackPathAtlas
from nightrecon_red_engine.graph_correlation import CrossSurfaceUnresolved
from nightrecon_red_engine.remediation_retest import RemediationFinding
from nightrecon_red_engine.validation_candidates import (
    ValidationCandidateCompilation,
)


REVIEW_INTERPRETATION = (
    "Descriptive exposure review only. Structural concentration, path-count, "
    "target-count, evidence gaps, and retest state are not risk scores and do "
    "not establish exploitability, likelihood, impact, compromise, or priority."
)


@dataclass(frozen=True)
class ExposureReviewLimits:
    max_paths: int = 1_000
    max_gaps: int = 2_000
    max_structures: int = 2_000
    max_remediation_findings: int = 2_000

    def __post_init__(self) -> None:
        for field in (
            "max_paths",
            "max_gaps",
            "max_structures",
            "max_remediation_findings",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 1:
                raise ValueError(f"{field} must be a positive integer")


@dataclass(frozen=True)
class ExposurePathReview:
    path_id: str
    observed_hops: int
    inferred_hops: int
    evidence_ids: tuple[str, ...]
    candidate_id: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "path_id": self.path_id,
            "observed_hops": self.observed_hops,
            "inferred_hops": self.inferred_hops,
            "evidence_ids": list(self.evidence_ids),
            "candidate_id": self.candidate_id,
        }


@dataclass(frozen=True)
class EvidenceGap:
    gap_type: str
    subject_id: str
    detail: str
    candidate_count: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "gap_type": self.gap_type,
            "subject_id": self.subject_id,
            "detail": self.detail,
            "candidate_count": self.candidate_count,
        }


@dataclass(frozen=True)
class StructuralConcentration:
    subject_id: str
    subject_type: str
    path_count: int
    start_count: int
    target_count: int
    path_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "subject_id": self.subject_id,
            "subject_type": self.subject_type,
            "path_count": self.path_count,
            "start_count": self.start_count,
            "target_count": self.target_count,
            "path_ids": list(self.path_ids),
        }


@dataclass(frozen=True)
class PathSetChange:
    before_count: int
    after_count: int
    removed_path_ids: tuple[str, ...]
    retained_path_ids: tuple[str, ...]
    added_path_ids: tuple[str, ...]
    interpretation: str = (
        "Structural path-set difference only. A removed or added path does not by "
        "itself prove that remediation caused the change or that exposure is fixed."
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "before_count": self.before_count,
            "after_count": self.after_count,
            "removed_path_ids": list(self.removed_path_ids),
            "retained_path_ids": list(self.retained_path_ids),
            "added_path_ids": list(self.added_path_ids),
            "interpretation": self.interpretation,
        }


@dataclass(frozen=True)
class ExposureReview:
    paths: tuple[ExposurePathReview, ...]
    evidence_gaps: tuple[EvidenceGap, ...]
    node_concentration: tuple[StructuralConcentration, ...]
    edge_concentration: tuple[StructuralConcentration, ...]
    remediation_status_counts: tuple[tuple[str, int], ...]
    retest_state_counts: tuple[tuple[str, int], ...]
    interpretation: str = REVIEW_INTERPRETATION

    def to_dict(self) -> dict[str, object]:
        return {
            "paths": [item.to_dict() for item in self.paths],
            "evidence_gaps": [item.to_dict() for item in self.evidence_gaps],
            "node_concentration": [
                item.to_dict() for item in self.node_concentration
            ],
            "edge_concentration": [
                item.to_dict() for item in self.edge_concentration
            ],
            "remediation_status_counts": dict(self.remediation_status_counts),
            "retest_state_counts": dict(self.retest_state_counts),
            "interpretation": self.interpretation,
        }


def _concentration(
    atlas: AttackPathAtlas,
    subject_type: str,
) -> tuple[StructuralConcentration, ...]:
    paths = {item.path_id: item for item in atlas.paths}
    source = (
        atlas.node_participation
        if subject_type == "node"
        else atlas.edge_participation
    )
    result: list[StructuralConcentration] = []
    for item in source:
        selected = tuple(paths[path_id] for path_id in item.path_ids)
        result.append(StructuralConcentration(
            subject_id=item.subject_id,
            subject_type=subject_type,
            path_count=item.path_count,
            start_count=len({path.start_node_id for path in selected}),
            target_count=len({path.target_node_id for path in selected}),
            path_ids=item.path_ids,
        ))
    return tuple(sorted(
        result,
        key=lambda item: (
            -item.target_count,
            -item.start_count,
            -item.path_count,
            item.subject_id,
        ),
    ))


def build_exposure_review(
    atlas: AttackPathAtlas,
    compilation: ValidationCandidateCompilation,
    *,
    unresolved_correlations: tuple[CrossSurfaceUnresolved, ...] = (),
    remediation_findings: tuple[RemediationFinding, ...] = (),
    limits: ExposureReviewLimits | None = None,
) -> ExposureReview:
    active = limits or ExposureReviewLimits()

    if len(atlas.paths) > active.max_paths:
        raise ValueError("exposure review exceeds path ceiling")
    if len(remediation_findings) > active.max_remediation_findings:
        raise ValueError("exposure review exceeds remediation finding ceiling")

    candidates_by_path: dict[str, str] = {}
    for candidate in compilation.candidates:
        if candidate.path_id in candidates_by_path:
            raise ValueError(
                "validation compilation contains duplicate path candidates"
            )
        candidates_by_path[candidate.path_id] = candidate.candidate_id

    known_paths = {item.path_id for item in atlas.paths}
    if not set(candidates_by_path).issubset(known_paths):
        raise ValueError(
            "validation compilation references a path outside the atlas"
        )

    path_rows = tuple(
        ExposurePathReview(
            path_id=path.path_id,
            observed_hops=path.observed_hops,
            inferred_hops=path.inferred_hops,
            evidence_ids=path.evidence_ids,
            candidate_id=candidates_by_path.get(path.path_id),
        )
        for path in atlas.paths
    )

    gaps: list[EvidenceGap] = []
    for path in atlas.paths:
        if path.inferred_hops:
            gaps.append(EvidenceGap(
                "inferred-path-evidence",
                path.path_id,
                f"{path.inferred_hops} inferred hop(s) require independent validation.",
            ))
    for reason in atlas.truncation_reasons:
        gaps.append(EvidenceGap("atlas-truncation", "atlas", reason))
    for reason in compilation.truncation_reasons:
        gaps.append(EvidenceGap(
            "candidate-truncation",
            "validation-candidates",
            reason,
        ))
    for item in unresolved_correlations:
        gaps.append(EvidenceGap(
            "unresolved-correlation",
            item.key_sha256,
            item.reason,
            item.candidate_count,
        ))
    for finding in remediation_findings:
        if finding.status.value in {"ready-for-retest", "regressed"}:
            gaps.append(EvidenceGap(
                "retest-state",
                finding.finding_id,
                finding.status.value,
            ))

    if len(gaps) > active.max_gaps:
        raise ValueError("exposure review exceeds evidence-gap ceiling")

    node_concentration = _concentration(atlas, "node")
    edge_concentration = _concentration(atlas, "edge")
    if len(node_concentration) + len(edge_concentration) > active.max_structures:
        raise ValueError(
            "exposure review exceeds structural concentration ceiling"
        )

    remediation_counts = Counter(
        item.status.value for item in remediation_findings
    )
    retest_counts = Counter(
        item.last_retest_state
        for item in remediation_findings
        if item.last_retest_state is not None
    )

    return ExposureReview(
        paths=path_rows,
        evidence_gaps=tuple(sorted(
            gaps,
            key=lambda item: (
                item.gap_type,
                item.subject_id,
                item.detail,
                item.candidate_count,
            ),
        )),
        node_concentration=node_concentration,
        edge_concentration=edge_concentration,
        remediation_status_counts=tuple(sorted(remediation_counts.items())),
        retest_state_counts=tuple(sorted(retest_counts.items())),
    )


def compare_path_sets(
    before: AttackPathAtlas,
    after: AttackPathAtlas,
) -> PathSetChange:
    before_ids = {item.path_id for item in before.paths}
    after_ids = {item.path_id for item in after.paths}
    return PathSetChange(
        before_count=len(before_ids),
        after_count=len(after_ids),
        removed_path_ids=tuple(sorted(before_ids - after_ids)),
        retained_path_ids=tuple(sorted(before_ids & after_ids)),
        added_path_ids=tuple(sorted(after_ids - before_ids)),
    )
