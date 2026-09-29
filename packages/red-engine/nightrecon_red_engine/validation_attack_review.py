"""Reviewed ATT&CK relationship metadata for controlled validation.

The registry records whether a NightRecon validation proof is behaviorally
related to an ATT&CK technique or has been explicitly reviewed and left
unmapped. A related record is not an equivalence or implementation claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import re
from typing import Iterable

from nightrecon_red_engine.validation_techniques import (
    BUILTIN_VALIDATION_TECHNIQUE_REGISTRY,
    ValidationTechniqueRegistry,
)


_ATTACK_ID_RE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_VALID_DISPOSITIONS = frozenset({"related", "reviewed-unmapped"})
ATTACK_REVIEW_INTERPRETATION = (
    "ATT&CK relationships are reviewed descriptive metadata. 'related' means "
    "the proof has a bounded behavioral relationship to the referenced ATT&CK "
    "technique; it does not mean NightRecon implements the complete adversary "
    "technique, procedure, tactic, or specialist-emulation capability."
)


def _required(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


@dataclass(frozen=True, order=True)
class AttackTechniqueReference:
    attack_id: str
    name: str
    tactic: str
    version: str
    last_modified: str
    source_url: str

    def __post_init__(self) -> None:
        if _ATTACK_ID_RE.fullmatch(_required(self.attack_id, "attack_id")) is None:
            raise ValueError("attack_id must be a canonical ATT&CK technique ID")
        _required(self.name, "name")
        _required(self.tactic, "tactic")
        _required(self.version, "version")
        _required(self.source_url, "source_url")
        if not self.source_url.startswith("https://attack.mitre.org/"):
            raise ValueError("ATT&CK source must use the official MITRE ATT&CK site")
        try:
            date.fromisoformat(self.last_modified)
        except (TypeError, ValueError) as exc:
            raise ValueError("last_modified must be an ISO date") from exc

    def to_dict(self) -> dict[str, str]:
        return {
            "attack_id": self.attack_id,
            "name": self.name,
            "tactic": self.tactic,
            "version": self.version,
            "last_modified": self.last_modified,
            "source_url": self.source_url,
        }


@dataclass(frozen=True)
class ValidationAttackReview:
    technique_id: str
    disposition: str
    references: tuple[AttackTechniqueReference, ...]
    rationale: str
    reviewed_at: str
    interpretation: str = ATTACK_REVIEW_INTERPRETATION

    def __post_init__(self) -> None:
        _required(self.technique_id, "technique_id")
        if self.disposition not in _VALID_DISPOSITIONS:
            raise ValueError("ATT&CK review disposition is not supported")
        _required(self.rationale, "rationale")
        try:
            date.fromisoformat(self.reviewed_at)
        except (TypeError, ValueError) as exc:
            raise ValueError("reviewed_at must be an ISO date") from exc
        ids = tuple(item.attack_id for item in self.references)
        if len(ids) != len(set(ids)):
            raise ValueError("ATT&CK references must not repeat technique IDs")
        if self.disposition == "related" and not self.references:
            raise ValueError("related ATT&CK reviews require a reference")
        if self.disposition == "reviewed-unmapped" and self.references:
            raise ValueError("reviewed-unmapped techniques must not carry references")

    @property
    def attack_ids(self) -> tuple[str, ...]:
        return tuple(item.attack_id for item in self.references)

    def to_dict(self) -> dict[str, object]:
        return {
            "technique_id": self.technique_id,
            "disposition": self.disposition,
            "attack_ids": list(self.attack_ids),
            "references": [item.to_dict() for item in self.references],
            "rationale": self.rationale,
            "reviewed_at": self.reviewed_at,
            "equivalence_claim": False,
            "interpretation": self.interpretation,
        }


class ValidationAttackReviewRegistry:
    def __init__(self, reviews: Iterable[ValidationAttackReview]):
        ordered = tuple(sorted(tuple(reviews), key=lambda item: item.technique_id))
        ids = tuple(item.technique_id for item in ordered)
        if len(ids) != len(set(ids)):
            raise ValueError("ATT&CK reviews must be unique per technique")
        self._reviews = ordered
        self._by_technique = {item.technique_id: item for item in ordered}

    def list(self) -> tuple[ValidationAttackReview, ...]:
        return self._reviews

    def get(self, technique_id: str) -> ValidationAttackReview:
        _required(technique_id, "technique_id")
        try:
            return self._by_technique[technique_id]
        except KeyError as exc:
            raise ValueError(
                f"no reviewed ATT&CK relationship for technique: {technique_id}"
            ) from exc


T1046_REFERENCE = AttackTechniqueReference(
    attack_id="T1046",
    name="Network Service Discovery",
    tactic="Discovery",
    version="3.2",
    last_modified="2026-05-12",
    source_url="https://attack.mitre.org/techniques/T1046/",
)

BUILTIN_VALIDATION_ATTACK_REVIEWS = (
    ValidationAttackReview(
        technique_id="service.tcp-property-proof",
        disposition="related",
        references=(T1046_REFERENCE,),
        rationale=(
            "The bounded proof establishes whether one already-selected TCP "
            "service accepts a connection. That is related to Network Service "
            "Discovery evidence, but it does not enumerate a host/range or "
            "implement the full T1046 discovery behavior."
        ),
        reviewed_at="2026-09-29",
    ),
    ValidationAttackReview(
        technique_id="service.tls-property-proof",
        disposition="reviewed-unmapped",
        references=(),
        rationale=(
            "The TLS proof confirms transport metadata and an already-observed "
            "certificate fingerprint. No exact Enterprise ATT&CK adversary "
            "behavior is claimed for this validation-only action."
        ),
        reviewed_at="2026-09-29",
    ),
    ValidationAttackReview(
        technique_id="web.http-policy-proof",
        disposition="reviewed-unmapped",
        references=(),
        rationale=(
            "The fixed HTTP HEAD proof observes response-policy metadata for an "
            "already-selected origin. It is validation evidence rather than an "
            "exact ATT&CK adversary technique implementation."
        ),
        reviewed_at="2026-09-29",
    ),
)

BUILTIN_VALIDATION_ATTACK_REVIEW_REGISTRY = ValidationAttackReviewRegistry(
    BUILTIN_VALIDATION_ATTACK_REVIEWS
)


def assert_attack_review_coverage(
    *,
    review_registry: ValidationAttackReviewRegistry = (
        BUILTIN_VALIDATION_ATTACK_REVIEW_REGISTRY
    ),
    technique_registry: ValidationTechniqueRegistry = (
        BUILTIN_VALIDATION_TECHNIQUE_REGISTRY
    ),
) -> None:
    """Require one reviewed disposition for every built-in technique."""

    techniques = technique_registry.list()
    reviews = review_registry.list()
    technique_ids = tuple(item.technique_id for item in techniques)
    review_ids = tuple(item.technique_id for item in reviews)
    if technique_ids != review_ids:
        raise ValueError("ATT&CK review coverage does not match technique registry")

    for technique in techniques:
        review = review_registry.get(technique.technique_id)
        if technique.attack_ids != review.attack_ids:
            raise ValueError(
                "technique ATT&CK IDs do not match reviewed relationship metadata"
            )


assert_attack_review_coverage()
