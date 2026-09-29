"""Reviewed metadata-only controlled-validation technique registry.

v0.43 Batch 1 defines symbolic technique metadata that can be reviewed before
any adapter is wired to it. The registry contains no payloads, command text,
scripts, credentials, exploit instructions, or automatic execution path.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Iterable

from nightrecon_red_engine.controlled_validation import ValidationDefinition


_VALID_IMPACTS = frozenset({"low", "standard", "high"})
_VALID_TARGET_KINDS = frozenset({"asset", "service", "web", "api"})
_VALID_ADAPTER_KINDS = frozenset({"read-only-proof"})
_VALID_CLEANUP_MODES = frozenset({"none"})
_SECRET_LIKE_EVIDENCE_FRAGMENTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "cookie",
    "authorization",
    "api_key",
    "apikey",
    "private_key",
    "session",
)

_TECHNIQUE_ID_RE = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")
_EVIDENCE_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ATTACK_ID_RE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")


def _required(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


def _unique(values: tuple[str, ...], field: str) -> tuple[str, ...]:
    if len(values) != len(set(values)):
        raise ValueError(f"{field} must not contain duplicates")
    return values


@dataclass(frozen=True, order=True)
class ValidationTechniqueDefinition:
    """Symbolic reviewed metadata for one controlled-validation technique."""

    technique_id: str
    title: str
    summary: str
    target_kinds: tuple[str, ...]
    evidence_keys: tuple[str, ...]
    eligibility_required_properties: tuple[str, ...] = ()
    eligibility_required_values: tuple[tuple[str, str], ...] = ()
    impact: str = "standard"
    requires_approval: bool = False
    attack_ids: tuple[str, ...] = ()
    adapter_kind: str = "read-only-proof"
    cleanup_mode: str = "none"

    def __post_init__(self) -> None:
        _required(self.technique_id, "technique_id")
        _required(self.title, "title")
        _required(self.summary, "summary")

        if not _TECHNIQUE_ID_RE.fullmatch(self.technique_id):
            raise ValueError("technique_id must be lowercase canonical metadata")
        if self.impact not in _VALID_IMPACTS:
            raise ValueError("impact must be low, standard, or high")
        if type(self.requires_approval) is not bool:
            raise ValueError("requires_approval must be boolean")
        if self.impact == "high" and not self.requires_approval:
            raise ValueError("high-impact techniques must require approval")
        if self.adapter_kind not in _VALID_ADAPTER_KINDS:
            raise ValueError("adapter_kind is not allowed")
        if self.cleanup_mode not in _VALID_CLEANUP_MODES:
            raise ValueError("cleanup_mode is not allowed in Batch 1")

        if not self.target_kinds:
            raise ValueError("target_kinds must not be empty")
        _unique(self.target_kinds, "target_kinds")
        for target_kind in self.target_kinds:
            if target_kind not in _VALID_TARGET_KINDS:
                raise ValueError(f"unsupported target kind: {target_kind}")

        if not self.evidence_keys:
            raise ValueError("evidence_keys must not be empty")
        _unique(self.evidence_keys, "evidence_keys")
        for key in self.evidence_keys:
            if not _EVIDENCE_KEY_RE.fullmatch(key):
                raise ValueError(f"invalid evidence key: {key}")
            lowered = key.lower()
            if any(
                fragment in lowered
                for fragment in _SECRET_LIKE_EVIDENCE_FRAGMENTS
            ):
                raise ValueError(
                    f"secret-like evidence key is not allowed: {key}"
                )

        _unique(
            self.eligibility_required_properties,
            "eligibility_required_properties",
        )
        for key in self.eligibility_required_properties:
            if not _EVIDENCE_KEY_RE.fullmatch(key):
                raise ValueError(
                    f"invalid eligibility property key: {key}"
                )
            lowered = key.lower()
            if any(
                fragment in lowered
                for fragment in _SECRET_LIKE_EVIDENCE_FRAGMENTS
            ):
                raise ValueError(
                    "secret-like eligibility property is not allowed: "
                    f"{key}"
                )

        eligibility_value_keys: list[str] = []
        for key, value in self.eligibility_required_values:
            if not _EVIDENCE_KEY_RE.fullmatch(key):
                raise ValueError(
                    f"invalid eligibility value key: {key}"
                )
            if not isinstance(value, str) or not value or value != value.strip():
                raise ValueError(
                    "eligibility required values must be nonblank "
                    "trimmed strings"
                )
            lowered = key.lower()
            if any(
                fragment in lowered
                for fragment in _SECRET_LIKE_EVIDENCE_FRAGMENTS
            ):
                raise ValueError(
                    f"secret-like eligibility value key is not allowed: {key}"
                )
            eligibility_value_keys.append(key)
        if len(eligibility_value_keys) != len(set(eligibility_value_keys)):
            raise ValueError(
                "eligibility_required_values must not repeat keys"
            )
        if set(self.eligibility_required_properties).intersection(
            eligibility_value_keys
        ):
            raise ValueError(
                "eligibility property names must not be duplicated across "
                "presence and exact-value requirements"
            )

        _unique(self.attack_ids, "attack_ids")
        for attack_id in self.attack_ids:
            if not _ATTACK_ID_RE.fullmatch(attack_id):
                raise ValueError(f"invalid ATT&CK technique id: {attack_id}")

    def to_dict(self) -> dict[str, object]:
        return {
            "technique_id": self.technique_id,
            "title": self.title,
            "summary": self.summary,
            "target_kinds": list(self.target_kinds),
            "evidence_keys": list(self.evidence_keys),
            "eligibility_required_properties": list(
                self.eligibility_required_properties
            ),
            "eligibility_required_values": [
                [key, value]
                for key, value in self.eligibility_required_values
            ],
            "impact": self.impact,
            "requires_approval": self.requires_approval,
            "attack_ids": list(self.attack_ids),
            "adapter_kind": self.adapter_kind,
            "cleanup_mode": self.cleanup_mode,
        }


class ValidationTechniqueRegistry:
    """Immutable deterministic registry of reviewed symbolic techniques."""

    def __init__(self, techniques: Iterable[ValidationTechniqueDefinition]):
        ordered = tuple(sorted(tuple(techniques), key=lambda item: item.technique_id))
        ids = tuple(item.technique_id for item in ordered)
        if len(ids) != len(set(ids)):
            raise ValueError("validation technique ids must be unique")
        self._techniques = ordered
        self._by_id = {item.technique_id: item for item in ordered}

    def list(self) -> tuple[ValidationTechniqueDefinition, ...]:
        return self._techniques

    def get(self, technique_id: str) -> ValidationTechniqueDefinition:
        _required(technique_id, "technique_id")
        try:
            return self._by_id[technique_id]
        except KeyError as exc:
            raise ValueError(f"unknown validation technique: {technique_id}") from exc


BUILTIN_VALIDATION_TECHNIQUES = (
    ValidationTechniqueDefinition(
        technique_id="service.tcp-property-proof",
        title="TCP service property proof",
        summary=(
            "Read-only confirmation of an already selected TCP service property "
            "through a fixed controlled-validation adapter."
        ),
        target_kinds=("service",),
        evidence_keys=("transport", "port", "state"),
        eligibility_required_properties=("address", "port"),
        eligibility_required_values=(("protocol", "tcp"),),
        impact="standard",
        attack_ids=("T1046",),
    ),
    ValidationTechniqueDefinition(
        technique_id="service.tls-property-proof",
        title="TLS transport property proof",
        summary=(
            "Read-only confirmation of selected TLS transport metadata through "
            "a fixed controlled-validation adapter."
        ),
        target_kinds=("service",),
        evidence_keys=("tls_version", "cipher", "certificate_sha256"),
        eligibility_required_properties=(
            "address",
            "port",
            "tls_certificate_sha256",
        ),
        eligibility_required_values=(("protocol", "tcp"),),
        impact="standard",
    ),
    ValidationTechniqueDefinition(
        technique_id="web.http-policy-proof",
        title="HTTP response policy proof",
        summary=(
            "Read-only confirmation of selected HTTP response policy metadata "
            "through a fixed controlled-validation adapter."
        ),
        target_kinds=("web", "api"),
        evidence_keys=("status_code", "security_headers"),
        eligibility_required_properties=(
            "origin_host",
            "origin_port",
            "origin_scheme",
        ),
        impact="standard",
    ),
)


BUILTIN_VALIDATION_TECHNIQUE_REGISTRY = ValidationTechniqueRegistry(
    BUILTIN_VALIDATION_TECHNIQUES
)


def build_validation_definition(
    technique: ValidationTechniqueDefinition,
    *,
    target: str,
) -> ValidationDefinition:
    """Create the existing runtime definition without executing an adapter."""

    normalized_target = _required(target, "target")
    material = f"{technique.technique_id}\x1f{normalized_target}".encode("utf-8")
    validation_id = "technique-" + sha256(material).hexdigest()
    return ValidationDefinition(
        validation_id=validation_id,
        target=normalized_target,
        title=technique.title,
        impact=technique.impact,
        requires_approval=technique.requires_approval,
    )
