"""Fail-closed Red Night composition compatibility contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from nightrecon_shared_core.contracts import SCHEMA_VERSION as ENGAGEMENT_SCHEMA_VERSION

RED_STACK_VERSION = "0.43.0"
SUPPORTED_ENGAGEMENT_SCHEMA_VERSIONS = (ENGAGEMENT_SCHEMA_VERSION,)
RED_REQUIRED_PACKAGE_VERSIONS = {
    "nightrecon-shared-core": RED_STACK_VERSION,
    "nightrecon-red-engine": RED_STACK_VERSION,
    "nightrecon-red-night": RED_STACK_VERSION,
}


@dataclass(frozen=True)
class RedCompositionCompatibility:
    compatible: bool
    reason_code: str
    reason: str
    red_stack_version: str
    engagement_schema_version: int
    package_versions: tuple[tuple[str, str], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "compatible": self.compatible,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "red_stack_version": self.red_stack_version,
            "engagement_schema_version": self.engagement_schema_version,
            "package_versions": [
                {"distribution": name, "version": version}
                for name, version in self.package_versions
            ],
            "authorization_effect": "none",
        }


def evaluate_red_composition_compatibility(
    installed_versions: Mapping[str, str],
    *,
    engagement_schema_version: int = ENGAGEMENT_SCHEMA_VERSION,
) -> RedCompositionCompatibility:
    """Validate Red package/schema compatibility without granting authority."""

    if not isinstance(installed_versions, Mapping):
        raise ValueError("installed_versions must be a mapping")

    normalized: list[tuple[str, str]] = []
    for distribution, expected in RED_REQUIRED_PACKAGE_VERSIONS.items():
        actual = installed_versions.get(distribution)
        if not isinstance(actual, str) or not actual.strip():
            return RedCompositionCompatibility(
                compatible=False,
                reason_code="missing-red-package",
                reason=f"Required Red distribution is missing: {distribution}.",
                red_stack_version=RED_STACK_VERSION,
                engagement_schema_version=engagement_schema_version,
                package_versions=tuple(normalized),
            )
        normalized.append((distribution, actual))
        if actual != expected:
            return RedCompositionCompatibility(
                compatible=False,
                reason_code="red-package-version-mismatch",
                reason=(
                    f"{distribution} version {actual} is incompatible with "
                    f"the Red stack version {expected}."
                ),
                red_stack_version=RED_STACK_VERSION,
                engagement_schema_version=engagement_schema_version,
                package_versions=tuple(normalized),
            )

    if engagement_schema_version not in SUPPORTED_ENGAGEMENT_SCHEMA_VERSIONS:
        return RedCompositionCompatibility(
            compatible=False,
            reason_code="unsupported-engagement-schema",
            reason=(
                "Shared engagement schema version "
                f"{engagement_schema_version} is not supported by this Red stack."
            ),
            red_stack_version=RED_STACK_VERSION,
            engagement_schema_version=engagement_schema_version,
            package_versions=tuple(normalized),
        )

    return RedCompositionCompatibility(
        compatible=True,
        reason_code="compatible",
        reason="Red package and shared engagement schema contracts are compatible.",
        red_stack_version=RED_STACK_VERSION,
        engagement_schema_version=engagement_schema_version,
        package_versions=tuple(normalized),
    )
