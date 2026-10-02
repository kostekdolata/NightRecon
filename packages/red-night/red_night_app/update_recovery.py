"""Fail-closed Red Night update staging and rollback planning contracts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RedUpdateRecoveryPlan:
    current_version: str
    target_version: str
    workspace_policy: str
    max_unconfirmed_boots: int
    stage_steps: tuple[str, ...]
    rollback_steps: tuple[str, ...]
    authorization_effect: str = "none"

    def __post_init__(self) -> None:
        if not self.current_version or not self.target_version:
            raise ValueError("update versions must be nonblank")
        if self.current_version == self.target_version:
            raise ValueError("target version must differ from current version")
        if self.workspace_policy != "preserve-encrypted-workspace":
            raise ValueError("updates must preserve the encrypted workspace")
        if self.max_unconfirmed_boots != 1:
            raise ValueError("Red update rollback must allow only one unconfirmed boot")
        if self.authorization_effect != "none":
            raise ValueError("update planning must not grant target authorization")

    def to_dict(self) -> dict[str, object]:
        return {
            "current_version": self.current_version,
            "target_version": self.target_version,
            "workspace_policy": self.workspace_policy,
            "max_unconfirmed_boots": self.max_unconfirmed_boots,
            "stage_steps": list(self.stage_steps),
            "rollback_steps": list(self.rollback_steps),
            "authorization_effect": self.authorization_effect,
        }


def build_red_update_recovery_plan(
    *,
    current_version: str,
    target_version: str,
    signed_bundle_verified: bool,
    package_compatibility_verified: bool,
    workspace_locked: bool,
    rollback_artifact_verified: bool,
) -> RedUpdateRecoveryPlan:
    """Create a bounded update plan only after every safety prerequisite passes."""

    prerequisites = (
        (signed_bundle_verified, "signed update bundle is not verified"),
        (package_compatibility_verified, "package/schema compatibility is not verified"),
        (workspace_locked, "encrypted workspace must be locked before staging"),
        (rollback_artifact_verified, "rollback artifact is not verified"),
    )
    for passed, reason in prerequisites:
        if not passed:
            raise ValueError(reason)

    return RedUpdateRecoveryPlan(
        current_version=current_version,
        target_version=target_version,
        workspace_policy="preserve-encrypted-workspace",
        max_unconfirmed_boots=1,
        stage_steps=(
            "verify-signed-bundle",
            "verify-package-and-schema-compatibility",
            "verify-encrypted-workspace-locked",
            "verify-rollback-artifact",
            "stage-immutable-system-image",
            "reboot-into-staged-image",
            "verify-post-boot-integrity-and-migrations",
            "explicitly-confirm-new-image",
        ),
        rollback_steps=(
            "detect-unconfirmed-or-failed-boot",
            "select-previous-verified-image",
            "preserve-encrypted-workspace",
            "reboot-into-previous-image",
            "verify-previous-image-integrity",
        ),
    )
