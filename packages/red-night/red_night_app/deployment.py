"""Red Night deployment-profile contracts.

These profiles describe how the same Red Night application/engine/shared-core
packages are expected to compose in normal standalone installations, a composed
NightRecon stack, and a future Red Night Live USB image.

The module is intentionally declarative. It performs no boot-media creation,
mounting, network activity, authorization, or cross-Night imports.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


RED_REQUIRED_DISTRIBUTIONS = (
    "nightrecon-shared-core",
    "nightrecon-red-engine",
    "nightrecon-red-night",
)

OTHER_NIGHT_SLUGS = ("white", "blue", "purple", "black")
FORBIDDEN_NIGHT_RUNTIME_PREFIXES = (
    "nightrecon_white_engine",
    "white_night_app",
    "nightrecon_blue_engine",
    "blue_night_app",
    "nightrecon_purple_engine",
    "purple_night_app",
    "nightrecon_black_engine",
    "black_night_app",
)


class RedDeploymentMode(str, Enum):
    STANDALONE = "standalone"
    COMPOSED = "composed"
    LIVE_USB = "live-usb"


@dataclass(frozen=True)
class RedDeploymentProfile:
    """Declarative deployment contract for one Red Night product shape."""

    mode: RedDeploymentMode
    required_distributions: tuple[str, ...]
    optional_peer_nights: tuple[str, ...]
    workspace_modes: tuple[str, ...]
    offline_capable: bool
    bootable_media: bool
    host_disk_policy: str = "no-automatic-mount"
    dependency_rule: str = "red-app->red-engine->shared-core"
    os_privilege_policy: str = "required-platform-privileged"

    def __post_init__(self) -> None:
        if self.required_distributions != RED_REQUIRED_DISTRIBUTIONS:
            raise ValueError(
                "all Red deployment profiles must use the same Red package set"
            )
        if len(self.optional_peer_nights) != len(set(self.optional_peer_nights)):
            raise ValueError("optional_peer_nights must not contain duplicates")
        if any(item not in OTHER_NIGHT_SLUGS for item in self.optional_peer_nights):
            raise ValueError("optional_peer_nights contains an unknown Night")
        if not self.workspace_modes:
            raise ValueError("workspace_modes must not be empty")
        if len(self.workspace_modes) != len(set(self.workspace_modes)):
            raise ValueError("workspace_modes must not contain duplicates")
        if self.host_disk_policy != "no-automatic-mount":
            raise ValueError("Red deployment must not auto-mount host disks")
        if self.dependency_rule != "red-app->red-engine->shared-core":
            raise ValueError("Red dependency direction is fixed")
        if not self.offline_capable:
            raise ValueError("Red deployment profiles must not require Internet access")
        if self.os_privilege_policy != "required-platform-privileged":
            raise ValueError("every Red deployment profile must require privileged OS execution")
        if self.mode is RedDeploymentMode.LIVE_USB and not self.bootable_media:
            raise ValueError("live-usb profile must be bootable media")
        if self.mode is not RedDeploymentMode.LIVE_USB and self.bootable_media:
            raise ValueError("non-Live profiles must not claim bootable-media behavior")

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode.value,
            "required_distributions": list(self.required_distributions),
            "optional_peer_nights": list(self.optional_peer_nights),
            "workspace_modes": list(self.workspace_modes),
            "offline_capable": self.offline_capable,
            "bootable_media": self.bootable_media,
            "host_disk_policy": self.host_disk_policy,
            "dependency_rule": self.dependency_rule,
            "os_privilege_policy": self.os_privilege_policy,
        }


RED_STANDALONE_PROFILE = RedDeploymentProfile(
    mode=RedDeploymentMode.STANDALONE,
    required_distributions=RED_REQUIRED_DISTRIBUTIONS,
    optional_peer_nights=(),
    workspace_modes=("local-persistent",),
    offline_capable=True,
    bootable_media=False,
)

RED_COMPOSED_PROFILE = RedDeploymentProfile(
    mode=RedDeploymentMode.COMPOSED,
    required_distributions=RED_REQUIRED_DISTRIBUTIONS,
    optional_peer_nights=OTHER_NIGHT_SLUGS,
    workspace_modes=("shared-contract-backend", "local-persistent"),
    offline_capable=True,
    bootable_media=False,
)

RED_LIVE_USB_PROFILE = RedDeploymentProfile(
    mode=RedDeploymentMode.LIVE_USB,
    required_distributions=RED_REQUIRED_DISTRIBUTIONS,
    optional_peer_nights=(),
    workspace_modes=(
        "secure-workspace",
        "ephemeral-session",
        "recovery-integrity",
    ),
    offline_capable=True,
    bootable_media=True,
)


RED_DEPLOYMENT_PROFILES = (
    RED_STANDALONE_PROFILE,
    RED_COMPOSED_PROFILE,
    RED_LIVE_USB_PROFILE,
)


def deployment_profile(mode: RedDeploymentMode | str) -> RedDeploymentProfile:
    selected = RedDeploymentMode(mode)
    for profile in RED_DEPLOYMENT_PROFILES:
        if profile.mode is selected:
            return profile
    raise ValueError(f"unsupported Red deployment mode: {selected.value}")


def validate_red_deployment_contract() -> None:
    """Fail closed if the three Red product shapes drift apart."""

    if tuple(item.mode for item in RED_DEPLOYMENT_PROFILES) != tuple(
        RedDeploymentMode
    ):
        raise ValueError("Red deployment profiles do not cover every mode")
    if any(
        item.required_distributions != RED_REQUIRED_DISTRIBUTIONS
        for item in RED_DEPLOYMENT_PROFILES
    ):
        raise ValueError("Red deployment package parity has drifted")
    if RED_COMPOSED_PROFILE.optional_peer_nights != OTHER_NIGHT_SLUGS:
        raise ValueError("composed Red profile peer-Night contract has drifted")
    if RED_STANDALONE_PROFILE.optional_peer_nights:
        raise ValueError("standalone Red must not require peer Nights")
    if RED_LIVE_USB_PROFILE.optional_peer_nights:
        raise ValueError("Red-only Live USB must not require peer Nights")
    if any(
        item.os_privilege_policy != "required-platform-privileged"
        for item in RED_DEPLOYMENT_PROFILES
    ):
        raise ValueError("Red OS privilege policy has drifted across deployment modes")


validate_red_deployment_contract()
