"""NightRecon stack-composition contracts.

Composition installs multiple independently useful Nights beside one shared core.
It must never create direct Night-to-Night runtime dependencies or implicit
authorization between Nights.
"""

from __future__ import annotations

from dataclasses import dataclass


SHARED_CORE_DISTRIBUTION = "nightrecon-shared-core"
REQUIRED_PRIVILEGE_POLICY = "required-platform-privileged"
HOST_DISK_POLICY = "no-automatic-mount"

RED_DISTRIBUTIONS = (
    "nightrecon-red-engine",
    "nightrecon-red-night",
)

WHITE_DISTRIBUTIONS = (
    "nightrecon-white-engine",
    "nightrecon-white-night",
)


@dataclass(frozen=True)
class StackCompositionProfile:
    profile_id: str
    nights: tuple[str, ...]
    required_distributions: tuple[str, ...]
    shared_contract_backend: str
    offline_capable: bool
    authorization_effect: str
    os_privilege_policy: str
    host_disk_policy: str
    direct_night_runtime_dependencies: bool = False

    def __post_init__(self) -> None:
        if not self.profile_id:
            raise ValueError("composition profile_id must not be empty")
        if len(self.nights) < 2:
            raise ValueError("composition requires at least two Nights")
        if len(self.nights) != len(set(self.nights)):
            raise ValueError("composition Nights must not contain duplicates")
        if len(self.required_distributions) != len(set(self.required_distributions)):
            raise ValueError("composition distributions must not contain duplicates")
        if self.required_distributions.count(SHARED_CORE_DISTRIBUTION) != 1:
            raise ValueError("composition must contain exactly one shared core")
        if self.shared_contract_backend != SHARED_CORE_DISTRIBUTION:
            raise ValueError("cross-Night composition must use shared-core contracts")
        if not self.offline_capable:
            raise ValueError("composition profiles must remain offline-capable")
        if self.authorization_effect != "none":
            raise ValueError("composition must never grant authorization")
        if self.os_privilege_policy != REQUIRED_PRIVILEGE_POLICY:
            raise ValueError("every composed Night must retain required OS privilege")
        if self.host_disk_policy != HOST_DISK_POLICY:
            raise ValueError("composition must not auto-mount host disks")
        if self.direct_night_runtime_dependencies:
            raise ValueError("Night-to-Night runtime dependencies are forbidden")

    def to_dict(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "nights": list(self.nights),
            "required_distributions": list(self.required_distributions),
            "shared_contract_backend": self.shared_contract_backend,
            "offline_capable": self.offline_capable,
            "authorization_effect": self.authorization_effect,
            "os_privilege_policy": self.os_privilege_policy,
            "host_disk_policy": self.host_disk_policy,
            "direct_night_runtime_dependencies": self.direct_night_runtime_dependencies,
        }


RED_WHITE_PROFILE = StackCompositionProfile(
    profile_id="red-white",
    nights=("red", "white"),
    required_distributions=(
        SHARED_CORE_DISTRIBUTION,
        *RED_DISTRIBUTIONS,
        *WHITE_DISTRIBUTIONS,
    ),
    shared_contract_backend=SHARED_CORE_DISTRIBUTION,
    offline_capable=True,
    authorization_effect="none",
    os_privilege_policy=REQUIRED_PRIVILEGE_POLICY,
    host_disk_policy=HOST_DISK_POLICY,
)


STACK_COMPOSITION_PROFILES = (
    RED_WHITE_PROFILE,
)


def composition_profile(profile_id: str) -> StackCompositionProfile:
    for profile in STACK_COMPOSITION_PROFILES:
        if profile.profile_id == profile_id:
            return profile
    raise ValueError(f"unknown NightRecon composition profile: {profile_id}")


def validate_stack_composition_contract() -> None:
    if RED_WHITE_PROFILE.nights != ("red", "white"):
        raise ValueError("Red+White composition identity has drifted")
    expected = (
        SHARED_CORE_DISTRIBUTION,
        *RED_DISTRIBUTIONS,
        *WHITE_DISTRIBUTIONS,
    )
    if RED_WHITE_PROFILE.required_distributions != expected:
        raise ValueError("Red+White composition package set has drifted")
    if RED_WHITE_PROFILE.direct_night_runtime_dependencies:
        raise ValueError("Red+White composition must not create cross-Night dependencies")


validate_stack_composition_contract()
