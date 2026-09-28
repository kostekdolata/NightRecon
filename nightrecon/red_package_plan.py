"""Static package-plan helpers for Red Night migration.

This module describes the current bridge and future direct package boundary. It
does not import or execute assessment engines.
"""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon.red_ownership import (
    RED_BASE_DEPENDENCIES,
    RED_ENGINE_DISTRIBUTION_DEPENDENCY,
    RED_LEGACY_BRIDGE_DEPENDENCY,
    RED_OPTIONAL_EXTRAS,
    red_package_modules,
)


@dataclass(frozen=True)
class RedPackagePlan:
    module_names: tuple[str, ...]
    base_dependencies: tuple[str, ...]
    optional_extras: tuple[tuple[str, tuple[str, ...]], ...]
    engine_distribution_dependency: str
    legacy_bridge_dependency: str

    @property
    def ready_to_remove_legacy_bridge(self) -> bool:
        return False


def current_red_package_plan() -> RedPackagePlan:
    return RedPackagePlan(
        module_names=red_package_modules(),
        base_dependencies=RED_BASE_DEPENDENCIES,
        optional_extras=tuple(sorted(RED_OPTIONAL_EXTRAS.items())),
        engine_distribution_dependency=RED_ENGINE_DISTRIBUTION_DEPENDENCY,
        legacy_bridge_dependency=RED_LEGACY_BRIDGE_DEPENDENCY,
    )
