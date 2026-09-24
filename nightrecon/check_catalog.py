"""Combined built-in and installed assessment-check catalog."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon.assessment_engine import (
    AssessmentCheck,
    CheckRegistry,
)
from nightrecon.builtin_checks import builtin_checks
from nightrecon.check_plugins import discover_installed_checks


@dataclass(frozen=True)
class CheckCatalogResult:
    """Available assessment checks plus isolated catalog errors."""

    checks: tuple[AssessmentCheck, ...] = ()
    errors: tuple[str, ...] = ()


def load_check_catalog(
    *,
    additional_checks: tuple[AssessmentCheck, ...] = (),
) -> CheckCatalogResult:
    """Load built-ins, installed plugins, and additional checks."""

    registry = CheckRegistry()
    errors: list[str] = []

    for check in builtin_checks():
        registry.register(check)

    discovery = discover_installed_checks()
    errors.extend(discovery.errors)

    for check in discovery.checks:
        try:
            registry.register(check)
        except ValueError as exc:
            errors.append(str(exc))

    for check in additional_checks:
        try:
            registry.register(check)
        except ValueError as exc:
            errors.append(str(exc))

    return CheckCatalogResult(
        checks=registry.all(),
        errors=tuple(errors),
    )
