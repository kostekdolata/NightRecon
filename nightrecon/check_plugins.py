"""Installed assessment-check discovery for NightRecon."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Iterable

from nightrecon.assessment_engine import AssessmentCheck


CHECK_ENTRYPOINT_GROUP = "nightrecon.checks"


@dataclass(frozen=True)
class CheckDiscoveryResult:
    """Installed checks and any isolated plugin-load errors."""

    checks: tuple[AssessmentCheck, ...] = ()
    errors: tuple[str, ...] = ()


def discover_installed_checks(
    *,
    group: str = CHECK_ENTRYPOINT_GROUP,
) -> CheckDiscoveryResult:
    """Discover installed check plugins through Python entry points."""

    discovered: list[AssessmentCheck] = []
    errors: list[str] = []

    available = entry_points().select(
        group=group
    )

    for entrypoint in sorted(
        available,
        key=lambda item: item.name,
    ):
        try:
            loaded = entrypoint.load()
            candidates = _normalize_plugin_object(
                loaded
            )

            if candidates is None:
                raise ValueError(
                    "plugin did not provide assessment checks"
                )

            for check in candidates:
                if not _is_check(check):
                    raise ValueError(
                        "plugin did not provide assessment checks"
                    )

                discovered.append(check)
        except Exception as exc:
            errors.append(
                f"{entrypoint.name}: "
                f"{str(exc) or exc.__class__.__name__}"
            )

    discovered.sort(
        key=lambda check: check.metadata.check_id
    )

    return CheckDiscoveryResult(
        checks=tuple(discovered),
        errors=tuple(errors),
    )


def _normalize_plugin_object(
    loaded: object,
) -> tuple[object, ...] | None:
    if _is_check(loaded):
        return (loaded,)

    if callable(loaded):
        produced = loaded()
        return _normalize_plugin_object(
            produced
        )

    if isinstance(loaded, (tuple, list)):
        return tuple(loaded)

    return None


def _is_check(
    value: object,
) -> bool:
    return (
        hasattr(value, "metadata")
        and callable(
            getattr(value, "run", None)
        )
    )
