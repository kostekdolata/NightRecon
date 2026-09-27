"""Compatibility exports from the independently installable shared core."""

from nightrecon_shared_core.editions import (
    EDITIONS,
    Edition,
    EditionRouteError,
    available_commands,
    edition_name,
)

__all__ = [
    "EDITIONS",
    "Edition",
    "EditionRouteError",
    "available_commands",
    "edition_name",
]
