"""Red Night engine package.

The package owns migrated Red engine modules. Legacy nightrecon module paths may
re-export these implementations during the compatibility window.
"""

from nightrecon_red_engine.compat import (
    LEGACY_NAMESPACE,
    MIGRATED_MODULES,
    NAMESPACE,
    existing_module,
    is_migrated_module,
    is_red_owned_module,
)

__all__ = [
    "LEGACY_NAMESPACE",
    "MIGRATED_MODULES",
    "NAMESPACE",
    "existing_module",
    "is_migrated_module",
    "is_red_owned_module",
]
