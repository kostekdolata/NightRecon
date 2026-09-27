"""Red Night engine package namespace skeleton.

This namespace belongs to the Red Night distribution. During the migration
preview it contains packaging and ownership metadata only; existing assessment
implementations remain canonical under their established nightrecon module paths.
"""

from nightrecon_red_engine.compat import (
    LEGACY_NAMESPACE,
    NAMESPACE,
    existing_module,
    is_red_owned_module,
)

__all__ = [
    "LEGACY_NAMESPACE",
    "NAMESPACE",
    "existing_module",
    "is_red_owned_module",
]
