"""Compatibility contract for staged Red Night package separation.

No assessment engine is implemented here. The helper only resolves modules that
are already declared Red-owned by the canonical ownership manifest.
"""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

from nightrecon.red_ownership import red_modules


NAMESPACE = "nightrecon_red_engine"
LEGACY_NAMESPACE = "nightrecon"


def is_red_owned_module(module_name: str) -> bool:
    return module_name in set(red_modules())


def existing_module(module_name: str) -> ModuleType:
    """Return an existing Red-owned module from its established legacy path."""

    if not isinstance(module_name, str) or not module_name.strip():
        raise ValueError("module_name must be a nonblank string")
    if not is_red_owned_module(module_name):
        raise ValueError(f"module is not declared Red-owned: {module_name}")
    return import_module(f"{LEGACY_NAMESPACE}.{module_name}")
