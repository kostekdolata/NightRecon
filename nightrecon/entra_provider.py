"""Compatibility alias for migrated Red Night entra provider module."""

from importlib import import_module as _import_module
import sys as _sys

_module = _import_module("nightrecon_red_engine.entra_provider")
_sys.modules[__name__] = _module
