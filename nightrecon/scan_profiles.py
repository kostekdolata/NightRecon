"""Compatibility alias for migrated Red Night scan timing profiles."""

from importlib import import_module as _import_module
import sys as _sys

_module = _import_module("nightrecon_red_engine.scan_profiles")
_sys.modules[__name__] = _module
