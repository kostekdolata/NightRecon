"""Compatibility alias for migrated Red Night threat context module."""

from importlib import import_module as _import_module
import sys as _sys

_module = _import_module("nightrecon_red_engine.threat_context")
_sys.modules[__name__] = _module
