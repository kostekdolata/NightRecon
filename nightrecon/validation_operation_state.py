"""Compatibility alias for migrated Red Night validation operation state module."""

from importlib import import_module as _import_module
import sys as _sys

_module = _import_module("nightrecon_red_engine.validation_operation_state")
_sys.modules[__name__] = _module
