"""Compatibility alias for the canonical Red Night CLI composition."""

from importlib import import_module as _import_module
import sys as _sys

_module = _import_module("nightrecon_red_engine.red_cli")
_sys.modules[__name__] = _module
