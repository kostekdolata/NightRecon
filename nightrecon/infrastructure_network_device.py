"""Compatibility alias for migrated Red Night infrastructure network device module."""

from importlib import import_module as _import_module
import sys as _sys

_module = _import_module("nightrecon_red_engine.infrastructure_network_device")
_sys.modules[__name__] = _module
