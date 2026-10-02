"""Compatibility alias for migrated Red Night network assessment bundle module."""

from importlib import import_module as _import_module
import sys as _sys

_module = _import_module("nightrecon_red_engine.network_assessment_bundle")
_sys.modules[__name__] = _module
