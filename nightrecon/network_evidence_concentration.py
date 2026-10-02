"""Compatibility alias for migrated Red Night network evidence concentration module."""

from importlib import import_module as _import_module
import sys as _sys

_module = _import_module("nightrecon_red_engine.network_evidence_concentration")
_sys.modules[__name__] = _module
