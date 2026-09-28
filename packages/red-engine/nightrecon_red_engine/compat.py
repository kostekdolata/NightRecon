"""Compatibility helpers for staged Red Night package separation."""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

NAMESPACE = "nightrecon_red_engine"
LEGACY_NAMESPACE = "nightrecon"

MIGRATED_MODULES = frozenset({
    "api_models",
    "discovery_report",
    "graph_models",
    "host_discovery",
    "infrastructure_models",
    "ports",
    "resolver",
    "service_fingerprint",
    "service_probe",
    "session",
    "software_identity",
    "tcp_scanner",
    "tls_detection",
})


def is_migrated_module(module_name: str) -> bool:
    return isinstance(module_name, str) and module_name.strip() in MIGRATED_MODULES


def is_red_owned_module(module_name: str) -> bool:
    """Compatibility alias for the Batch A namespace API."""

    return is_migrated_module(module_name)


def existing_module(module_name: str) -> ModuleType:
    """Return a migrated Red module from its canonical Red engine namespace."""

    if not isinstance(module_name, str) or not module_name.strip():
        raise ValueError("module_name must be a nonblank string")
    normalized = module_name.strip()
    if normalized not in MIGRATED_MODULES:
        raise ValueError(f"module is not migrated to Red engine: {normalized}")
    return import_module(f"{NAMESPACE}.{normalized}")
