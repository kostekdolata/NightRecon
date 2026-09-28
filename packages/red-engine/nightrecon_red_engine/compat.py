"""Compatibility helpers for staged Red Night package separation."""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

NAMESPACE = "nightrecon_red_engine"
LEGACY_NAMESPACE = "nightrecon"

MIGRATED_MODULES = frozenset({
    "api_execution",
    "api_graphql",
    "api_models",
    "api_openapi",
    "api_planner",
    "api_policy",
    "api_report",
    "api_validation_report",
    "assessment_engine",
    "browser_playwright",
    "browser_policy",
    "browser_report",
    "browser_worker",
    "builtin_checks",
    "check_catalog",
    "check_feed",
    "check_feed_state",
    "check_pack_manager",
    "check_pack_signing",
    "check_pack_store",
    "check_packs",
    "check_plugins",
    "dast_cors",
    "dast_evidence",
    "dast_findings",
    "dast_http",
    "dast_policy",
    "dast_report",
    "discovery_report",
    "graph_models",
    "graphql_report",
    "host_discovery",
    "infrastructure_models",
    "os_fingerprint",
    "ports",
    "resolver",
    "security_headers",
    "service_detection",
    "service_fingerprint",
    "service_probe",
    "session",
    "software_identity",
    "tcp_scanner",
    "tls_detection",
    "web_active_assessment",
    "web_assessment",
    "web_crawl",
    "web_form_execution",
    "web_form_intent",
    "web_form_submission",
    "web_report",
    "web_workflow",
    "web_workflow_execution",
    "web_workflow_report",
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
