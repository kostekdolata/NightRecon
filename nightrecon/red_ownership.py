"""Machine-readable ownership map for existing Red Night capabilities.

This module assigns existing NightRecon capability modules to Red Night without
duplicating their implementations. It is descriptive packaging metadata only.
"""

from __future__ import annotations

RED_MODULE_GROUPS: dict[str, tuple[str, ...]] = {
    "discovery": (
        "asset_inventory", "asset_inventory_store", "discovery_report",
        "host_discovery", "os_fingerprint", "ports", "report", "resolver",
        "service_detection", "service_fingerprint", "service_probe", "session",
        "software_identity", "storage", "tcp_scanner", "tls_detection",
    ),
    "web": (
        "browser_playwright", "browser_policy", "browser_report", "browser_worker",
        "dast_cors", "dast_evidence", "dast_findings", "dast_http",
        "dast_policy", "dast_report", "security_headers", "web_active_assessment",
        "web_assessment", "web_crawl", "web_form_execution", "web_form_intent",
        "web_form_submission", "web_report", "web_workflow",
        "web_workflow_execution", "web_workflow_report",
    ),
    "api": (
        "api_execution", "api_graphql", "api_models", "api_openapi",
        "api_planner", "api_policy", "api_report", "api_validation_report",
        "graphql_report",
    ),
    "infrastructure": (
        "credential_providers", "credential_resolution", "infrastructure_database",
        "infrastructure_database_adapter", "infrastructure_database_mysql",
        "infrastructure_database_psycopg", "infrastructure_execution",
        "infrastructure_models", "infrastructure_network_device",
        "infrastructure_policy", "infrastructure_registry",
        "infrastructure_report", "infrastructure_smb",
        "infrastructure_smb_adapter", "infrastructure_smb_impacket",
        "infrastructure_ssh", "infrastructure_winrm",
        "infrastructure_winrm_adapter", "infrastructure_winrm_pywinrm",
    ),
    "vulnerability": (
        "cisa_kev_provider", "cpe_identity", "epss_provider", "nvd_provider",
        "threat_context", "vulnerability_intelligence",
    ),
    "checks": (
        "assessment_engine", "builtin_checks", "check_catalog", "check_feed",
        "check_feed_state", "check_pack_manager", "check_pack_signing",
        "check_pack_store", "check_packs", "check_plugins",
    ),
    "graph_identity": (
        "graph_assessment", "graph_builder", "graph_critical_asset",
        "graph_identity_evidence", "graph_identity_projection", "graph_index",
        "graph_models", "graph_path", "graph_path_review", "graph_pipeline",
        "graph_projection", "graph_query", "graph_report", "graph_snapshot",
        "graph_summary", "graph_threat_context", "graph_traversal",
        "graph_validation", "red_directory_cli", "red_directory_import",
    ),
}

RED_OPTIONAL_EXTRAS: dict[str, tuple[str, ...]] = {
    "browser": ("playwright>=1.63,<2",),
    "api": ("PyYAML>=6.0,<7",),
    "ssh": ("paramiko>=5.0,<6",),
    "smb": ("impacket>=0.13.1,<0.14",),
    "winrm": ("pywinrm>=0.5,<0.6",),
    "postgres": ("psycopg[binary]>=3.2,<4",),
    "mysql": ("mysql-connector-python>=9.0,<10",),
}

RED_COMMANDS: tuple[str, ...] = (
    "api", "assets", "checks", "crawl", "discover", "identity",
    "infra", "scan", "workspace",
)

SHARED_CORE_COMPATIBILITY_MODULES: tuple[str, ...] = (
    "authorization_policy", "edition_catalog", "edition_policy", "scope", "targets",
)


def red_modules() -> tuple[str, ...]:
    return tuple(sorted({module for group in RED_MODULE_GROUPS.values() for module in group}))
