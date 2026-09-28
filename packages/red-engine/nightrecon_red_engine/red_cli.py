"""Command-line interface for NightRecon."""

import argparse
import json
import os
import sys
from http.cookiejar import CookieJar
from urllib.parse import urlsplit

try:
    from importlib.metadata import version as _distribution_version
    __version__ = _distribution_version("nightrecon-red-night")
except Exception:
    __version__ = "0.35.0.dev0"
from nightrecon_red_engine import report
from nightrecon_red_engine import config
from nightrecon_shared_core.editions import EDITIONS, EditionRouteError, available_commands, edition_name
from nightrecon_red_engine.api_execution import execute_api_request
from nightrecon_red_engine.api_graphql import (
    execute_graphql_introspection,
    load_graphql_introspection_json,
)
from nightrecon_red_engine.api_openapi import (
    ApiDescriptionRuntimeUnavailable,
    load_api_description,
)
from nightrecon_red_engine.api_planner import select_api_operations
from nightrecon_red_engine.api_policy import (
    ApiRequest,
    ApiRequestPolicy,
    ApiRequestState,
    authorize_api_request,
)
from nightrecon_red_engine.api_report import ApiInventoryReport
from nightrecon_red_engine.api_validation_report import (
    ApiValidationRecord,
    ApiValidationReport,
)
from nightrecon_red_engine.asset_inventory import (
    AssetChangeEvent,
    apply_discovery_report,
    apply_scan_report,
)
from nightrecon_red_engine.asset_inventory_store import AssetInventoryStore
from nightrecon_red_engine.browser_playwright import (
    BrowserRuntimeUnavailable,
    discover_with_playwright,
)
from nightrecon_red_engine.browser_policy import BrowserDiscoveryPolicy
from nightrecon_red_engine.browser_report import BrowserDiscoveryReport
from nightrecon_red_engine.assessment_engine import (
    CheckIntrusiveness,
    CheckRegistry,
    assess_services,
    summarize_assessments,
)
from nightrecon_red_engine.check_catalog import load_check_catalog
from nightrecon_red_engine.check_feed import fetch_signed_check_feed
from nightrecon_red_engine.check_pack_manager import (
    install_pack_from_verified_feed,
    plan_verified_check_feed,
    sync_verified_check_feed,
)
from nightrecon_red_engine.check_pack_store import CheckPackStore
from nightrecon_red_engine.check_pack_signing import (
    load_signed_check_pack_file,
    parse_trusted_key_specs,
)
from nightrecon_red_engine.config import NightReconConfig
from nightrecon_red_engine.cisa_kev_provider import CisaKevProvider
from nightrecon_red_engine.discovery_report import HostDiscoveryReport
from nightrecon_red_engine.dast_cors import assess_credentialed_cors
from nightrecon_red_engine.dast_policy import (
    DastBudgetPolicy,
    DastBudgetState,
)
from nightrecon_red_engine.dast_report import DastAssessmentReport
from nightrecon_red_engine.epss_provider import FirstEpssProvider
from nightrecon_red_engine.host_discovery import (
    discover_hosts,
    enrich_reverse_dns,
)
from nightrecon_red_engine.graphql_report import GraphQLSchemaReport
from nightrecon_red_engine.credential_resolution import (
    CredentialBinding,
    CredentialResolutionError,
    resolve_credential,
)
from nightrecon_red_engine.infrastructure_execution import execute_infrastructure_action
from nightrecon_red_engine.infrastructure_models import (
    CredentialKind,
    CredentialReference,
    CredentialSourceKind,
    InfrastructureAction,
    InfrastructureActionState,
    InfrastructureTransport,
)
from nightrecon_red_engine.infrastructure_policy import (
    InfrastructureAssessmentPolicy,
    authorize_infrastructure_action,
)
from nightrecon_red_engine.infrastructure_registry import (
    get_infrastructure_action_definition,
)
from nightrecon_red_engine.infrastructure_report import (
    DatabaseInfrastructureAssessmentReport,
    InfrastructureActionRecord,
    InfrastructureAssessmentReport,
    SmbInfrastructureAssessmentReport,
    WinRmInfrastructureAssessmentReport,
)
from nightrecon_red_engine.infrastructure_database import (
    DatabaseConnectionProfile,
    DatabaseEngine,
)
from nightrecon_red_engine.infrastructure_database_adapter import DatabaseReadOnlyAdapter
from nightrecon_red_engine.infrastructure_database_mysql import MySqlRuntimeFactory
from nightrecon_red_engine.infrastructure_database_psycopg import PsycopgRuntimeFactory
from nightrecon_red_engine.infrastructure_smb import SmbConnectionProfile
from nightrecon_red_engine.infrastructure_smb_adapter import SmbReadOnlyAdapter
from nightrecon_red_engine.infrastructure_smb_impacket import ImpacketSmbRuntimeFactory
from nightrecon_red_engine.infrastructure_winrm import WinRmConnectionProfile
from nightrecon_red_engine.infrastructure_winrm_adapter import WinRmReadOnlyAdapter
from nightrecon_red_engine.infrastructure_winrm_pywinrm import PyWinRmRuntimeFactory
from nightrecon_red_engine.infrastructure_ssh import (
    SshConnectionProfile,
    SshReadOnlyAdapter,
)
from nightrecon_red_engine.logging import NightReconLogger
from nightrecon_red_engine.nvd_provider import NvdVulnerabilityProvider
from nightrecon_red_engine.os_fingerprint import (
    build_host_operating_system_fingerprints,
)
from nightrecon_red_engine.ports import parse_ports
from nightrecon_red_engine.report import TcpScanReport
from nightrecon_red_engine.resolver import resolve_target
from nightrecon_shared_core.authorization import Scope
from nightrecon_red_engine.service_detection import detect_services
from nightrecon_red_engine.session import ScanSession
from nightrecon_red_engine.storage import ResultStore
from nightrecon_shared_core.authorization import TargetType, parse_target
from nightrecon_shared_core.workspace import LocalWorkspace
from nightrecon_red_engine.tcp_scanner import scan_tcp_ports
from nightrecon_red_engine.threat_context import (
    enrich_threat_context,
    summarize_threat_context,
)
from nightrecon_red_engine.vulnerability_intelligence import (
    enrich_service_vulnerabilities,
    summarize_vulnerabilities,
)
from nightrecon_red_engine.web_assessment import (
    assess_web_pages,
    summarize_web_assessments,
)
from nightrecon_red_engine.web_active_assessment import (
    assess_web_pages_safe_active,
)
from nightrecon_red_engine.web_crawl import (
    crawl_site,
    normalize_http_url,
    url_origin,
)
from nightrecon_red_engine.web_form_intent import observe_form_intents
from nightrecon_red_engine.web_report import WebCrawlReport
from nightrecon_red_engine.web_workflow import (
    WorkflowAction,
    WorkflowActionKind,
    WorkflowPolicy,
    WorkflowState,
    authorize_workflow_action,
    build_observed_navigation_plan,
)
from nightrecon_red_engine.web_workflow_execution import execute_workflow_navigation
from nightrecon_red_engine.web_workflow_report import (
    WebWorkflowReport,
    WorkflowExecutionRecord,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nightrecon",
        description=(
            "NightRecon - modular reconnaissance and penetration testing "
            "platform for authorized security assessments."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"NightRecon {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
    )

    editions_parser = subparsers.add_parser(
        "editions",
        help="Show the five planned NightRecon product editions and their readiness.",
    )
    editions_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the edition catalog as JSON.",
    )

    infra_parser = subparsers.add_parser(
        "infra",
        help="Run bounded credentialed infrastructure assessment.",
    )

    infra_subparsers = infra_parser.add_subparsers(
        dest="infra_command",
        title="infrastructure commands",
    )

    infra_ssh_parser = infra_subparsers.add_parser(
        "ssh",
        help=(
            "Run fixed read-only SSH identity/inventory actions "
            "against one explicitly authorized target."
        ),
    )

    infra_ssh_parser.add_argument(
        "target",
        help="Single authorized hostname or IP address.",
    )

    infra_ssh_parser.add_argument(
        "--scope",
        action="append",
        required=True,
        help=(
            "Authorized scope rule. May be supplied multiple times."
        ),
    )

    infra_ssh_parser.add_argument(
        "--username",
        required=True,
        help="SSH username. This is non-secret metadata.",
    )

    infra_ssh_parser.add_argument(
        "--known-hosts",
        required=True,
        help=(
            "Explicit known_hosts file. Unknown host keys are rejected."
        ),
    )

    infra_ssh_parser.add_argument(
        "--credential-id",
        required=True,
        help=(
            "Non-secret credential reference identifier used in audit/report data."
        ),
    )

    infra_ssh_parser.add_argument(
        "--password-env",
        required=True,
        help=(
            "Environment variable containing the SSH password. "
            "The variable value is never printed or persisted."
        ),
    )

    infra_ssh_parser.add_argument(
        "--action",
        action="append",
        dest="infra_actions",
        required=True,
        choices=(
            "ssh.system_identity",
            "ssh.os_inventory",
        ),
        help=(
            "Fixed read-only SSH action. May be repeated."
        ),
    )

    infra_ssh_parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="SSH port. Default: 22",
    )

    infra_ssh_parser.add_argument(
        "--max-actions",
        type=int,
        default=4,
        help="Maximum SSH action attempts. Default: 4",
    )

    infra_ssh_parser.add_argument(
        "--connect-timeout",
        type=float,
        default=5.0,
        help="SSH connect/auth timeout in seconds. Default: 5.0",
    )

    infra_ssh_parser.add_argument(
        "--command-timeout",
        type=float,
        default=5.0,
        help="Per-command timeout in seconds. Default: 5.0",
    )

    infra_ssh_parser.add_argument(
        "--max-output-bytes",
        type=int,
        default=65_536,
        help=(
            "Maximum combined stdout/stderr bytes per action. Default: 65536"
        ),
    )

    infra_ssh_parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory for result files. Default: results",
    )

    infra_ssh_parser.add_argument(
        "--logs-dir",
        default="logs",
        help="Directory for audit logs. Default: logs",
    )

    infra_smb_parser = infra_subparsers.add_parser(
        "smb",
        help=(
            "Run fixed read-only SMB identity/share-inventory actions "
            "against one explicitly authorized target."
        ),
    )

    infra_smb_parser.add_argument(
        "target",
        help="Single authorized hostname or IP address.",
    )

    infra_smb_parser.add_argument(
        "--scope",
        action="append",
        required=True,
        help=(
            "Authorized scope rule. May be supplied multiple times."
        ),
    )

    infra_smb_parser.add_argument(
        "--username",
        required=True,
        help="SMB username. This is non-secret metadata.",
    )

    infra_smb_parser.add_argument(
        "--domain",
        default="",
        help="Optional SMB domain/workgroup. This is non-secret metadata.",
    )

    infra_smb_parser.add_argument(
        "--credential-id",
        required=True,
        help=(
            "Non-secret credential reference identifier used in audit/report data."
        ),
    )

    infra_smb_parser.add_argument(
        "--password-env",
        required=True,
        help=(
            "Environment variable containing the SMB password. "
            "The variable value and variable name are never printed or persisted."
        ),
    )

    infra_smb_parser.add_argument(
        "--action",
        action="append",
        dest="infra_actions",
        required=True,
        choices=(
            "smb.server_identity",
            "smb.share_inventory",
        ),
        help=(
            "Fixed read-only SMB action. May be repeated."
        ),
    )

    infra_smb_parser.add_argument(
        "--port",
        type=int,
        default=445,
        help="SMB port. Default: 445",
    )

    infra_smb_parser.add_argument(
        "--max-actions",
        type=int,
        default=4,
        help="Maximum SMB action attempts. Default: 4",
    )

    infra_smb_parser.add_argument(
        "--connect-timeout",
        type=float,
        default=5.0,
        help="SMB connect/auth timeout in seconds. Default: 5.0",
    )

    infra_smb_parser.add_argument(
        "--operation-timeout",
        type=float,
        default=5.0,
        help="SMB operation timeout in seconds. Default: 5.0",
    )

    infra_smb_parser.add_argument(
        "--max-shares",
        type=int,
        default=128,
        help="Maximum SMB shares retained from inventory. Default: 128",
    )

    infra_smb_parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory for result files. Default: results",
    )

    infra_smb_parser.add_argument(
        "--logs-dir",
        default="logs",
        help="Directory for audit logs. Default: logs",
    )

    infra_winrm_parser = infra_subparsers.add_parser(
        "winrm",
        help=(
            "Run fixed read-only WinRM system/patch inventory actions "
            "against one explicitly authorized target."
        ),
    )

    infra_winrm_parser.add_argument(
        "target",
        help="Single authorized hostname or IP address.",
    )

    infra_winrm_parser.add_argument(
        "--scope",
        action="append",
        required=True,
        help=(
            "Authorized scope rule. May be supplied multiple times."
        ),
    )

    infra_winrm_parser.add_argument(
        "--username",
        required=True,
        help="WinRM username. This is non-secret metadata.",
    )

    infra_winrm_parser.add_argument(
        "--credential-id",
        required=True,
        help=(
            "Non-secret credential reference identifier used in audit/report data."
        ),
    )

    infra_winrm_parser.add_argument(
        "--password-env",
        required=True,
        help=(
            "Environment variable containing the WinRM password. "
            "The variable value and variable name are never printed or persisted."
        ),
    )

    infra_winrm_parser.add_argument(
        "--action",
        action="append",
        dest="infra_actions",
        required=True,
        choices=(
            "winrm.system_identity",
            "winrm.patch_inventory",
        ),
        help=(
            "Fixed read-only WinRM action. May be repeated."
        ),
    )

    infra_winrm_parser.add_argument(
        "--port",
        type=int,
        default=5986,
        help="HTTPS WinRM port. Default: 5986",
    )

    infra_winrm_parser.add_argument(
        "--max-actions",
        type=int,
        default=4,
        help="Maximum WinRM action attempts. Default: 4",
    )

    infra_winrm_parser.add_argument(
        "--connect-timeout",
        type=float,
        default=5.0,
        help="WinRM connect/read timeout basis in seconds. Default: 5.0",
    )

    infra_winrm_parser.add_argument(
        "--operation-timeout",
        type=float,
        default=5.0,
        help="WinRM WS-Man operation timeout in seconds. Default: 5.0",
    )

    infra_winrm_parser.add_argument(
        "--max-patches",
        type=int,
        default=512,
        help="Maximum WinRM patch observations retained. Default: 512",
    )

    infra_winrm_parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory for result files. Default: results",
    )

    infra_winrm_parser.add_argument(
        "--logs-dir",
        default="logs",
        help="Directory for audit logs. Default: logs",
    )

    infra_database_parser = infra_subparsers.add_parser(
        "database",
        help=(
            "Run fixed read-only database identity/schema actions "
            "against one explicitly authorized target."
        ),
    )

    infra_database_parser.add_argument(
        "target",
        help="Single authorized database hostname or IP address.",
    )

    infra_database_parser.add_argument(
        "--scope",
        action="append",
        required=True,
        help="Authorized scope rule. May be supplied multiple times.",
    )

    infra_database_parser.add_argument(
        "--engine",
        required=True,
        choices=("postgresql", "mysql"),
        help="Supported database engine.",
    )

    infra_database_parser.add_argument(
        "--username",
        required=True,
        help="Database username. This is non-secret metadata.",
    )

    infra_database_parser.add_argument(
        "--database-name",
        required=True,
        help="Database name. This is non-secret metadata.",
    )

    infra_database_parser.add_argument(
        "--credential-id",
        required=True,
        help="Non-secret credential reference identifier.",
    )

    infra_database_parser.add_argument(
        "--password-env",
        required=True,
        help=(
            "Environment variable containing the database password. "
            "The variable value and name are never printed or persisted."
        ),
    )

    infra_database_parser.add_argument(
        "--action",
        action="append",
        dest="infra_actions",
        required=True,
        choices=(
            "database.server_identity",
            "database.schema_inventory",
        ),
        help="Fixed read-only database action. May be repeated.",
    )

    infra_database_parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Database port. Defaults to 5432 for PostgreSQL or 3306 for MySQL.",
    )

    infra_database_parser.add_argument(
        "--max-actions",
        type=int,
        default=4,
        help="Maximum database action attempts. Default: 4",
    )

    infra_database_parser.add_argument(
        "--connect-timeout",
        type=float,
        default=5.0,
        help="Database connect/auth timeout in seconds. Default: 5.0",
    )

    infra_database_parser.add_argument(
        "--operation-timeout",
        type=float,
        default=5.0,
        help="Database metadata-operation timeout in seconds. Default: 5.0",
    )

    infra_database_parser.add_argument(
        "--max-schemas",
        type=int,
        default=512,
        help="Maximum schema observations retained. Default: 512",
    )

    infra_database_parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory for result files. Default: results",
    )

    infra_database_parser.add_argument(
        "--logs-dir",
        default="logs",
        help="Directory for audit logs. Default: logs",
    )

    api_parser = subparsers.add_parser(
        "api",
        help="Inspect authorized API descriptions and API intelligence.",
    )

    api_subparsers = api_parser.add_subparsers(
        dest="api_command",
        title="api commands",
    )

    api_inspect_parser = api_subparsers.add_parser(
        "inspect",
        help=(
            "Passively inspect a local OpenAPI/Swagger description "
            "without network activity."
        ),
    )

    api_inspect_parser.add_argument(
        "spec",
        help=(
            "Local .json, .yaml, or .yml OpenAPI/Swagger file. "
            "YAML requires the optional NightRecon api extra."
        ),
    )

    api_inspect_parser.add_argument(
        "--base-url",
        required=True,
        help=(
            "Authorized HTTP(S) API base URL used only for scope/origin "
            "validation. No request is sent."
        ),
    )

    api_inspect_parser.add_argument(
        "--scope",
        action="append",
        required=True,
        help=(
            "Authorized scope rule for the API base host. "
            "May be supplied multiple times."
        ),
    )

    api_inspect_parser.add_argument(
        "--max-spec-bytes",
        type=int,
        default=2_097_152,
        help=(
            "Maximum local API description size in bytes. "
            "Default: 2097152"
        ),
    )

    api_inspect_parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory for result files. Default: results",
    )

    api_inspect_parser.add_argument(
        "--logs-dir",
        default="logs",
        help="Directory for audit logs. Default: logs",
    )

    api_probe_parser = api_subparsers.add_parser(
        "probe",
        help=(
            "Execute explicitly selected bounded GET/HEAD API operations "
            "from a local OpenAPI/Swagger description."
        ),
    )

    api_probe_parser.add_argument(
        "spec",
        help=(
            "Local .json, .yaml, or .yml OpenAPI/Swagger file. "
            "YAML requires the optional NightRecon api extra."
        ),
    )

    api_probe_parser.add_argument(
        "--base-url",
        required=True,
        help=(
            "Authorized HTTP(S) API base URL. Selected operation paths "
            "are resolved beneath this URL."
        ),
    )

    api_probe_parser.add_argument(
        "--scope",
        action="append",
        required=True,
        help=(
            "Authorized scope rule for the API base host. "
            "May be supplied multiple times."
        ),
    )

    api_probe_parser.add_argument(
        "--operation",
        action="append",
        dest="api_operations",
        required=True,
        help=(
            "Exact operationId, or METHOD /path when operationId is absent. "
            "May be repeated. Only GET/HEAD operations without required "
            "parameter values are executable."
        ),
    )

    api_probe_parser.add_argument(
        "--max-spec-bytes",
        type=int,
        default=2_097_152,
        help=(
            "Maximum local API description size in bytes. "
            "Default: 2097152"
        ),
    )

    api_probe_parser.add_argument(
        "--max-requests",
        type=int,
        default=10,
        help="Maximum API requests in this validation run. Default: 10",
    )

    api_probe_parser.add_argument(
        "--max-response-bytes",
        type=int,
        default=1_048_576,
        help=(
            "Maximum response bytes read per GET request. "
            "Response bodies are not persisted. Default: 1048576"
        ),
    )

    api_probe_parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-request timeout in seconds. Default: 5.0",
    )

    api_probe_parser.add_argument(
        "--authorization-env",
        help=(
            "Read the complete Authorization header value from this "
            "environment variable. The value is never printed or persisted."
        ),
    )

    api_probe_parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory for result files. Default: results",
    )

    api_probe_parser.add_argument(
        "--logs-dir",
        default="logs",
        help="Directory for audit logs. Default: logs",
    )

    api_graphql_inspect_parser = api_subparsers.add_parser(
        "graphql-inspect",
        help=(
            "Passively inspect saved GraphQL introspection JSON without "
            "network activity."
        ),
    )

    api_graphql_inspect_parser.add_argument(
        "introspection",
        help="Local saved GraphQL introspection JSON file.",
    )

    api_graphql_inspect_parser.add_argument(
        "--endpoint-url",
        required=True,
        help=(
            "Authorized GraphQL endpoint URL used only for scope/origin "
            "context. No request is sent."
        ),
    )

    api_graphql_inspect_parser.add_argument(
        "--scope",
        action="append",
        required=True,
        help="Authorized scope rule for the GraphQL endpoint host.",
    )

    api_graphql_inspect_parser.add_argument(
        "--max-spec-bytes",
        type=int,
        default=2_097_152,
        help=(
            "Maximum saved introspection JSON size in bytes. "
            "Default: 2097152"
        ),
    )

    api_graphql_inspect_parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory for result files. Default: results",
    )

    api_graphql_inspect_parser.add_argument(
        "--logs-dir",
        default="logs",
        help="Directory for audit logs. Default: logs",
    )

    api_graphql_introspect_parser = api_subparsers.add_parser(
        "graphql-introspect",
        help=(
            "Execute one fixed bounded GraphQL introspection operation "
            "against an explicitly authorized endpoint."
        ),
    )

    api_graphql_introspect_parser.add_argument(
        "--endpoint-url",
        required=True,
        help=(
            "Authorized GraphQL endpoint URL. The URL must not contain "
            "credentials, query data, or fragments."
        ),
    )

    api_graphql_introspect_parser.add_argument(
        "--scope",
        action="append",
        required=True,
        help="Authorized scope rule for the GraphQL endpoint host.",
    )

    api_graphql_introspect_parser.add_argument(
        "--max-response-bytes",
        type=int,
        default=1_048_576,
        help=(
            "Maximum introspection response bytes. "
            "Default: 1048576"
        ),
    )

    api_graphql_introspect_parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Introspection request timeout in seconds. Default: 5.0",
    )

    api_graphql_introspect_parser.add_argument(
        "--authorization-env",
        help=(
            "Read the complete Authorization header value from this "
            "environment variable. The value is never printed or persisted."
        ),
    )

    api_graphql_introspect_parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory for result files. Default: results",
    )

    api_graphql_introspect_parser.add_argument(
        "--logs-dir",
        default="logs",
        help="Directory for audit logs. Default: logs",
    )

    assets_parser = subparsers.add_parser(
        "assets",
        help="Inspect the persistent NightRecon asset inventory.",
    )

    assets_subparsers = assets_parser.add_subparsers(
        dest="assets_command",
        title="asset commands",
    )

    assets_list_parser = assets_subparsers.add_parser(
        "list",
        help="List persistent assets without network activity.",
    )

    assets_list_parser.add_argument(
        "--inventory-dir",
        default="inventory",
        help=(
            "Persistent NightRecon asset inventory directory. "
            "Default: inventory"
        ),
    )

    assets_history_parser = assets_subparsers.add_parser(
        "history",
        help="Inspect persisted asset changes without network activity.",
    )

    assets_history_parser.add_argument(
        "--inventory-dir",
        default="inventory",
        help=(
            "Persistent NightRecon asset inventory directory. "
            "Default: inventory"
        ),
    )

    assets_history_parser.add_argument(
        "--address",
        help="Filter history by exact asset IP address.",
    )

    assets_history_parser.add_argument(
        "--limit",
        type=int,
        help="Return only the most recent N matching changes.",
    )

    checks_parser = subparsers.add_parser(
        "checks",
        help="Inspect installed assessment checks.",
    )

    checks_subparsers = checks_parser.add_subparsers(
        dest="checks_command",
        title="check commands",
    )

    checks_list_parser = checks_subparsers.add_parser(
        "list",
        help="List installed assessment checks.",
    )

    checks_list_parser.add_argument(
        "--check",
        action="append",
        dest="check_ids",
        help="Filter by exact check ID. May be repeated.",
    )

    checks_list_parser.add_argument(
        "--family",
        action="append",
        dest="check_families",
        help="Filter by check family. May be repeated.",
    )

    checks_list_parser.add_argument(
        "--tag",
        action="append",
        dest="check_tags",
        help="Filter by check tag. May be repeated.",
    )

    checks_list_parser.add_argument(
        "--check-pack",
        action="append",
        dest="check_pack_paths",
        help=(
            "Load a signed declarative check-pack JSON file. "
            "May be repeated."
        ),
    )

    checks_list_parser.add_argument(
        "--check-pack-key",
        action="append",
        dest="check_pack_keys",
        help=(
            "Trust an Ed25519 check-pack signer using "
            "KEY_ID=BASE64_PUBLIC_KEY. May be repeated."
        ),
    )

    checks_list_parser.add_argument(
        "--installed-check-packs",
        action="store_true",
        help=(
            "Load all active locally installed signed check packs."
        ),
    )

    checks_list_parser.add_argument(
        "--check-store-dir",
        default=".nightrecon",
        help=(
            "Local NightRecon state directory for installed packs. "
            "Default: .nightrecon"
        ),
    )

    checks_feed_parser = checks_subparsers.add_parser(
        "feed",
        help="Inspect a signed declarative check feed.",
    )

    checks_feed_parser.add_argument(
        "--url",
        help="HTTPS URL of the signed check-feed manifest.",
    )

    checks_feed_parser.add_argument(
        "--feed-key",
        action="append",
        dest="feed_keys",
        help=(
            "Trust an Ed25519 feed signer using "
            "KEY_ID=BASE64_PUBLIC_KEY. May be repeated."
        ),
    )

    checks_feed_parser.add_argument(
        "--install-pack",
        help=(
            "Install one advertised signed check pack into the local "
            "verified pack store."
        ),
    )

    checks_feed_parser.add_argument(
        "--pack-key",
        action="append",
        dest="feed_pack_keys",
        help=(
            "Trust a check-pack signer using "
            "KEY_ID=BASE64_PUBLIC_KEY. May be repeated."
        ),
    )

    checks_feed_parser.add_argument(
        "--store-dir",
        default=".nightrecon",
        help=(
            "Local NightRecon state directory for installed packs. "
            "Default: .nightrecon"
        ),
    )

    checks_feed_parser.add_argument(
        "--sync",
        action="store_true",
        help=(
            "Synchronize all advertised packs into the local verified "
            "pack store."
        ),
    )

    checks_feed_parser.add_argument(
        "--plan",
        action="store_true",
        help=(
            "Compare the verified feed with local installed-pack state "
            "without downloading or activating packs."
        ),
    )

    checks_feed_parser.add_argument(
        "--list-installed",
        action="store_true",
        help=(
            "List locally installed check packs without network access."
        ),
    )

    checks_feed_parser.add_argument(
        "--rollback-pack",
        help=(
            "Reverify and reactivate the previous cached version of one "
            "installed check pack without network access."
        ),
    )

    discover_parser = subparsers.add_parser(
        "discover",
        help="Discover responsive hosts in an authorized CIDR.",
    )

    discover_parser.add_argument(
        "target",
        help="Authorized CIDR target.",
    )

    discover_parser.add_argument(
        "--scope",
        action="append",
        required=True,
        help=(
            "Authorized scope rule. May be supplied multiple times. "
            "The discovery CIDR must be fully contained in scope."
        ),
    )

    discover_parser.add_argument(
        "--ports",
        default="22,80,443,445",
        help=(
            "TCP ports used only for host reachability evidence. "
            "Default: 22,80,443,445"
        ),
    )

    discover_parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Per-port connection timeout in seconds. Default: 1.0",
    )

    discover_parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Maximum concurrent host probes. Default: 100",
    )

    discover_parser.add_argument(
        "--max-hosts",
        type=int,
        default=1024,
        help=(
            "Hard maximum number of host addresses permitted in one "
            "discovery run. Default: 1024"
        ),
    )

    discover_parser.add_argument(
        "--reverse-dns",
        action="store_true",
        help=(
            "Attempt fail-soft reverse-DNS enrichment for responsive "
            "hosts after TCP discovery."
        ),
    )

    discover_parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory for result files. Default: results",
    )

    discover_parser.add_argument(
        "--logs-dir",
        default="logs",
        help="Directory for audit logs. Default: logs",
    )

    discover_parser.add_argument(
        "--update-inventory",
        action="store_true",
        help=(
            "Merge discovery evidence into the persistent asset inventory."
        ),
    )

    discover_parser.add_argument(
        "--inventory-dir",
        default="inventory",
        help=(
            "Persistent NightRecon asset inventory directory. "
            "Default: inventory"
        ),
    )

    crawl_parser = subparsers.add_parser(
        "crawl",
        help="Crawl an authorized HTTP(S) origin.",
    )

    crawl_parser.add_argument(
        "url",
        help="Authorized HTTP(S) start URL.",
    )

    crawl_parser.add_argument(
        "--scope",
        action="append",
        required=True,
        help=(
            "Authorized hostname, IP address, or CIDR rule. "
            "The URL host must be explicitly within scope."
        ),
    )

    crawl_parser.add_argument(
        "--max-pages",
        type=int,
        default=50,
        help="Maximum pages fetched in one crawl. Default: 50",
    )

    crawl_parser.add_argument(
        "--max-bytes-per-page",
        type=int,
        default=1_048_576,
        help=(
            "Maximum response bytes read per page. "
            "Default: 1048576"
        ),
    )

    crawl_parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-request timeout in seconds. Default: 5.0",
    )

    crawl_parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory for result files. Default: results",
    )

    crawl_parser.add_argument(
        "--logs-dir",
        default="logs",
        help="Directory for audit logs. Default: logs",
    )

    crawl_parser.add_argument(
        "--assessment",
        action="store_true",
        help=(
            "Run web DAST checks. Passive checks are the default; "
            "safe-active probes require an explicit intrusiveness setting."
        ),
    )

    crawl_parser.add_argument(
        "--max-web-assessment-intrusiveness",
        choices=(
            "passive",
            "safe-active",
        ),
        default="passive",
        help=(
            "Maximum web-assessment intrusiveness. "
            "safe-active currently adds bounded non-mutating OPTIONS "
            "probes only. Default: passive"
        ),
    )

    crawl_parser.add_argument(
        "--max-web-assessment-requests",
        type=int,
        default=10,
        help=(
            "Maximum safe-active web assessment requests. "
            "Applies only with --assessment and "
            "--max-web-assessment-intrusiveness safe-active. "
            "Default: 10"
        ),
    )

    crawl_parser.add_argument(
        "--dast-cors",
        action="store_true",
        help=(
            "Run the bounded credentialed-CORS reflection DAST check over "
            "same-origin crawled pages. Requires --assessment and "
            "--max-web-assessment-intrusiveness safe-active."
        ),
    )

    crawl_parser.add_argument(
        "--dast-max-total-requests",
        type=int,
        default=20,
        help="Maximum requests across the v0.28 DAST run. Default: 20",
    )

    crawl_parser.add_argument(
        "--dast-max-family-requests",
        type=int,
        default=10,
        help="Maximum requests per DAST family. Default: 10",
    )

    crawl_parser.add_argument(
        "--dast-cors-max-targets",
        type=int,
        default=3,
        help=(
            "Maximum same-origin crawl targets checked for credentialed "
            "CORS reflection. Each target requires two OPTIONS requests. "
            "Default: 3"
        ),
    )

    crawl_parser.add_argument(
        "--dast-max-response-bytes",
        type=int,
        default=65_536,
        help=(
            "Maximum response bytes read per DAST request. Response bodies "
            "are fingerprinted and discarded. Default: 65536"
        ),
    )

    crawl_parser.add_argument(
        "--authorization-env",
        help=(
            "Name of an environment variable containing the complete "
            "HTTP Authorization header value for authenticated crawling. "
            "The value is never printed or persisted."
        ),
    )

    crawl_parser.add_argument(
        "--cookie-env",
        help=(
            "Name of an environment variable containing the HTTP Cookie "
            "header value for authenticated crawling. "
            "The value is never printed or persisted."
        ),
    )

    crawl_parser.add_argument(
        "--session-cookies",
        action="store_true",
        help=(
            "Reuse response cookies only in memory for later requests "
            "within this authorized crawl. Cookie values are never "
            "printed or persisted. Cannot be combined with --cookie-env."
        ),
    )

    crawl_parser.add_argument(
        "--workflow",
        action="store_true",
        help=(
            "Build a non-secret stateful workflow plan from observed links "
            "and forms. No form submissions are performed."
        ),
    )

    crawl_parser.add_argument(
        "--workflow-max-actions",
        type=int,
        default=10,
        help=(
            "Maximum workflow actions permitted for explicit workflow GET "
            "execution. Default: 10"
        ),
    )

    crawl_parser.add_argument(
        "--workflow-get",
        action="append",
        dest="workflow_get_urls",
        help=(
            "Explicitly execute one absolute same-origin GET URL after the "
            "crawl under workflow policy. Requires --workflow. May repeat. "
            "Form POST execution is not exposed by the v0.25 CLI."
        ),
    )

    crawl_parser.add_argument(
        "--browser-discovery",
        action="store_true",
        help=(
            "Run bounded Playwright/Chromium discovery for JavaScript-rendered "
            "same-origin links and form metadata. Requires the optional "
            "NightRecon browser extra and Chromium runtime. Authenticated "
            "browser context is not yet supported in v0.26."
        ),
    )

    crawl_parser.add_argument(
        "--browser-max-requests",
        type=int,
        default=100,
        help="Maximum browser network requests reserved. Default: 100",
    )

    crawl_parser.add_argument(
        "--browser-max-pages",
        type=int,
        default=10,
        help="Maximum browser document navigations. Default: 10",
    )

    crawl_parser.add_argument(
        "--browser-max-runtime",
        type=float,
        default=30.0,
        help="Maximum browser runtime in seconds. Default: 30",
    )

    crawl_parser.add_argument(
        "--browser-max-response-bytes",
        type=int,
        default=1_048_576,
        help=(
            "Maximum declared response bytes permitted for browser delivery. "
            "Default: 1048576"
        ),
    )

    crawl_parser.add_argument(
        "--browser-max-dom-bytes",
        type=int,
        default=2_097_152,
        help=(
            "Maximum serialized browser-discovery metadata bytes retained. "
            "Default: 2097152"
        ),
    )

    crawl_parser.add_argument(
        "--browser-max-dom-items",
        type=int,
        default=500,
        help=(
            "Maximum DOM links/forms/fields sampled per collection. "
            "Default: 500"
        ),
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan an authorized target.",
    )

    scan_parser.add_argument(
        "target",
        help="Authorized target hostname or IP address.",
    )

    scan_parser.add_argument(
        "--scope",
        action="append",
        required=True,
        help=(
            "Authorized scope rule. May be supplied multiple times. "
            "Example: --scope 192.168.1.0/24"
        ),
    )

    scan_parser.add_argument(
        "--ports",
        default="80,443",
        help=(
            "TCP ports to scan. Supports lists and ranges. "
            "Default: 80,443"
        ),
    )

    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Connection timeout in seconds. Default: 2.0",
    )

    scan_parser.add_argument(
        "--workers",
        type=int,
        default=50,
        help="Maximum concurrent workers. Default: 50",
    )

    scan_parser.add_argument(
        "--service-probe-intensity",
        type=int,
        choices=range(0, 10),
        default=0,
        help=(
            "Bounded active service-probe intensity from 0 to 9. "
            "0 disables active service probes. Default: 0"
        ),
    )

    scan_parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory for result files. Default: results",
    )

    scan_parser.add_argument(
        "--logs-dir",
        default="logs",
        help="Directory for audit logs. Default: logs",
    )

    scan_parser.add_argument(
        "--update-inventory",
        action="store_true",
        help=(
            "Merge scan evidence into the persistent asset inventory."
        ),
    )

    scan_parser.add_argument(
        "--inventory-dir",
        default="inventory",
        help=(
            "Persistent NightRecon asset inventory directory. "
            "Default: inventory"
        ),
    )

    scan_parser.add_argument(
        "--vuln-lookup",
        action="store_true",
        help=(
            "Query supported vulnerability intelligence providers for "
            "explicitly observed software identities. Disabled by default."
        ),
    )

    scan_parser.add_argument(
        "--threat-context",
        action="store_true",
        help=(
            "Enrich CVE findings with CISA KEV and FIRST EPSS evidence. "
            "Requires --vuln-lookup."
        ),
    )

    scan_parser.add_argument(
        "--assessment",
        action="store_true",
        help=(
            "Run the assessment-check engine against detected services. "
            "Disabled by default."
        ),
    )

    scan_parser.add_argument(
        "--check",
        action="append",
        dest="assessment_check_ids",
        help=(
            "Run only an exact assessment check ID. May be repeated. "
            "Requires --assessment."
        ),
    )

    scan_parser.add_argument(
        "--check-family",
        action="append",
        dest="assessment_check_families",
        help=(
            "Run only assessment checks in a family. May be repeated. "
            "Requires --assessment."
        ),
    )

    scan_parser.add_argument(
        "--check-tag",
        action="append",
        dest="assessment_check_tags",
        help=(
            "Run assessment checks matching a tag. May be repeated. "
            "Requires --assessment."
        ),
    )

    scan_parser.add_argument(
        "--max-check-intrusiveness",
        choices=(
            "passive",
            "safe-active",
            "intrusive",
        ),
        default="safe-active",
        help=(
            "Maximum assessment-check intrusiveness. "
            "Destructive checks are not available from this scan command. "
            "Default: safe-active"
        ),
    )

    scan_parser.add_argument(
        "--check-pack",
        action="append",
        dest="check_pack_paths",
        help=(
            "Load a signed declarative assessment check-pack. "
            "May be repeated. Requires --assessment."
        ),
    )

    scan_parser.add_argument(
        "--check-pack-key",
        action="append",
        dest="check_pack_keys",
        help=(
            "Trust an Ed25519 check-pack signer using "
            "KEY_ID=BASE64_PUBLIC_KEY. May be repeated. "
            "Requires --assessment."
        ),
    )

    scan_parser.add_argument(
        "--installed-check-packs",
        action="store_true",
        help=(
            "Load all active locally installed signed check packs. "
            "Requires --assessment and --check-pack-key."
        ),
    )

    scan_parser.add_argument(
        "--check-store-dir",
        default=".nightrecon",
        help=(
            "Local NightRecon state directory for installed packs. "
            "Default: .nightrecon"
        ),
    )

    return parser


def _load_requested_check_pack_checks(
    paths: tuple[str, ...],
    key_specs: tuple[str, ...],
) -> tuple[object, ...]:
    """Load explicitly requested signed declarative check packs."""

    trusted_keys = parse_trusted_key_specs(
        key_specs
    )
    checks: list[object] = []

    for path in paths:
        pack = load_signed_check_pack_file(
            path,
            trusted_keys=trusted_keys,
        )
        checks.extend(pack.checks)

    return tuple(checks)


def _load_installed_check_pack_checks(
    store_dir: str,
    key_specs: tuple[str, ...],
) -> tuple[object, ...]:
    """Load and reverify all active locally installed check packs."""

    trusted_keys = parse_trusted_key_specs(
        key_specs
    )

    if not trusted_keys:
        raise ValueError(
            "--installed-check-packs requires --check-pack-key."
        )

    store = CheckPackStore(
        store_dir
    )
    checks: list[object] = []

    for pack_id in store.list_pack_ids():
        pack = store.load_active(
            pack_id,
            trusted_keys=trusted_keys,
        )
        checks.extend(
            pack.checks
        )

    return tuple(checks)


def _command_main(argv: tuple[str, ...] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "editions":
        if args.json:
            print(json.dumps([edition.to_record() for edition in EDITIONS]))
        else:
            for edition in EDITIONS:
                print(
                    f"{edition.name}: {edition.foundation_status}; "
                    "standalone edition not yet available"
                )
                print(f"  {edition.purpose}")
        return

    if args.command == "infra":
        if args.infra_command == "smb":
            try:
                target = parse_target(
                    args.target
                )

                if target.target_type == TargetType.CIDR:
                    raise ValueError(
                        "SMB infrastructure assessment requires a single host or IP target."
                    )

                scope = Scope.from_values(
                    args.scope
                )

                if args.max_actions < 1:
                    raise ValueError(
                        "max_actions must be at least 1."
                    )

                if len(
                    args.infra_actions
                ) > args.max_actions:
                    raise ValueError(
                        "Selected SMB actions exceed max_actions."
                    )

                credential_id = (
                    args.credential_id.strip()
                )

                if (
                    not credential_id
                    or len(credential_id) > 128
                    or not all(
                        character.isalnum()
                        or character in "._-"
                        for character in credential_id
                    )
                ):
                    raise ValueError(
                        "credential_id must contain only letters, numbers, '.', '_', or '-'."
                    )

                profile = SmbConnectionProfile(
                    username=args.username,
                    domain=args.domain,
                    port=args.port,
                    connect_timeout=args.connect_timeout,
                    operation_timeout=args.operation_timeout,
                    max_shares=args.max_shares,
                )
            except ValueError as exc:
                parser.error(
                    str(
                        exc
                    )
                )

            logger = NightReconLogger(
                args.logs_dir
            )

            if not scope.is_authorized(
                target
            ):
                logger.write(
                    "infra.smb.rejected",
                    target=target.value,
                    target_type=target.target_type.value,
                    scope=args.scope,
                    reason="outside_authorized_scope",
                )
                parser.error(
                    f"Target '{target.value}' is outside the authorized scope."
                )

            session = ScanSession.create(
                target=target,
                scope_rules=tuple(
                    args.scope
                ),
            )
            policy = InfrastructureAssessmentPolicy(
                scope=scope,
                allowed_transports=(
                    InfrastructureTransport.SMB,
                ),
                max_actions=args.max_actions,
            )
            state = InfrastructureActionState(
                actions_used=0,
                max_actions=args.max_actions,
            )
            reference = CredentialReference(
                credential_id=credential_id,
                kind=CredentialKind.PASSWORD,
                source_kind=CredentialSourceKind.ENVIRONMENT,
            )
            binding = CredentialBinding(
                reference=reference,
                source_name=args.password_env,
            )
            adapter = SmbReadOnlyAdapter(
                profile,
                ImpacketSmbRuntimeFactory(),
            )
            records = []

            for action_id in args.infra_actions:
                definition = (
                    get_infrastructure_action_definition(
                        action_id
                    )
                )
                action = InfrastructureAction(
                    target=target.value,
                    transport=InfrastructureTransport.SMB,
                    action_id=action_id,
                    credential_id=credential_id,
                )
                decision = authorize_infrastructure_action(
                    action=action,
                    definition=definition,
                    credential=reference,
                    policy=policy,
                    state=state,
                )

                if not decision.allowed:
                    logger.write(
                        "infra.smb.action_rejected",
                        session_id=session.session_id,
                        target=target.value,
                        transport="smb",
                        action_id=action_id,
                        credential_id=credential_id,
                        reason=decision.reason,
                    )
                    parser.error(
                        "SMB action was rejected by the infrastructure policy: "
                        f"{decision.reason}"
                    )

                try:
                    credential = resolve_credential(
                        binding,
                        ttl_seconds=max(
                            30.0,
                            args.connect_timeout
                            + args.operation_timeout
                            + 5.0,
                        ),
                    )
                except CredentialResolutionError:
                    logger.write(
                        "infra.smb.credential_resolution_failed",
                        session_id=session.session_id,
                        target=target.value,
                        transport="smb",
                        action_id=action_id,
                        credential_id=credential_id,
                        reason="credential_resolution_failed",
                    )
                    parser.error(
                        "SMB credential could not be resolved from the configured "
                        "environment source."
                    )

                result = execute_infrastructure_action(
                    action=action,
                    definition=definition,
                    decision=decision,
                    state=state,
                    credential=credential,
                    adapter=adapter,
                )
                state = result.state
                records.append(
                    InfrastructureActionRecord.from_result(
                        result
                    )
                )

            infra_report = (
                SmbInfrastructureAssessmentReport.create(
                    session=session,
                    username=profile.username,
                    domain=profile.domain,
                    port=profile.port,
                    max_actions=args.max_actions,
                    max_shares=profile.max_shares,
                    records=tuple(
                        records
                    ),
                )
            )
            output_path = ResultStore(
                args.results_dir
            ).save_infrastructure_assessment_report(
                infra_report
            )
            summary = infra_report.to_dict()[
                "summary"
            ]

            logger.write(
                "infra.smb.completed",
                session_id=session.session_id,
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                transport="smb",
                username=profile.username,
                domain=profile.domain,
                port=profile.port,
                credential_id=credential_id,
                max_shares=profile.max_shares,
                selected_actions=summary[
                    "selected_actions"
                ],
                attempted_actions=summary[
                    "attempted_actions"
                ],
                successful_actions=summary[
                    "successful_actions"
                ],
                failed_actions=summary[
                    "failed_actions"
                ],
                status=infra_report.status,
            )

            print(
                "SMB Assessment Summary: "
                f"selected={summary['selected_actions']} "
                f"attempted={summary['attempted_actions']} "
                f"successful={summary['successful_actions']} "
                f"failed={summary['failed_actions']}"
            )

            for record in infra_report.records:
                print(
                    "  SMB ACTION "
                    f"{record.action_id} "
                    f"success={'yes' if record.success else 'no'} "
                    f"reason={record.reason}"
                )

                for fact in record.facts:
                    print(
                        "    FACT "
                        f"{fact['key']}={fact['value']}"
                    )

            print(
                f"Session ID: {session.session_id}"
            )
            print(
                f"Infrastructure result file: {output_path}"
            )
            return

        if args.infra_command == "winrm":
            try:
                target = parse_target(
                    args.target
                )

                if target.target_type == TargetType.CIDR:
                    raise ValueError(
                        "WinRM infrastructure assessment requires a single host or IP target."
                    )

                scope = Scope.from_values(
                    args.scope
                )

                if args.max_actions < 1:
                    raise ValueError(
                        "max_actions must be at least 1."
                    )

                if len(
                    args.infra_actions
                ) > args.max_actions:
                    raise ValueError(
                        "Selected WinRM actions exceed max_actions."
                    )

                credential_id = (
                    args.credential_id.strip()
                )

                if (
                    not credential_id
                    or len(credential_id) > 128
                    or not all(
                        character.isalnum()
                        or character in "._-"
                        for character in credential_id
                    )
                ):
                    raise ValueError(
                        "credential_id must contain only letters, numbers, '.', '_', or '-'."
                    )

                profile = WinRmConnectionProfile(
                    username=args.username,
                    port=args.port,
                    connect_timeout=args.connect_timeout,
                    operation_timeout=args.operation_timeout,
                    max_patches=args.max_patches,
                    use_tls=True,
                    validate_server_certificate=True,
                )
            except ValueError as exc:
                parser.error(
                    str(
                        exc
                    )
                )

            logger = NightReconLogger(
                args.logs_dir
            )

            if not scope.is_authorized(
                target
            ):
                logger.write(
                    "infra.winrm.rejected",
                    target=target.value,
                    target_type=target.target_type.value,
                    scope=args.scope,
                    reason="outside_authorized_scope",
                )
                parser.error(
                    f"Target '{target.value}' is outside the authorized scope."
                )

            session = ScanSession.create(
                target=target,
                scope_rules=tuple(
                    args.scope
                ),
            )
            policy = InfrastructureAssessmentPolicy(
                scope=scope,
                allowed_transports=(
                    InfrastructureTransport.WINRM,
                ),
                max_actions=args.max_actions,
            )
            state = InfrastructureActionState(
                actions_used=0,
                max_actions=args.max_actions,
            )
            reference = CredentialReference(
                credential_id=credential_id,
                kind=CredentialKind.PASSWORD,
                source_kind=CredentialSourceKind.ENVIRONMENT,
            )
            binding = CredentialBinding(
                reference=reference,
                source_name=args.password_env,
            )
            adapter = WinRmReadOnlyAdapter(
                profile,
                PyWinRmRuntimeFactory(),
            )
            records = []

            for action_id in args.infra_actions:
                definition = (
                    get_infrastructure_action_definition(
                        action_id
                    )
                )
                action = InfrastructureAction(
                    target=target.value,
                    transport=InfrastructureTransport.WINRM,
                    action_id=action_id,
                    credential_id=credential_id,
                )
                decision = authorize_infrastructure_action(
                    action=action,
                    definition=definition,
                    credential=reference,
                    policy=policy,
                    state=state,
                )

                if not decision.allowed:
                    logger.write(
                        "infra.winrm.action_rejected",
                        session_id=session.session_id,
                        target=target.value,
                        transport="winrm",
                        action_id=action_id,
                        credential_id=credential_id,
                        reason=decision.reason,
                    )
                    parser.error(
                        "WinRM action was rejected by the infrastructure policy: "
                        f"{decision.reason}"
                    )

                try:
                    credential = resolve_credential(
                        binding,
                        ttl_seconds=max(
                            30.0,
                            args.connect_timeout
                            + args.operation_timeout
                            + 5.0,
                        ),
                    )
                except CredentialResolutionError:
                    logger.write(
                        "infra.winrm.credential_resolution_failed",
                        session_id=session.session_id,
                        target=target.value,
                        transport="winrm",
                        action_id=action_id,
                        credential_id=credential_id,
                        reason="credential_resolution_failed",
                    )
                    parser.error(
                        "WinRM credential could not be resolved from the configured "
                        "environment source."
                    )

                result = execute_infrastructure_action(
                    action=action,
                    definition=definition,
                    decision=decision,
                    state=state,
                    credential=credential,
                    adapter=adapter,
                )
                state = result.state
                records.append(
                    InfrastructureActionRecord.from_result(
                        result
                    )
                )

            infra_report = (
                WinRmInfrastructureAssessmentReport.create(
                    session=session,
                    username=profile.username,
                    port=profile.port,
                    max_actions=args.max_actions,
                    max_patches=profile.max_patches,
                    records=tuple(
                        records
                    ),
                )
            )
            output_path = ResultStore(
                args.results_dir
            ).save_infrastructure_assessment_report(
                infra_report
            )
            summary = infra_report.to_dict()[
                "summary"
            ]

            logger.write(
                "infra.winrm.completed",
                session_id=session.session_id,
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                transport="winrm",
                username=profile.username,
                port=profile.port,
                authentication="ntlm",
                tls_required=True,
                certificate_validation="required",
                credential_id=credential_id,
                max_patches=profile.max_patches,
                selected_actions=summary[
                    "selected_actions"
                ],
                attempted_actions=summary[
                    "attempted_actions"
                ],
                successful_actions=summary[
                    "successful_actions"
                ],
                failed_actions=summary[
                    "failed_actions"
                ],
                status=infra_report.status,
            )

            print(
                "WinRM Assessment Summary: "
                f"selected={summary['selected_actions']} "
                f"attempted={summary['attempted_actions']} "
                f"successful={summary['successful_actions']} "
                f"failed={summary['failed_actions']}"
            )

            for record in infra_report.records:
                print(
                    "  WINRM ACTION "
                    f"{record.action_id} "
                    f"success={'yes' if record.success else 'no'} "
                    f"reason={record.reason}"
                )

                for fact in record.facts:
                    print(
                        "    FACT "
                        f"{fact['key']}={fact['value']}"
                    )

            print(
                f"Session ID: {session.session_id}"
            )
            print(
                f"Infrastructure result file: {output_path}"
            )
            return

        if args.infra_command == "database":
            try:
                target = parse_target(args.target)

                if target.target_type == TargetType.CIDR:
                    raise ValueError(
                        "Database infrastructure assessment requires a single host or IP target."
                    )

                scope = Scope.from_values(args.scope)

                if args.max_actions < 1:
                    raise ValueError("max_actions must be at least 1.")

                if len(args.infra_actions) > args.max_actions:
                    raise ValueError(
                        "Selected database actions exceed max_actions."
                    )

                credential_id = args.credential_id.strip()

                if (
                    not credential_id
                    or len(credential_id) > 128
                    or not all(
                        character.isalnum()
                        or character in "._-"
                        for character in credential_id
                    )
                ):
                    raise ValueError(
                        "credential_id must contain only letters, numbers, '.', '_', or '-'."
                    )

                engine = DatabaseEngine(args.engine)
                port = args.port
                if port is None:
                    port = (
                        5432
                        if engine == DatabaseEngine.POSTGRESQL
                        else 3306
                    )

                profile = DatabaseConnectionProfile(
                    engine=engine,
                    username=args.username,
                    database_name=args.database_name,
                    port=port,
                    connect_timeout=args.connect_timeout,
                    operation_timeout=args.operation_timeout,
                    max_schemas=args.max_schemas,
                    use_tls=True,
                    validate_server_certificate=True,
                )
            except ValueError as exc:
                parser.error(str(exc))

            logger = NightReconLogger(args.logs_dir)

            if not scope.is_authorized(target):
                logger.write(
                    "infra.database.rejected",
                    target=target.value,
                    target_type=target.target_type.value,
                    scope=args.scope,
                    reason="outside_authorized_scope",
                )
                parser.error(
                    f"Target '{target.value}' is outside the authorized scope."
                )

            session = ScanSession.create(
                target=target,
                scope_rules=tuple(args.scope),
            )
            policy = InfrastructureAssessmentPolicy(
                scope=scope,
                allowed_transports=(
                    InfrastructureTransport.DATABASE,
                ),
                max_actions=args.max_actions,
            )
            state = InfrastructureActionState(
                actions_used=0,
                max_actions=args.max_actions,
            )
            reference = CredentialReference(
                credential_id=credential_id,
                kind=CredentialKind.PASSWORD,
                source_kind=CredentialSourceKind.ENVIRONMENT,
            )
            binding = CredentialBinding(
                reference=reference,
                source_name=args.password_env,
            )
            runtime_factory = (
                PsycopgRuntimeFactory()
                if engine == DatabaseEngine.POSTGRESQL
                else MySqlRuntimeFactory()
            )
            adapter = DatabaseReadOnlyAdapter(
                profile,
                runtime_factory,
            )
            records = []

            for action_id in args.infra_actions:
                definition = get_infrastructure_action_definition(
                    action_id
                )
                action = InfrastructureAction(
                    target=target.value,
                    transport=InfrastructureTransport.DATABASE,
                    action_id=action_id,
                    credential_id=credential_id,
                )
                decision = authorize_infrastructure_action(
                    action=action,
                    definition=definition,
                    credential=reference,
                    policy=policy,
                    state=state,
                )

                if not decision.allowed:
                    logger.write(
                        "infra.database.action_rejected",
                        session_id=session.session_id,
                        target=target.value,
                        transport="database",
                        engine=engine.value,
                        action_id=action_id,
                        credential_id=credential_id,
                        reason=decision.reason,
                    )
                    parser.error(
                        "Database action was rejected by the infrastructure policy: "
                        f"{decision.reason}"
                    )

                try:
                    credential = resolve_credential(
                        binding,
                        ttl_seconds=max(
                            30.0,
                            args.connect_timeout
                            + args.operation_timeout
                            + 5.0,
                        ),
                    )
                except CredentialResolutionError:
                    logger.write(
                        "infra.database.credential_resolution_failed",
                        session_id=session.session_id,
                        target=target.value,
                        transport="database",
                        engine=engine.value,
                        action_id=action_id,
                        credential_id=credential_id,
                        reason="credential_resolution_failed",
                    )
                    parser.error(
                        "Database credential could not be resolved from the configured "
                        "environment source."
                    )

                result = execute_infrastructure_action(
                    action=action,
                    definition=definition,
                    decision=decision,
                    state=state,
                    credential=credential,
                    adapter=adapter,
                )
                state = result.state
                records.append(
                    InfrastructureActionRecord.from_result(result)
                )

            infra_report = DatabaseInfrastructureAssessmentReport.create(
                session=session,
                engine=engine.value,
                username=profile.username,
                database_name=profile.database_name,
                port=profile.port,
                max_actions=args.max_actions,
                max_schemas=profile.max_schemas,
                records=tuple(records),
            )
            output_path = ResultStore(
                args.results_dir
            ).save_infrastructure_assessment_report(infra_report)
            summary = infra_report.to_dict()["summary"]

            logger.write(
                "infra.database.completed",
                session_id=session.session_id,
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                transport="database",
                engine=engine.value,
                username=profile.username,
                database_name=profile.database_name,
                port=profile.port,
                authentication="password",
                tls_required=True,
                certificate_validation="required",
                credential_id=credential_id,
                max_schemas=profile.max_schemas,
                selected_actions=summary["selected_actions"],
                attempted_actions=summary["attempted_actions"],
                successful_actions=summary["successful_actions"],
                failed_actions=summary["failed_actions"],
                status=infra_report.status,
            )

            print(
                "Database Assessment Summary: "
                f"engine={engine.value} "
                f"selected={summary['selected_actions']} "
                f"attempted={summary['attempted_actions']} "
                f"successful={summary['successful_actions']} "
                f"failed={summary['failed_actions']}"
            )

            for record in infra_report.records:
                print(
                    "  DATABASE ACTION "
                    f"{record.action_id} "
                    f"success={'yes' if record.success else 'no'} "
                    f"reason={record.reason}"
                )
                for fact in record.facts:
                    print(
                        "    FACT "
                        f"{fact['key']}={fact['value']}"
                    )

            print(f"Session ID: {session.session_id}")
            print(f"Infrastructure result file: {output_path}")
            return

        if args.infra_command != "ssh":
            parser.error(
                "The infra command requires a supported subcommand."
            )

        try:
            target = parse_target(
                args.target
            )

            if target.target_type == TargetType.CIDR:
                raise ValueError(
                    "SSH infrastructure assessment requires a single host or IP target."
                )

            scope = Scope.from_values(
                args.scope
            )

            if args.max_actions < 1:
                raise ValueError(
                    "max_actions must be at least 1."
                )

            if len(
                args.infra_actions
            ) > args.max_actions:
                raise ValueError(
                    "Selected SSH actions exceed max_actions."
                )

            credential_id = (
                args.credential_id.strip()
            )

            if (
                not credential_id
                or len(credential_id) > 128
                or not all(
                    character.isalnum()
                    or character in "._-"
                    for character in credential_id
                )
            ):
                raise ValueError(
                    "credential_id must contain only letters, numbers, '.', '_', or '-'."
                )

            profile = SshConnectionProfile(
                username=args.username,
                known_hosts_file=args.known_hosts,
                port=args.port,
                connect_timeout=args.connect_timeout,
                command_timeout=args.command_timeout,
                max_output_bytes=args.max_output_bytes,
            )
        except ValueError as exc:
            parser.error(
                str(
                    exc
                )
            )

        logger = NightReconLogger(
            args.logs_dir
        )

        if not scope.is_authorized(
            target
        ):
            logger.write(
                "infra.ssh.rejected",
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                reason="outside_authorized_scope",
            )
            parser.error(
                f"Target '{target.value}' is outside the authorized scope."
            )

        session = ScanSession.create(
            target=target,
            scope_rules=tuple(
                args.scope
            ),
        )
        policy = InfrastructureAssessmentPolicy(
            scope=scope,
            allowed_transports=(
                InfrastructureTransport.SSH,
            ),
            max_actions=args.max_actions,
        )
        state = InfrastructureActionState(
            actions_used=0,
            max_actions=args.max_actions,
        )
        reference = CredentialReference(
            credential_id=credential_id,
            kind=CredentialKind.PASSWORD,
            source_kind=CredentialSourceKind.ENVIRONMENT,
        )
        binding = CredentialBinding(
            reference=reference,
            source_name=args.password_env,
        )
        adapter = SshReadOnlyAdapter(
            profile
        )
        records = []

        for action_id in args.infra_actions:
            definition = (
                get_infrastructure_action_definition(
                    action_id
                )
            )
            action = InfrastructureAction(
                target=target.value,
                transport=InfrastructureTransport.SSH,
                action_id=action_id,
                credential_id=credential_id,
            )
            decision = authorize_infrastructure_action(
                action=action,
                definition=definition,
                credential=reference,
                policy=policy,
                state=state,
            )

            if not decision.allowed:
                logger.write(
                    "infra.ssh.action_rejected",
                    session_id=session.session_id,
                    target=target.value,
                    transport="ssh",
                    action_id=action_id,
                    credential_id=credential_id,
                    reason=decision.reason,
                )
                parser.error(
                    "SSH action was rejected by the infrastructure policy: "
                    f"{decision.reason}"
                )

            try:
                credential = resolve_credential(
                    binding,
                    ttl_seconds=max(
                        30.0,
                        args.connect_timeout
                        + args.command_timeout
                        + 5.0,
                    ),
                )
            except CredentialResolutionError:
                logger.write(
                    "infra.ssh.credential_resolution_failed",
                    session_id=session.session_id,
                    target=target.value,
                    transport="ssh",
                    action_id=action_id,
                    credential_id=credential_id,
                    reason="credential_resolution_failed",
                )
                parser.error(
                    "SSH credential could not be resolved from the configured "
                    "environment source."
                )

            result = execute_infrastructure_action(
                action=action,
                definition=definition,
                decision=decision,
                state=state,
                credential=credential,
                adapter=adapter,
            )
            state = result.state
            records.append(
                InfrastructureActionRecord.from_result(
                    result
                )
            )

        infra_report = (
            InfrastructureAssessmentReport.create(
                session=session,
                transport="ssh",
                username=profile.username,
                port=profile.port,
                max_actions=args.max_actions,
                records=tuple(
                    records
                ),
            )
        )
        output_path = ResultStore(
            args.results_dir
        ).save_infrastructure_assessment_report(
            infra_report
        )
        summary = infra_report.to_dict()[
            "summary"
        ]

        logger.write(
            "infra.ssh.completed",
            session_id=session.session_id,
            target=target.value,
            target_type=target.target_type.value,
            scope=args.scope,
            transport="ssh",
            username=profile.username,
            port=profile.port,
            host_key_policy="reject",
            credential_id=credential_id,
            selected_actions=summary[
                "selected_actions"
            ],
            attempted_actions=summary[
                "attempted_actions"
            ],
            successful_actions=summary[
                "successful_actions"
            ],
            failed_actions=summary[
                "failed_actions"
            ],
            status=infra_report.status,
        )

        print(
            "SSH Assessment Summary: "
            f"selected={summary['selected_actions']} "
            f"attempted={summary['attempted_actions']} "
            f"successful={summary['successful_actions']} "
            f"failed={summary['failed_actions']}"
        )

        for record in infra_report.records:
            print(
                "  SSH ACTION "
                f"{record.action_id} "
                f"success={'yes' if record.success else 'no'} "
                f"reason={record.reason}"
            )

            for fact in record.facts:
                print(
                    "    FACT "
                    f"{fact['key']}={fact['value']}"
                )

        print(
            f"Session ID: {session.session_id}"
        )
        print(
            f"Infrastructure result file: {output_path}"
        )
        return

    if args.command == "api":
        if args.api_command in {
            "graphql-inspect",
            "graphql-introspect",
        }:
            try:
                raw_endpoint = args.endpoint_url.strip()
                raw_parts = urlsplit(
                    raw_endpoint
                )

                if (
                    raw_parts.username is not None
                    or raw_parts.password is not None
                    or raw_parts.query
                    or raw_parts.fragment
                ):
                    raise ValueError(
                        "GraphQL endpoint URL must not contain credentials, "
                        "query data, or a fragment."
                    )

                endpoint_url = normalize_http_url(
                    raw_endpoint
                )
                endpoint_origin = url_origin(
                    endpoint_url
                )
                hostname = urlsplit(
                    endpoint_url
                ).hostname

                if hostname is None:
                    raise ValueError(
                        "GraphQL endpoint URL must include a hostname."
                    )

                target = parse_target(
                    hostname
                )
                scope = Scope.from_values(
                    args.scope
                )

                if args.api_command == "graphql-inspect":
                    if args.max_spec_bytes < 1:
                        raise ValueError(
                            "max_spec_bytes must be at least 1."
                        )

                    graphql_schema = load_graphql_introspection_json(
                        args.introspection,
                        max_bytes=args.max_spec_bytes,
                    )
                    authorization = None
                else:
                    if args.max_response_bytes < 1:
                        raise ValueError(
                            "max_response_bytes must be at least 1."
                        )

                    if args.timeout <= 0:
                        raise ValueError(
                            "timeout must be greater than 0."
                        )

                    authorization = None

                    if args.authorization_env:
                        authorization = os.environ.get(
                            args.authorization_env
                        )

                        if (
                            authorization is None
                            or not authorization.strip()
                        ):
                            raise ValueError(
                                "Authorization environment variable "
                                f"'{args.authorization_env}' is missing or empty."
                            )
            except (
                OSError,
                ValueError,
            ) as exc:
                parser.error(str(exc))

            logger = NightReconLogger(
                args.logs_dir
            )

            if not scope.is_authorized(
                target
            ):
                logger.write(
                    "api.graphql.rejected",
                    endpoint_url=endpoint_url,
                    target=target.value,
                    target_type=target.target_type.value,
                    scope=args.scope,
                    reason="outside_authorized_scope",
                )
                parser.error(
                    f"Target '{target.value}' is outside the authorized scope."
                )

            source = "saved-introspection"

            if args.api_command == "graphql-introspect":
                result = execute_graphql_introspection(
                    endpoint_url=endpoint_url,
                    origin=endpoint_origin,
                    authorized=scope.is_authorized(
                        target
                    ),
                    timeout=args.timeout,
                    max_response_bytes=args.max_response_bytes,
                    authorization=authorization,
                )

                if (
                    not result.success
                    or result.schema is None
                ):
                    logger.write(
                        "api.graphql.introspection_failed",
                        endpoint_url=endpoint_url,
                        target=target.value,
                        target_type=target.target_type.value,
                        scope=args.scope,
                        reason=result.reason,
                        status=result.status,
                        byte_count=result.byte_count,
                    )
                    parser.error(
                        "GraphQL introspection failed: "
                        f"{result.reason}"
                    )

                graphql_schema = result.schema
                source = "live-introspection"

            session = ScanSession.create(
                target=target,
                scope_rules=tuple(
                    args.scope
                ),
            )
            graphql_report = GraphQLSchemaReport.create(
                session=session,
                endpoint_url=endpoint_url,
                source=source,
                schema=graphql_schema,
            )
            output_path = ResultStore(
                args.results_dir
            ).save_graphql_schema_report(
                graphql_report
            )
            summary = graphql_report.to_dict()[
                "summary"
            ]

            logger.write(
                "api.graphql.completed",
                session_id=session.session_id,
                endpoint_url=endpoint_url,
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                source=source,
                types=summary["types"],
                fields=summary["fields"],
                query_type=summary["query_type"],
                mutation_type=summary["mutation_type"],
                subscription_type=summary["subscription_type"],
                status=graphql_report.status,
            )

            print(
                "GraphQL Schema Summary: "
                f"source={source} "
                f"types={summary['types']} "
                f"fields={summary['fields']} "
                f"query={summary['query_type'] or '-'} "
                f"mutation={summary['mutation_type'] or '-'} "
                f"subscription={summary['subscription_type'] or '-'}"
            )

            for gql_type in graphql_report.types:
                if not gql_type["fields"]:
                    continue

                print(
                    "  GRAPHQL TYPE "
                    f"{gql_type['kind']} {gql_type['name']} "
                    f"fields={len(gql_type['fields'])}"
                )

                for field in gql_type["fields"]:
                    arguments = (
                        ",".join(
                            (
                                f"{argument['name']}:"
                                f"{argument['type_name'] or argument['type_kind'] or '-'}"
                                f"{'!' if argument['required'] else ''}"
                            )
                            for argument in field["arguments"]
                        )
                        if field["arguments"]
                        else "-"
                    )
                    print(
                        "    GRAPHQL FIELD "
                        f"{field['name']} "
                        "returns="
                        f"{field['return_type_name'] or field['return_type_kind'] or '-'} "
                        f"args={arguments}"
                    )

            print(
                f"Session ID: {session.session_id}"
            )
            print(
                f"GraphQL result file: {output_path}"
            )
            return

        if args.api_command == "probe":
            try:
                if args.max_spec_bytes < 1:
                    raise ValueError(
                        "max_spec_bytes must be at least 1."
                    )

                if args.max_requests < 1:
                    raise ValueError(
                        "max_requests must be at least 1."
                    )

                if args.max_response_bytes < 1:
                    raise ValueError(
                        "max_response_bytes must be at least 1."
                    )

                if args.timeout <= 0:
                    raise ValueError(
                        "timeout must be greater than 0."
                    )

                raw_base = args.base_url.strip()
                raw_parts = urlsplit(
                    raw_base
                )

                if (
                    raw_parts.username is not None
                    or raw_parts.password is not None
                ):
                    raise ValueError(
                        "--base-url must not contain URL credentials."
                    )

                if raw_parts.query or raw_parts.fragment:
                    raise ValueError(
                        "--base-url must not contain a query string or fragment."
                    )

                normalized_base = normalize_http_url(
                    raw_base
                )
                base_origin = url_origin(
                    normalized_base
                )
                hostname = urlsplit(
                    normalized_base
                ).hostname

                if hostname is None:
                    raise ValueError(
                        "--base-url must include a hostname."
                    )

                target = parse_target(
                    hostname
                )
                scope = Scope.from_values(
                    args.scope
                )
                inventory = load_api_description(
                    args.spec,
                    max_bytes=args.max_spec_bytes,
                )
                selections = select_api_operations(
                    inventory=inventory,
                    selectors=tuple(
                        args.api_operations
                    ),
                    base_url=normalized_base,
                )

                if len(selections) > args.max_requests:
                    raise ValueError(
                        "Selected API operations exceed max_requests."
                    )

                authorization = None

                if args.authorization_env:
                    authorization = os.environ.get(
                        args.authorization_env
                    )

                    if (
                        authorization is None
                        or not authorization.strip()
                    ):
                        raise ValueError(
                            "Authorization environment variable "
                            f"'{args.authorization_env}' is missing or empty."
                        )
            except ApiDescriptionRuntimeUnavailable as exc:
                parser.error(str(exc))
            except (
                OSError,
                ValueError,
            ) as exc:
                parser.error(str(exc))

            logger = NightReconLogger(
                args.logs_dir
            )

            if not scope.is_authorized(
                target
            ):
                logger.write(
                    "api.probe.rejected",
                    base_origin=base_origin,
                    target=target.value,
                    target_type=target.target_type.value,
                    scope=args.scope,
                    reason="outside_authorized_scope",
                )
                parser.error(
                    f"Target '{target.value}' is outside the authorized scope."
                )

            session = ScanSession.create(
                target=target,
                scope_rules=tuple(
                    args.scope
                ),
            )
            policy = ApiRequestPolicy(
                origin=base_origin,
                max_requests=args.max_requests,
            )
            state = ApiRequestState(
                requests_used=0,
                max_requests=args.max_requests,
            )
            records = []

            for selection in selections:
                request = ApiRequest(
                    url=selection.url,
                    method=selection.operation.method,
                    operation_id=selection.operation.operation_id,
                )
                decision = authorize_api_request(
                    request=request,
                    policy=policy,
                    state=state,
                )

                if not decision.allowed:
                    raise ValueError(
                        "API request policy rejected selected operation "
                        f"'{selection.selector}': {decision.reason}"
                    )

                result = execute_api_request(
                    request=request,
                    decision=decision,
                    state=state,
                    origin=base_origin,
                    authorized=scope.is_authorized(
                        target
                    ),
                    timeout=args.timeout,
                    max_response_bytes=args.max_response_bytes,
                    authorization=authorization,
                )
                state = result.state
                records.append(
                    ApiValidationRecord.from_result(
                        selection=selection,
                        result=result,
                    )
                )

            api_inventory_report = ApiInventoryReport.create(
                session=session,
                base_origin=base_origin,
                inventory=inventory,
            )
            validation_report = ApiValidationReport.create(
                session=session,
                base_origin=base_origin,
                max_requests=args.max_requests,
                max_response_bytes=args.max_response_bytes,
                records=tuple(
                    records
                ),
            )
            store = ResultStore(
                args.results_dir
            )
            inventory_path = store.save_api_inventory_report(
                api_inventory_report
            )
            validation_path = store.save_api_validation_report(
                validation_report
            )
            summary = validation_report.to_dict()[
                "summary"
            ]

            logger.write(
                "api.probe.completed",
                session_id=session.session_id,
                base_origin=base_origin,
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                selected_operations=summary[
                    "selected_operations"
                ],
                attempted_requests=summary[
                    "attempted_requests"
                ],
                successful_requests=summary[
                    "successful_requests"
                ],
                failed_requests=summary[
                    "failed_requests"
                ],
                status=validation_report.status,
            )

            print(
                "API Validation Summary: "
                f"selected={summary['selected_operations']} "
                f"attempted={summary['attempted_requests']} "
                f"successful={summary['successful_requests']} "
                f"failed={summary['failed_requests']}"
            )

            for record in validation_report.records:
                print(
                    "  API PROBE "
                    f"{record.method} {record.url} "
                    f"selector={record.selector} "
                    f"success={'yes' if record.success else 'no'} "
                    f"status={record.status if record.status is not None else '-'} "
                    f"reason={record.reason} "
                    f"bytes={record.byte_count}"
                )

            print(
                f"Session ID: {session.session_id}"
            )
            print(
                f"API inventory file: {inventory_path}"
            )
            print(
                f"API validation file: {validation_path}"
            )
            return

        if args.api_command != "inspect":
            parser.error(
                "The api command requires a subcommand."
            )

        try:
            if args.max_spec_bytes < 1:
                raise ValueError(
                    "max_spec_bytes must be at least 1."
                )

            raw_base = args.base_url.strip()
            raw_parts = urlsplit(
                raw_base
            )

            if (
                raw_parts.username is not None
                or raw_parts.password is not None
            ):
                raise ValueError(
                    "--base-url must not contain URL credentials."
                )

            if raw_parts.query or raw_parts.fragment:
                raise ValueError(
                    "--base-url must not contain a query string or fragment."
                )

            normalized_base = normalize_http_url(
                raw_base
            )
            base_origin = url_origin(
                normalized_base
            )
            hostname = urlsplit(
                normalized_base
            ).hostname

            if hostname is None:
                raise ValueError(
                    "--base-url must include a hostname."
                )

            target = parse_target(
                hostname
            )
            scope = Scope.from_values(
                args.scope
            )
            inventory = load_api_description(
                args.spec,
                max_bytes=args.max_spec_bytes,
            )
        except ApiDescriptionRuntimeUnavailable as exc:
            parser.error(str(exc))
        except (
            OSError,
            ValueError,
        ) as exc:
            parser.error(str(exc))

        logger = NightReconLogger(
            args.logs_dir
        )

        if not scope.is_authorized(
            target
        ):
            logger.write(
                "api.inspect.rejected",
                base_origin=base_origin,
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                reason="outside_authorized_scope",
            )
            parser.error(
                f"Target '{target.value}' is outside the authorized scope."
            )

        session = ScanSession.create(
            target=target,
            scope_rules=tuple(
                args.scope
            ),
        )
        api_report = ApiInventoryReport.create(
            session=session,
            base_origin=base_origin,
            inventory=inventory,
        )
        output_path = ResultStore(
            args.results_dir
        ).save_api_inventory_report(
            api_report
        )
        summary = api_report.to_dict()[
            "summary"
        ]

        logger.write(
            "api.inspect.completed",
            session_id=api_report.session_id,
            base_origin=api_report.base_origin,
            target=api_report.target,
            target_type=api_report.target_type,
            scope=args.scope,
            specification=api_report.specification,
            specification_version=api_report.specification_version,
            operations=summary["operations"],
            safe_operations=summary["safe_operations"],
            mutating_operations=summary["mutating_operations"],
            external_references=summary["external_references"],
            status=api_report.status,
        )

        print(
            "API Description: "
            f"{api_report.specification} "
            f"{api_report.specification_version}"
        )
        print(
            f"API Title: {api_report.title or '-'}"
        )
        print(
            f"API Version: {api_report.api_version or '-'}"
        )
        print(
            "API Summary: "
            f"operations={summary['operations']} "
            f"safe={summary['safe_operations']} "
            f"mutating={summary['mutating_operations']} "
            f"servers={summary['servers']} "
            f"security_schemes={summary['security_schemes']} "
            f"external_refs={summary['external_references']}"
        )

        for server in api_report.servers:
            server_origin = ""

            try:
                server_origin = url_origin(
                    normalize_http_url(
                        server
                    )
                )
            except ValueError:
                pass

            print(
                "  API SERVER "
                f"{server} "
                "same_origin="
                f"{'yes' if server_origin == base_origin else 'no'}"
            )

        for operation in api_report.operations:
            parameters = (
                ",".join(
                    (
                        f"{parameter.location}:"
                        f"{parameter.name}:"
                        f"{parameter.schema_type or '-'}"
                    )
                    for parameter in operation.parameters
                )
                if operation.parameters
                else "-"
            )
            print(
                "  API OPERATION "
                f"{operation.method} {operation.path} "
                f"id={operation.operation_id or '-'} "
                f"params={parameters}"
            )

        for reference in (
            api_report.external_references_observed
        ):
            print(
                f"  API EXTERNAL REF {reference}"
            )

        print(
            f"Session ID: {api_report.session_id}"
        )
        print(
            f"API result file: {output_path}"
        )
        return

    if args.command == "assets":
        if args.assets_command == "history":
            try:
                history = AssetInventoryStore(
                    args.inventory_dir
                ).load_change_history(
                    address=args.address,
                    limit=args.limit,
                )
            except ValueError as exc:
                parser.error(str(exc))

            print(f"Asset changes: {len(history)}")

            for event in history:
                change = event.change
                line = (
                    f"ASSET CHANGE {change.address} "
                    f"{change.change_type}"
                )

                if change.port is not None:
                    line += f" port={change.port}"

                if change.before:
                    line += f" before={change.before}"

                if change.after:
                    line += f" after={change.after}"

                line += (
                    f" source={event.source_type}"
                    f" session={event.session_id}"
                    f" observed_at={event.observed_at}"
                )
                print(line)

            return

        if args.assets_command != "list":
            parser.error(
                "The assets command requires a subcommand."
            )

        try:
            inventory = AssetInventoryStore(
                args.inventory_dir
            ).load()
        except ValueError as exc:
            parser.error(str(exc))

        print(f"Assets: {len(inventory.assets)}")

        for asset in inventory.assets:
            hostnames = (
                ",".join(asset.hostnames)
                if asset.hostnames
                else "-"
            )
            services = (
                ",".join(
                    (
                        f"{service.port}/{service.service}/"
                        f"{service.product or '-'}/"
                        f"{service.version or '-'}"
                    )
                    for service in asset.services
                )
                if asset.services
                else "-"
            )

            print(
                f"ASSET {asset.address} "
                f"hostnames={hostnames} "
                f"services={services}"
            )

        return

    if args.command == "checks":
        if args.checks_command == "feed":
            selected_actions = sum(
                bool(value)
                for value in (
                    args.install_pack,
                    args.sync,
                    args.plan,
                    args.list_installed,
                    args.rollback_pack,
                )
            )

            if selected_actions > 1:
                parser.error(
                    "Choose only one of --install-pack, --sync, --plan, "
                    "--list-installed, or --rollback-pack."
                )

            if args.list_installed:
                store = CheckPackStore(
                    args.store_dir
                )
                pack_ids = store.list_pack_ids()

                if not pack_ids:
                    print("No installed check packs.")

                for pack_id in pack_ids:
                    active = store.active_version(
                        pack_id
                    )
                    print(
                        f"Installed Pack: {pack_id} "
                        f"active={active or '-'}"
                    )

                    for record in store.list_versions(
                        pack_id
                    ):
                        marker = (
                            "yes"
                            if record.version == active
                            else "no"
                        )
                        print(
                            f"  version={record.version} "
                            f"active={marker} "
                            f"signer={record.signer_key_id or '-'} "
                            f"sha256={record.sha256 or '-'}"
                        )

                return

            if args.rollback_pack:
                if not args.feed_pack_keys:
                    parser.error(
                        "--rollback-pack requires --pack-key."
                    )

                try:
                    trusted_pack_keys = parse_trusted_key_specs(
                        tuple(args.feed_pack_keys or ())
                    )
                    store = CheckPackStore(
                        args.store_dir
                    )
                    restored = store.rollback_verified(
                        args.rollback_pack,
                        trusted_keys=trusted_pack_keys,
                    )
                except ValueError as exc:
                    parser.error(str(exc))

                print(
                    f"Rolled back: {args.rollback_pack} "
                    f"active={restored}"
                )
                return

            if not args.url:
                parser.error(
                    "--url is required unless using "
                    "--list-installed or --rollback-pack."
                )

            if not args.feed_keys:
                parser.error(
                    "--feed-key is required for feed operations."
                )

            if (
                (args.install_pack or args.sync)
                and not args.feed_pack_keys
            ):
                option = (
                    "--install-pack"
                    if args.install_pack
                    else "--sync"
                )
                parser.error(
                    f"{option} requires --pack-key."
                )

            try:
                trusted_feed_keys = parse_trusted_key_specs(
                    tuple(args.feed_keys or ())
                )
                feed = fetch_signed_check_feed(
                    args.url,
                    trusted_keys=trusted_feed_keys,
                )
            except ValueError as exc:
                parser.error(str(exc))

            print(
                f"Feed: {feed.feed_id} "
                f"generated_at={feed.generated_at or '-'}"
            )

            if not feed.packs:
                print("No check packs advertised.")

            for entry in feed.packs:
                print(
                    f"{entry.pack_id} "
                    f"version={entry.version} "
                    f"signer={entry.signer_key_id} "
                    f"sha256={entry.sha256} "
                    f"url={entry.url}"
                )

            if args.plan:
                try:
                    store = CheckPackStore(
                        args.store_dir
                    )
                    store.validate_feed(
                        feed,
                        source_url=args.url,
                    )
                    plans = plan_verified_check_feed(
                        feed=feed,
                        store=store,
                    )
                except ValueError as exc:
                    parser.error(str(exc))

                for plan in plans:
                    line = (
                        f"PLAN {plan.pack_id} "
                        f"status={plan.status} "
                        f"advertised={plan.advertised_version} "
                        f"active={plan.active_version or '-'} "
                        "download_required="
                        f"{'yes' if plan.download_required else 'no'}"
                    )

                    if plan.error:
                        line += f" error={plan.error}"

                    print(line)

            if args.install_pack:
                try:
                    trusted_pack_keys = parse_trusted_key_specs(
                        tuple(args.feed_pack_keys or ())
                    )
                    store = CheckPackStore(
                        args.store_dir
                    )
                    store.accept_feed(
                        feed,
                        source_url=args.url,
                    )
                    installed = install_pack_from_verified_feed(
                        feed=feed,
                        pack_id=args.install_pack,
                        pack_trusted_keys=trusted_pack_keys,
                        store=store,
                    )
                except ValueError as exc:
                    parser.error(str(exc))

                print(
                    f"Installed: {installed.pack_id} "
                    f"version={installed.version} "
                    f"signer={installed.signer_key_id} "
                    f"sha256={installed.sha256}"
                )

            if args.sync:
                try:
                    trusted_pack_keys = parse_trusted_key_specs(
                        tuple(args.feed_pack_keys or ())
                    )
                    store = CheckPackStore(
                        args.store_dir
                    )
                    store.accept_feed(
                        feed,
                        source_url=args.url,
                    )
                    sync_results = sync_verified_check_feed(
                        feed=feed,
                        pack_trusted_keys=trusted_pack_keys,
                        store=store,
                    )
                except ValueError as exc:
                    parser.error(str(exc))

                for result in sync_results:
                    line = (
                        f"SYNC {result.pack_id} "
                        f"status={result.status} "
                        f"advertised={result.advertised_version} "
                        f"previous={result.previous_version or '-'} "
                        f"active={result.active_version or '-'}"
                    )

                    if result.error:
                        line += f" error={result.error}"

                    print(line)

            return

        if args.checks_command != "list":
            parser.error(
                "The checks command requires a subcommand."
            )

        try:
            pack_checks = _load_requested_check_pack_checks(
                tuple(args.check_pack_paths or ()),
                tuple(args.check_pack_keys or ()),
            )
            installed_checks = (
                _load_installed_check_pack_checks(
                    args.check_store_dir,
                    tuple(args.check_pack_keys or ()),
                )
                if args.installed_check_packs
                else ()
            )
        except ValueError as exc:
            parser.error(str(exc))

        catalog = load_check_catalog(
            additional_checks=(
                pack_checks
                + installed_checks
            )
        )
        registry = CheckRegistry()
        plugin_errors = list(catalog.errors)

        for check in catalog.checks:
            try:
                registry.register(check)
            except ValueError as exc:
                plugin_errors.append(str(exc))

        selected = registry.select(
            check_ids=tuple(args.check_ids or ()),
            families=tuple(args.check_families or ()),
            tags=tuple(args.check_tags or ()),
        )

        if not selected:
            print("No assessment checks matched.")

        for check in selected:
            metadata = check.metadata
            tags = (
                ",".join(metadata.tags)
                if metadata.tags
                else "-"
            )
            services = (
                ",".join(metadata.supported_services)
                if metadata.supported_services
                else "*"
            )

            print(
                f"{metadata.check_id} "
                f"family={metadata.family} "
                "intrusiveness="
                f"{metadata.intrusiveness.value} "
                f"tags={tags} "
                f"services={services}"
            )

        for error in plugin_errors:
            print(
                f"Plugin error: {error}",
                file=sys.stderr,
            )

        return

    if args.command == "discover":
        try:
            target = parse_target(args.target)
            scope = Scope.from_values(args.scope)
            ports = parse_ports(args.ports)

            config = NightReconConfig(
                connect_timeout=args.timeout,
                max_workers=args.workers,
                results_dir=args.results_dir,
                logs_dir=args.logs_dir,
            )
        except ValueError as exc:
            parser.error(str(exc))

        logger = NightReconLogger(
            config.logs_dir
        )

        if not scope.is_authorized(target):
            logger.write(
                "discovery.rejected",
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                reason="outside_authorized_scope",
            )
            parser.error(
                f"Target '{target.value}' is outside the authorized scope."
            )

        if target.target_type != TargetType.CIDR:
            logger.write(
                "discovery.rejected",
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                reason="cidr_required",
            )
            parser.error(
                "discover requires a CIDR target."
            )

        try:
            discovery_results = discover_hosts(
                cidr=target.value,
                ports=ports,
                timeout=config.connect_timeout,
                max_workers=config.max_workers,
                max_hosts=args.max_hosts,
            )

            if args.reverse_dns:
                discovery_results = enrich_reverse_dns(
                    discovery_results,
                    max_workers=config.max_workers,
                )
        except ValueError as exc:
            logger.write(
                "discovery.failed",
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                reason=str(exc),
            )
            parser.error(str(exc))

        session = ScanSession.create(
            target=target,
            scope_rules=tuple(args.scope),
        )
        discovery_report = HostDiscoveryReport.create(
            session=session,
            ports_requested=ports,
            max_hosts=args.max_hosts,
            results=discovery_results,
        )
        store = ResultStore(
            config.results_dir
        )
        output_path = store.save_discovery_report(
            discovery_report
        )

        inventory_update = None
        inventory_path = None

        if args.update_inventory:
            try:
                inventory_store = AssetInventoryStore(
                    args.inventory_dir
                )
                current_inventory = inventory_store.load()
                inventory_update = apply_discovery_report(
                    current_inventory,
                    discovery_report,
                )
                inventory_path = inventory_store.save(
                    inventory_update.inventory
                )
                inventory_store.append_change_events(
                    tuple(
                        AssetChangeEvent(
                            observed_at=discovery_report.created_at,
                            session_id=discovery_report.session_id,
                            source_type="discovery",
                            change=change,
                        )
                        for change in inventory_update.changes
                    )
                )
            except ValueError as exc:
                parser.error(str(exc))

        logger.write(
            "discovery.completed",
            session_id=discovery_report.session_id,
            target=discovery_report.target,
            target_type=discovery_report.target_type,
            scope=args.scope,
            ports=list(
                discovery_report.ports_requested
            ),
            hosts_tested=len(
                discovery_report.results
            ),
            responsive_hosts=[
                result.address
                for result in discovery_report.responsive_hosts
            ],
            status=discovery_report.status,
        )

        print(
            "NightRecon discovery target: "
            f"{discovery_report.target}"
        )
        print(
            f"Target type: {discovery_report.target_type}"
        )
        print("Scope authorization: approved")
        print(
            "Discovery ports: "
            f"{','.join(str(port) for port in discovery_report.ports_requested)}"
        )
        print(
            f"Hosts tested: {len(discovery_report.results)}"
        )
        print(
            "Responsive hosts: "
            f"{len(discovery_report.responsive_hosts)}"
        )

        for result in discovery_report.responsive_hosts:
            port_text = (
                str(result.port)
                if result.port is not None
                else "-"
            )
            line = (
                f"  RESPONSIVE {result.address} "
                f"method={result.method} "
                f"observation={result.observation} "
                f"port={port_text}"
            )

            if result.hostname:
                line += (
                    f" hostname={result.hostname}"
                )

            print(line)

        print(
            f"Session ID: {discovery_report.session_id}"
        )
        print(
            f"Session status: {discovery_report.status}"
        )
        print(
            f"Connection timeout: {config.connect_timeout}"
        )
        print(
            f"Max workers: {config.max_workers}"
        )
        print(
            f"Max hosts: {args.max_hosts}"
        )
        print(
            f"Result file: {output_path}"
        )
        if inventory_update is not None:
            print(
                f"Inventory changes: {len(inventory_update.changes)}"
            )

            for change in inventory_update.changes:
                line = (
                    f"ASSET CHANGE {change.address} "
                    f"{change.change_type}"
                )

                if change.port is not None:
                    line += f" port={change.port}"

                if change.before:
                    line += f" before={change.before}"

                if change.after:
                    line += f" after={change.after}"

                print(line)

            print(
                f"Inventory file: {inventory_path}"
            )

        return

    if args.command == "crawl":
        try:
            normalized_url = normalize_http_url(
                args.url
            )
            hostname = urlsplit(
                normalized_url
            ).hostname

            if hostname is None:
                raise ValueError(
                    "URL must include a hostname."
                )

            target = parse_target(hostname)
            scope = Scope.from_values(
                args.scope
            )
            config = NightReconConfig(
                connect_timeout=args.timeout,
                max_workers=1,
                results_dir=args.results_dir,
                logs_dir=args.logs_dir,
            )

            authorization = None
            cookie = None
            session_cookie_jar = (
                CookieJar()
                if args.session_cookies
                else None
            )

            if (
                args.session_cookies
                and args.cookie_env
            ):
                raise ValueError(
                    "--session-cookies cannot be combined with --cookie-env."
                )

            if args.workflow_get_urls and not args.workflow:
                raise ValueError(
                    "--workflow-get requires --workflow."
                )

            if args.workflow and args.workflow_max_actions < 1:
                raise ValueError(
                    "workflow_max_actions must be at least 1."
                )

            if args.workflow_get_urls and args.cookie_env:
                raise ValueError(
                    "--workflow-get does not accept raw --cookie-env context; "
                    "use --session-cookies for ephemeral cookie continuity."
                )

            workflow_get_urls = tuple(
                normalize_http_url(value)
                for value in (args.workflow_get_urls or ())
            )

            if any(
                url_origin(value) != url_origin(normalized_url)
                for value in workflow_get_urls
            ):
                raise ValueError(
                    "--workflow-get URLs must use the crawl's exact origin."
                )

            if (
                args.browser_discovery
                and urlsplit(
                    normalized_url
                ).query
            ):
                raise ValueError(
                    "--browser-discovery start URL must not include "
                    "a query string."
                )

            if (
                args.browser_discovery
                and (
                    args.authorization_env
                    or args.cookie_env
                    or args.session_cookies
                )
            ):
                raise ValueError(
                    "--browser-discovery does not yet accept authenticated "
                    "crawl context; omit --authorization-env, --cookie-env, "
                    "and --session-cookies for v0.26 browser discovery."
                )

            browser_policy = (
                BrowserDiscoveryPolicy(
                    origin=url_origin(
                        normalized_url
                    ),
                    max_requests=args.browser_max_requests,
                    max_pages=args.browser_max_pages,
                    max_runtime_seconds=args.browser_max_runtime,
                    max_response_bytes=args.browser_max_response_bytes,
                    max_dom_bytes=args.browser_max_dom_bytes,
                    max_dom_items=args.browser_max_dom_items,
                )
                if args.browser_discovery
                else None
            )

            if args.authorization_env:
                authorization = os.environ.get(
                    args.authorization_env
                )

                if (
                    authorization is None
                    or not authorization.strip()
                ):
                    raise ValueError(
                        "Authorization environment variable "
                        f"'{args.authorization_env}' is missing or empty."
                    )

            if args.cookie_env:
                cookie = os.environ.get(
                    args.cookie_env
                )

                if cookie is None or not cookie.strip():
                    raise ValueError(
                        "Cookie environment variable "
                        f"'{args.cookie_env}' is missing or empty."
                    )

            if (
                args.assessment
                and args.max_web_assessment_intrusiveness == "safe-active"
                and args.max_web_assessment_requests < 1
            ):
                raise ValueError(
                    "max_web_assessment_requests must be at least 1."
                )

            if args.dast_cors:
                if not args.assessment:
                    raise ValueError(
                        "--dast-cors requires --assessment."
                    )

                if (
                    args.max_web_assessment_intrusiveness
                    != "safe-active"
                ):
                    raise ValueError(
                        "--dast-cors requires "
                        "--max-web-assessment-intrusiveness safe-active."
                    )

                if args.cookie_env:
                    raise ValueError(
                        "--dast-cors does not accept raw --cookie-env context; "
                        "use --session-cookies for ephemeral cookie continuity."
                    )

                if not 1 <= args.dast_cors_max_targets <= 5:
                    raise ValueError(
                        "dast_cors_max_targets must be between 1 and 5."
                    )

                if args.dast_max_total_requests < 2:
                    raise ValueError(
                        "dast_max_total_requests must be at least 2."
                    )

                if args.dast_max_family_requests < 2:
                    raise ValueError(
                        "dast_max_family_requests must be at least 2."
                    )

                if args.dast_max_response_bytes < 1:
                    raise ValueError(
                        "dast_max_response_bytes must be at least 1."
                    )

                required_dast_requests = (
                    args.dast_cors_max_targets
                    * 2
                )

                if (
                    required_dast_requests
                    > args.dast_max_total_requests
                ):
                    raise ValueError(
                        "Configured CORS targets exceed "
                        "dast_max_total_requests."
                    )

                if (
                    required_dast_requests
                    > args.dast_max_family_requests
                ):
                    raise ValueError(
                        "Configured CORS targets exceed "
                        "dast_max_family_requests."
                    )
        except ValueError as exc:
            parser.error(str(exc))

        logger = NightReconLogger(
            config.logs_dir
        )

        if not scope.is_authorized(target):
            logger.write(
                "crawl.rejected",
                url=normalized_url,
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                reason="outside_authorized_scope",
            )
            parser.error(
                f"Target '{target.value}' is outside the authorized scope."
            )

        try:
            crawl = crawl_site(
                start_url=normalized_url,
                max_pages=args.max_pages,
                max_bytes_per_page=(
                    args.max_bytes_per_page
                ),
                timeout=config.connect_timeout,
                authorization=authorization,
                cookie=cookie,
                cookie_jar=session_cookie_jar,
            )
        except ValueError as exc:
            logger.write(
                "crawl.failed",
                url=normalized_url,
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                reason=str(exc),
            )
            parser.error(str(exc))

        assessment_findings = (
            assess_web_pages(
                crawl.pages
            )
            if args.assessment
            else ()
        )
        safe_active_requests_attempted = 0
        safe_active_successful_probes = 0
        safe_active_errors: tuple[str, ...] = ()

        if (
            args.assessment
            and args.max_web_assessment_intrusiveness == "safe-active"
        ):
            try:
                safe_active_result = assess_web_pages_safe_active(
                    pages=crawl.pages,
                    origin=crawl.origin,
                    authorized=scope.is_authorized(target),
                    timeout=config.connect_timeout,
                    max_requests=args.max_web_assessment_requests,
                    authorization=authorization,
                    cookie=cookie,
                    cookie_jar=session_cookie_jar,
                )
            except (PermissionError, ValueError) as exc:
                logger.write(
                    "crawl.assessment_failed",
                    url=normalized_url,
                    target=target.value,
                    target_type=target.target_type.value,
                    scope=args.scope,
                    intrusiveness="safe-active",
                    reason=str(exc),
                )
                parser.error(str(exc))

            assessment_findings = (
                assessment_findings
                + safe_active_result.findings
            )
            safe_active_requests_attempted = (
                safe_active_result.requests_attempted
            )
            safe_active_successful_probes = (
                safe_active_result.successful_probes
            )
            safe_active_errors = (
                safe_active_result.errors
            )

        session = ScanSession.create(
            target=target,
            scope_rules=tuple(
                args.scope
            ),
        )

        dast_report = None
        dast_output_path = None

        if args.dast_cors:
            dast_policy = DastBudgetPolicy(
                max_total_requests=(
                    args.dast_max_total_requests
                ),
                default_family_requests=(
                    args.dast_max_family_requests
                ),
                family_limits=(
                    (
                        "cors",
                        args.dast_max_family_requests,
                    ),
                ),
            )

            try:
                dast_result = assess_credentialed_cors(
                    urls=tuple(
                        page.url
                        for page in crawl.pages
                        if not page.error
                    ),
                    origin=crawl.origin,
                    policy=dast_policy,
                    state=DastBudgetState(),
                    authorized=scope.is_authorized(
                        target
                    ),
                    max_targets=(
                        args.dast_cors_max_targets
                    ),
                    timeout=config.connect_timeout,
                    max_response_bytes=(
                        args.dast_max_response_bytes
                    ),
                    authorization=authorization,
                    cookie_jar=session_cookie_jar,
                )
            except (
                PermissionError,
                ValueError,
            ) as exc:
                logger.write(
                    "crawl.dast_failed",
                    session_id=session.session_id,
                    origin=crawl.origin,
                    target=target.value,
                    target_type=target.target_type.value,
                    scope=args.scope,
                    check=(
                        "web.cors.credentialed-origin-reflection"
                    ),
                    reason=exc.__class__.__name__,
                )
                parser.error(
                    "Safe-active DAST was rejected by its safety policy."
                )

            dast_report = DastAssessmentReport.create(
                session=session,
                origin=crawl.origin,
                enabled_checks=(
                    "web.cors.credentialed-origin-reflection",
                ),
                policy=dast_policy,
                state=dast_result.state,
                findings=dast_result.findings,
                evidence_records=(
                    dast_result.evidence_records
                ),
                errors=dast_result.errors,
            )

        browser_report = None
        browser_output_path = None

        if browser_policy is not None:
            try:
                browser_result = discover_with_playwright(
                    start_url=normalized_url,
                    policy=browser_policy,
                    headless=True,
                )
            except BrowserRuntimeUnavailable:
                logger.write(
                    "crawl.browser_failed",
                    session_id=session.session_id,
                    origin=crawl.origin,
                    target=target.value,
                    target_type=target.target_type.value,
                    scope=args.scope,
                    reason="browser_runtime_unavailable",
                )
                parser.error(
                    "Browser runtime unavailable. Install the NightRecon "
                    "browser extra and Chromium runtime."
                )
            except (PermissionError, ValueError) as exc:
                logger.write(
                    "crawl.browser_failed",
                    session_id=session.session_id,
                    url=normalized_url,
                    origin=crawl.origin,
                    target=target.value,
                    target_type=target.target_type.value,
                    scope=args.scope,
                    reason=exc.__class__.__name__,
                )
                parser.error(
                    "Browser discovery was rejected by its safety policy."
                )

            browser_report = BrowserDiscoveryReport.create(
                session=session,
                policy=browser_policy,
                result=browser_result,
            )

        workflow_report = None
        workflow_output_path = None

        if args.workflow:
            planned_actions = build_observed_navigation_plan(
                pages=crawl.pages,
                origin=crawl.origin,
                max_actions=args.workflow_max_actions,
            )
            form_intents = observe_form_intents(
                pages=crawl.pages,
                origin=crawl.origin,
            )
            workflow_policy = WorkflowPolicy(
                origin=crawl.origin,
                max_actions=args.workflow_max_actions,
            )
            workflow_state = WorkflowState(
                current_url=normalized_url,
                visited_urls=(normalized_url,),
                actions_used=0,
                max_actions=args.workflow_max_actions,
            )
            workflow_executions = []

            for workflow_url in workflow_get_urls:
                action = WorkflowAction(
                    kind=WorkflowActionKind.NAVIGATE,
                    source_url=workflow_state.current_url,
                    target_url=workflow_url,
                    method="GET",
                )
                decision = authorize_workflow_action(
                    action=action,
                    policy=workflow_policy,
                    actions_used=workflow_state.actions_used,
                )

                if not decision.allowed:
                    workflow_executions.append(
                        WorkflowExecutionRecord.denied(
                            action=action,
                            decision=decision,
                            actions_used_after=workflow_state.actions_used,
                        )
                    )
                    continue

                result = execute_workflow_navigation(
                    action=action,
                    decision=decision,
                    state=workflow_state,
                    origin=crawl.origin,
                    authorized=scope.is_authorized(target),
                    timeout=config.connect_timeout,
                    max_bytes=args.max_bytes_per_page,
                    authorization=authorization,
                    cookie_jar=session_cookie_jar,
                )
                workflow_executions.append(
                    WorkflowExecutionRecord.completed(
                        action=action,
                        decision=decision,
                        result=result,
                    )
                )

                if result.success:
                    workflow_state = result.state

            workflow_report = WebWorkflowReport.create(
                session=session,
                origin=crawl.origin,
                max_actions=args.workflow_max_actions,
                planned_actions=planned_actions,
                forms=form_intents,
                executions=tuple(workflow_executions),
            )

        crawl_report = WebCrawlReport.create(
            session=session,
            crawl=crawl,
            assessment_enabled=args.assessment,
            assessment_intrusiveness=(
                args.max_web_assessment_intrusiveness
                if args.assessment
                else "disabled"
            ),
            assessment_findings=assessment_findings,
            safe_active_requests_attempted=(
                safe_active_requests_attempted
            ),
            safe_active_successful_probes=(
                safe_active_successful_probes
            ),
            safe_active_errors=safe_active_errors,
        )
        store = ResultStore(
            config.results_dir
        )
        output_path = store.save_web_crawl_report(
            crawl_report
        )

        if workflow_report is not None:
            workflow_output_path = store.save_web_workflow_report(
                workflow_report
            )

        if dast_report is not None:
            dast_output_path = store.save_dast_assessment_report(
                dast_report
            )

        if browser_report is not None:
            browser_output_path = store.save_browser_discovery_report(
                browser_report
            )

        logger.write(
            "crawl.completed",
            session_id=crawl_report.session_id,
            url=crawl_report.start_url,
            origin=crawl_report.origin,
            target=crawl_report.target,
            target_type=crawl_report.target_type,
            scope=args.scope,
            pages_fetched=len(
                crawl_report.pages
            ),
            successful_pages=len(
                crawl_report.successful_pages
            ),
            failed_pages=len(
                crawl_report.failed_pages
            ),
            assessment_enabled=(
                crawl_report.assessment_enabled
            ),
            assessment_findings=len(
                crawl_report.assessment_findings
            ),
            assessment_intrusiveness=(
                crawl_report.assessment_intrusiveness
            ),
            safe_active_requests_attempted=(
                crawl_report.safe_active_requests_attempted
            ),
            safe_active_successful_probes=(
                crawl_report.safe_active_successful_probes
            ),
            safe_active_errors=len(
                crawl_report.safe_active_errors
            ),
            session_cookies_enabled=(
                args.session_cookies
            ),
            workflow_enabled=args.workflow,
            workflow_planned_actions=(
                len(workflow_report.planned_actions)
                if workflow_report is not None
                else 0
            ),
            workflow_executions=(
                len(workflow_report.executions)
                if workflow_report is not None
                else 0
            ),
            dast_enabled=args.dast_cors,
            dast_requests_used=(
                dast_report.requests_used
                if dast_report is not None
                else 0
            ),
            dast_findings=(
                len(dast_report.findings)
                if dast_report is not None
                else 0
            ),
            dast_errors=(
                len(dast_report.errors)
                if dast_report is not None
                else 0
            ),
            browser_discovery_enabled=args.browser_discovery,
            browser_status=(
                browser_report.status
                if browser_report is not None
                else "disabled"
            ),
            browser_requests_observed=(
                len(browser_report.requests)
                if browser_report is not None
                else 0
            ),
            browser_requests_blocked=(
                sum(
                    not item.allowed
                    for item in browser_report.requests
                )
                if browser_report is not None
                else 0
            ),
            status=crawl_report.status,
        )

        print(
            "NightRecon crawl URL: "
            f"{crawl_report.start_url}"
        )
        print(
            f"Origin: {crawl_report.origin}"
        )
        print(
            f"Target: {crawl_report.target}"
        )
        print(
            f"Target type: {crawl_report.target_type}"
        )
        print(
            "Scope authorization: approved"
        )
        print(
            "Session cookie continuity: "
            f"{'enabled' if args.session_cookies else 'disabled'}"
        )
        print(
            f"Pages fetched: {len(crawl_report.pages)}"
        )
        print(
            "Successful pages: "
            f"{len(crawl_report.successful_pages)}"
        )
        print(
            "Failed pages: "
            f"{len(crawl_report.failed_pages)}"
        )

        for page in crawl_report.pages:
            line = (
                f"  PAGE {page.url} "
                f"status={page.status if page.status is not None else '-'} "
                f"type={page.content_type or '-'} "
                f"bytes={page.byte_count} "
                f"links={len(page.links)}"
            )

            if page.error:
                line += (
                    f" error={page.error}"
                )

            print(line)

            if page.title:
                print(
                    f"    Title: {page.title}"
                )

            for form in page.forms:
                input_summary = (
                    ",".join(
                        (
                            f"{item.name or '-'}:"
                            f"{item.input_type}"
                        )
                        for item in form.inputs
                    )
                    if form.inputs
                    else "-"
                )
                print(
                    "    FORM "
                    f"method={form.method} "
                    f"action={form.action or '-'} "
                    f"inputs={input_summary}"
                )

            for source in page.script_sources:
                print(
                    f"    SCRIPT {source}"
                )

            for cookie_observation in page.cookies:
                print(
                    "    COOKIE "
                    f"name={cookie_observation.name} "
                    f"path={cookie_observation.path or '-'} "
                    "secure="
                    f"{'yes' if cookie_observation.secure else 'no'} "
                    "httponly="
                    f"{'yes' if cookie_observation.http_only else 'no'} "
                    "samesite="
                    f"{cookie_observation.same_site or '-'}"
                )

        if crawl_report.assessment_enabled:
            assessment_summary = summarize_web_assessments(
                crawl_report.assessment_findings
            )
            print(
                "Web Assessment Summary: "
                f"findings={assessment_summary.total_findings} "
                f"high={assessment_summary.high_count} "
                f"medium={assessment_summary.medium_count} "
                f"low={assessment_summary.low_count} "
                f"unknown={assessment_summary.unknown_count}"
            )

            print(
                "Assessment intrusiveness: "
                f"{crawl_report.assessment_intrusiveness}"
            )

            if (
                crawl_report.assessment_intrusiveness
                == "safe-active"
            ):
                print(
                    "Safe-active probes: "
                    "attempted="
                    f"{crawl_report.safe_active_requests_attempted} "
                    "successful="
                    f"{crawl_report.safe_active_successful_probes} "
                    "errors="
                    f"{len(crawl_report.safe_active_errors)}"
                )

            for finding in crawl_report.assessment_findings:
                print(
                    "  FINDING "
                    f"{finding.check_id} "
                    f"severity={finding.severity} "
                    f"page={finding.page_url}"
                )
                print(
                    f"    {finding.title}"
                )
                print(
                    f"    Evidence: {finding.evidence}"
                )

        if dast_report is not None:
            dast_summary = dast_report.to_dict()[
                "summary"
            ]
            print(
                "DAST Summary: "
                f"checks={dast_summary['enabled_checks']} "
                f"requests={dast_summary['requests_used']} "
                f"findings={dast_summary['findings']} "
                f"evidence={dast_summary['evidence_records']} "
                f"errors={dast_summary['errors']}"
            )
            print(
                "DAST limits: "
                f"total={dast_report.max_total_requests} "
                f"family={dast_report.default_family_requests}"
            )

            for finding in dast_report.findings:
                print(
                    "  DAST FINDING "
                    f"{finding.check_id} "
                    f"severity={finding.severity} "
                    f"target={finding.target_url}"
                )
                print(
                    f"    {finding.title}"
                )

                for evidence in finding.evidence:
                    print(
                        f"    Evidence: {evidence}"
                    )

                if finding.retest is not None:
                    print(
                        "    Retest ID: "
                        f"{finding.retest.retest_id}"
                    )

            print(
                f"DAST result file: {dast_output_path}"
            )

        if workflow_report is not None:
            print(
                "Workflow Summary: "
                f"planned={len(workflow_report.planned_actions)} "
                f"forms={len(workflow_report.forms)} "
                f"executions={len(workflow_report.executions)} "
                f"successful={workflow_report.successful_executions}"
            )
            print(
                f"Workflow max actions: {workflow_report.max_actions}"
            )

            for action in workflow_report.planned_actions:
                print(
                    "  WORKFLOW PLAN "
                    f"{action.method} {action.target_url} "
                    f"kind={action.kind}"
                )

            for form in workflow_report.forms:
                fields = (
                    ",".join(
                        f"{field.name or '-'}:{field.field_class}"
                        for field in form.fields
                    )
                    if form.fields
                    else "-"
                )
                print(
                    "  WORKFLOW FORM "
                    f"method={form.method} "
                    f"action={form.action_url or '-'} "
                    "same_origin="
                    f"{'yes' if form.action_same_origin else 'no'} "
                    f"fields={fields}"
                )

            for execution in workflow_report.executions:
                print(
                    "  WORKFLOW EXEC "
                    f"{execution.action.method} "
                    f"{execution.action.target_url} "
                    f"allowed={'yes' if execution.allowed else 'no'} "
                    f"success={'yes' if execution.success else 'no'} "
                    f"reason={execution.execution_reason}"
                )

            print(
                f"Workflow result file: {workflow_output_path}"
            )

        if browser_report is not None:
            summary = browser_report.to_dict()["summary"]
            print(
                "Browser Discovery Summary: "
                f"status={browser_report.status} "
                f"requests={summary['requests_observed']} "
                f"blocked={summary['requests_blocked']} "
                f"links={summary['links_discovered']} "
                f"forms={summary['forms_observed']}"
            )
            print(
                "Browser limits: "
                f"requests={browser_report.max_requests} "
                f"pages={browser_report.max_pages} "
                f"runtime={browser_report.max_runtime_seconds}s"
            )

            if browser_report.page is not None:
                print(
                    "  BROWSER PAGE "
                    f"{browser_report.page.url} "
                    f"title={browser_report.page.title or '-'}"
                )

                for link in browser_report.page.links:
                    print(
                        f"    BROWSER LINK {link}"
                    )

                for form in browser_report.page.forms:
                    print(
                        "    BROWSER FORM "
                        f"method={form.method} "
                        f"action={form.action or '-'} "
                        f"inputs={len(form.inputs)}"
                    )

            if browser_report.error:
                print(
                    f"Browser error: {browser_report.error}"
                )

            print(
                f"Browser result file: {browser_output_path}"
            )

        print(
            f"Max pages: {crawl_report.max_pages}"
        )
        print(
            "Max bytes per page: "
            f"{crawl_report.max_bytes_per_page}"
        )
        print(
            f"Connection timeout: {config.connect_timeout}"
        )
        print(
            f"Session ID: {crawl_report.session_id}"
        )
        print(
            f"Session status: {crawl_report.status}"
        )
        print(
            f"Result file: {output_path}"
        )
        return

    if args.command == "scan":
        if (
            (
                args.assessment_check_ids
                or args.assessment_check_families
                or args.assessment_check_tags
            )
            and not args.assessment
        ):
            parser.error(
                "--check/--check-family/--check-tag require --assessment."
            )

        if (
            args.installed_check_packs
            and not args.assessment
        ):
            parser.error(
                "--installed-check-packs requires --assessment."
            )

        if (
            (
                args.check_pack_paths
                or args.check_pack_keys
            )
            and not args.assessment
        ):
            parser.error(
                "--check-pack/--check-pack-key require --assessment."
            )

        if (
            args.installed_check_packs
            and not args.check_pack_keys
        ):
            parser.error(
                "--installed-check-packs requires --check-pack-key."
            )

        if args.threat_context and not args.vuln_lookup:
            parser.error(
                "--threat-context requires --vuln-lookup."
            )

        try:
            target = parse_target(args.target)
            scope = Scope.from_values(args.scope)
            ports = parse_ports(args.ports)

            config = NightReconConfig(
                connect_timeout=args.timeout,
                max_workers=args.workers,
                results_dir=args.results_dir,
                logs_dir=args.logs_dir,
            )
        except ValueError as exc:
            parser.error(str(exc))

        logger = NightReconLogger(config.logs_dir)

        if not scope.is_authorized(target):
            logger.write(
                "scan.rejected",
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                reason="outside_authorized_scope",
            )

            parser.error(
                f"Target '{target.value}' is outside the authorized scope."
            )

        if target.target_type == TargetType.CIDR:
            logger.write(
                "scan.rejected",
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                reason="cidr_active_scan_not_supported",
            )

            parser.error(
                "Active TCP scanning of CIDR targets is not supported yet."
            )

        try:
            resolution = resolve_target(target)
        except ValueError as exc:
            logger.write(
                "resolution.failed",
                target=target.value,
                target_type=target.target_type.value,
                reason=str(exc),
            )
            parser.error(str(exc))

        session = ScanSession.create(
            target=target,
            scope_rules=tuple(args.scope),
        )

        all_results = []

        for address in resolution.addresses:
            results = scan_tcp_ports(
                address=address,
                ports=ports,
                timeout=config.connect_timeout,
                max_workers=config.max_workers,
            )

            all_results.extend(results)

        all_services = []

        for address in resolution.addresses:
            open_ports = tuple(
                result.port
                for result in all_results
                if result.address == address and result.is_open
            )

            if not open_ports:
                continue

            if target.target_type == TargetType.HOSTNAME:
                if args.service_probe_intensity > 0:
                    services = detect_services(
                        address=address,
                        ports=open_ports,
                        timeout=config.connect_timeout,
                        max_workers=config.max_workers,
                        server_hostname=target.value,
                        probe_intensity=(
                            args.service_probe_intensity
                        ),
                    )
                else:
                    services = detect_services(
                        address=address,
                        ports=open_ports,
                        timeout=config.connect_timeout,
                        max_workers=config.max_workers,
                        server_hostname=target.value,
                    )
            else:
                if args.service_probe_intensity > 0:
                    services = detect_services(
                        address=address,
                        ports=open_ports,
                        timeout=config.connect_timeout,
                        max_workers=config.max_workers,
                        probe_intensity=(
                            args.service_probe_intensity
                        ),
                    )
                else:
                    services = detect_services(
                        address=address,
                        ports=open_ports,
                        timeout=config.connect_timeout,
                        max_workers=config.max_workers,
                    )

            all_services.extend(services)

        operating_system_fingerprints = (
            build_host_operating_system_fingerprints(
                tuple(all_services)
            )
        )

        all_assessments = ()
        assessment_catalog_errors = ()

        if args.assessment:
            try:
                pack_checks = _load_requested_check_pack_checks(
                    tuple(args.check_pack_paths or ()),
                    tuple(args.check_pack_keys or ()),
                )
                installed_checks = (
                    _load_installed_check_pack_checks(
                        args.check_store_dir,
                        tuple(args.check_pack_keys or ()),
                    )
                    if args.installed_check_packs
                    else ()
                )
            except ValueError as exc:
                parser.error(str(exc))

            catalog = load_check_catalog(
                additional_checks=(
                    pack_checks
                    + installed_checks
                )
            )
            assessment_catalog_errors = catalog.errors
            registry = CheckRegistry()

            for check in catalog.checks:
                registry.register(check)

            selected_checks = registry.select(
                check_ids=tuple(
                    args.assessment_check_ids or ()
                ),
                families=tuple(
                    args.assessment_check_families or ()
                ),
                tags=tuple(
                    args.assessment_check_tags or ()
                ),
            )

            all_assessments = assess_services(
                target=target.value,
                services=tuple(all_services),
                checks=selected_checks,
                max_intrusiveness=CheckIntrusiveness(
                    args.max_check_intrusiveness
                ),
                authorized=True,
            )

        all_vulnerabilities = ()

        if args.vuln_lookup:
            provider = NvdVulnerabilityProvider(
                api_key=os.environ.get(
                    "NIGHTRECON_NVD_API_KEY"
                ),
            )
            all_vulnerabilities = enrich_service_vulnerabilities(
                provider=provider,
                services=tuple(all_services),
            )

        all_threat_context = ()

        if args.threat_context:
            all_threat_context = enrich_threat_context(
                vulnerabilities=all_vulnerabilities,
                kev_provider=CisaKevProvider(),
                epss_provider=FirstEpssProvider(),
            )

        report = TcpScanReport.create(
            session=session,
            resolved_addresses=resolution.addresses,
            ports_requested=ports,
            results=tuple(all_results),
            services=tuple(all_services),
            operating_system_fingerprints=(
                operating_system_fingerprints
            ),
            assessment_enabled=args.assessment,
            assessment_catalog_errors=assessment_catalog_errors,
            assessments=all_assessments,
            vulnerability_intelligence_enabled=args.vuln_lookup,
            vulnerabilities=all_vulnerabilities,
            threat_context_enabled=args.threat_context,
            threat_context=all_threat_context,
        )

        store = ResultStore(config.results_dir)
        output_path = store.save_report(report)

        inventory_update = None
        inventory_path = None

        if args.update_inventory:
            try:
                inventory_store = AssetInventoryStore(
                    args.inventory_dir
                )
                current_inventory = inventory_store.load()
                inventory_update = apply_scan_report(
                    current_inventory,
                    report,
                )
                inventory_path = inventory_store.save(
                    inventory_update.inventory
                )
                inventory_store.append_change_events(
                    tuple(
                        AssetChangeEvent(
                            observed_at=report.created_at,
                            session_id=report.session_id,
                            source_type="scan",
                            change=change,
                        )
                        for change in inventory_update.changes
                    )
                )
            except ValueError as exc:
                parser.error(str(exc))

        open_ports = report.open_ports

        logger.write(
            "scan.completed",
            session_id=report.session_id,
            target=report.target,
            target_type=report.target_type,
            scope=args.scope,
            ports=list(report.ports_requested),
            resolved_addresses=list(report.resolved_addresses),
            open_ports=[
                {
                    "address": result.address,
                    "port": result.port,
                }
                for result in open_ports
            ],
            status=report.status,
        )

        print(f"NightRecon scan target: {report.target}")
        print(f"Target type: {report.target_type}")
        print("Scope authorization: approved")

        print("Resolved addresses:")
        for address in report.resolved_addresses:
            print(f"  - {address}")

        print(f"Ports requested: {len(report.ports_requested)}")
        print(f"Open ports: {len(open_ports)}")

        for result in open_ports:
            print(f"  OPEN {result.address}:{result.port}")

        for service in report.services:
            print(
             f"  SERVICE {service.address}:{service.port} "
                f"{service.service}"
            )

            if service.banner:
                print(f"    Banner: {service.banner}")

            if service.http_status:
                print(f"    HTTP Status: {service.http_status}")

            if service.http_server:
                print(f"    Server: {service.http_server}")

            if service.software_identity is not None:
                print(
                    "    Software: "
                    f"{service.software_identity.product} "
                    f"{service.software_identity.version}"
                )

            if service.service_fingerprint is not None:
                fingerprint = service.service_fingerprint
                details = [
                    f"protocol={fingerprint.protocol}",
                ]

                if fingerprint.protocol_version:
                    details.append(
                        "protocol_version="
                        f"{fingerprint.protocol_version}"
                    )

                if fingerprint.product:
                    details.append(
                        f"product={fingerprint.product}"
                    )

                if fingerprint.version:
                    details.append(
                        f"version={fingerprint.version}"
                    )

                if fingerprint.platform:
                    details.append(
                        f"platform={fingerprint.platform}"
                    )

                if fingerprint.confidence:
                    details.append(
                        "confidence="
                        f"{fingerprint.confidence}"
                    )

                print(
                    "    Fingerprint: "
                    + " ".join(details)
                )

            if service.security_headers_present:
                print(
                    "    Security Headers Present: "
                    f"{', '.join(service.security_headers_present)}"
                )

            if service.security_headers_missing:
                print(
                    "    Security Headers Missing: "
                    f"{', '.join(service.security_headers_missing)}"
                )

            if service.tls_version:
                print(f"    TLS Version: {service.tls_version}")

            if service.tls_cipher:
                print(f"    TLS Cipher: {service.tls_cipher}")

            if service.tls_certificate_subject:
                print(
                    "    Certificate Subject: "
                    f"{service.tls_certificate_subject}"
                )

            if service.tls_certificate_issuer:
                print(
                    "    Certificate Issuer: "
                    f"{service.tls_certificate_issuer}"
                )

            if service.tls_certificate_not_before:
                print(
                    "    Certificate Valid From: "
                    f"{service.tls_certificate_not_before}"
                )

            if service.tls_certificate_not_after:
                print(
                    "    Certificate Valid Until: "
                    f"{service.tls_certificate_not_after}"
                )
            if service.tls_certificate_sans:
                print(
                    "    Certificate SANs: "
                    f"{', '.join(service.tls_certificate_sans)}"
                )
            if service.tls_certificate_sha256:
                print(
                    "    Certificate SHA-256: "
                    f"{service.tls_certificate_sha256}"
                )


        for service_assessment in report.assessments:
            print(
                "  ASSESSMENT "
                f"{service_assessment.address}:"
                f"{service_assessment.port} "
                f"{service_assessment.service}"
            )

            for execution in service_assessment.executions:
                print(
                    "    CHECK "
                    f"{execution.check_id} "
                    f"status={execution.status}"
                )

                if execution.reason:
                    print(
                        "      Reason: "
                        f"{execution.reason}"
                    )

                if execution.error:
                    print(
                        "      Error: "
                        f"{execution.error}"
                    )

                for finding in execution.findings:
                    severity = (
                        finding.severity
                        or "unspecified"
                    )
                    print(
                        "      FINDING "
                        f"{finding.check_id} "
                        f"severity={severity}"
                    )
                    print(
                        "        Title: "
                        f"{finding.title}"
                    )
                    print(
                        "        Summary: "
                        f"{finding.summary}"
                    )

                    for evidence in finding.evidence:
                        print(
                            "        Evidence: "
                            f"{evidence}"
                        )

                    if finding.remediation:
                        print(
                            "        Remediation: "
                            f"{finding.remediation}"
                        )

        if report.assessment_enabled:
            assessment_summary = summarize_assessments(
                report.assessments
            )
            print(
                "Assessment Summary: "
                f"services={assessment_summary.services_assessed} "
                f"completed={assessment_summary.checks_completed} "
                f"skipped={assessment_summary.checks_skipped} "
                f"errors={assessment_summary.checks_errored} "
                f"findings={assessment_summary.findings}"
            )

            for error in report.assessment_catalog_errors:
                print(
                    "Assessment Catalog Error: "
                    f"{error}"
                )

        for host_os in report.operating_system_fingerprints:
            fingerprint = host_os.fingerprint

            if fingerprint.confidence == "conflicting":
                print(
                    f"  OS FINGERPRINT {host_os.address} "
                    "confidence=conflicting "
                    "candidates="
                    f"{','.join(fingerprint.candidates)}"
                )
                continue

            details = [
                f"platform={fingerprint.platform}",
            ]

            if fingerprint.family:
                details.append(
                    f"family={fingerprint.family}"
                )

            details.append(
                f"confidence={fingerprint.confidence}"
            )
            details.append(
                f"evidence={len(fingerprint.evidence)}"
            )

            print(
                f"  OS FINGERPRINT {host_os.address} "
                + " ".join(details)
            )

        for vulnerability in report.vulnerabilities:
            lookup = vulnerability.lookup

            if lookup.error:
                print(
                    f"  VULN INTEL {vulnerability.address}:"
                    f"{vulnerability.port} {vulnerability.service} "
                    f"provider={lookup.provider} "
                    f"error={lookup.error}"
                )
                continue

            print(
                f"  VULN INTEL {vulnerability.address}:"
                f"{vulnerability.port} {vulnerability.service} "
                f"provider={lookup.provider} "
                f"matches={len(lookup.findings)}"
            )

            for finding in lookup.findings:
                details = [
                    f"    {finding.vulnerability_id}",
                ]

                if finding.severity:
                    details.append(
                        f"severity={finding.severity}"
                    )

                if finding.cvss_score is not None:
                    details.append(
                        f"cvss={finding.cvss_score}"
                    )

                if finding.match_basis:
                    details.append(
                        f"basis={finding.match_basis}"
                    )

                if finding.matched_identifier:
                    details.append(
                        "identifier="
                        f"{finding.matched_identifier}"
                    )

                print(" ".join(details))

        for context in report.threat_context:
            print(
                "  THREAT CONTEXT "
                f"{context.vulnerability_id} "
                "known_exploited="
                f"{'yes' if context.known_exploited else 'no'}"
            )

            if context.known_exploited:
                print(
                    "    KEV "
                    f"date_added={context.kev_date_added or 'unknown'} "
                    f"due_date={context.kev_due_date or 'unknown'}"
                )

                if context.kev_known_ransomware_campaign_use:
                    print(
                        "    KEV ransomware_use="
                        f"{context.kev_known_ransomware_campaign_use}"
                    )

                if context.kev_required_action:
                    print(
                        "    KEV required_action="
                        f"{context.kev_required_action}"
                    )

            if context.epss_probability is not None:
                print(
                    "    EPSS "
                    f"probability={context.epss_probability} "
                    f"percentile={context.epss_percentile} "
                    f"date={context.epss_date or 'unknown'}"
                )

            for error in context.errors:
                print(
                    "    Threat Context Error: "
                    f"{error}"
                )

        if report.threat_context_enabled:
            threat_summary = summarize_threat_context(
                report.threat_context
            )

            print(
                "Threat Context Summary: "
                f"cves={threat_summary.cves_enriched} "
                "known_exploited="
                f"{threat_summary.known_exploited_count} "
                "epss_available="
                f"{threat_summary.epss_available_count} "
                "provider_errors="
                f"{threat_summary.provider_error_count}"
            )

            if (
                threat_summary.max_epss_probability
                is not None
            ):
                print(
                    "Max EPSS: "
                    "probability="
                    f"{threat_summary.max_epss_probability} "
                    "percentile="
                    f"{threat_summary.max_epss_percentile}"
                )

        if report.vulnerability_intelligence_enabled:
            vulnerability_summary = summarize_vulnerabilities(
                report.vulnerabilities
            )

            print(
                "Vulnerability Summary: "
                f"services={vulnerability_summary.services_queried} "
                f"successful={vulnerability_summary.successful_lookups} "
                f"failed={vulnerability_summary.failed_lookups} "
                f"matches={vulnerability_summary.total_findings}"
            )
            print(
                "Severity: "
                f"critical={vulnerability_summary.critical_count} "
                f"high={vulnerability_summary.high_count} "
                f"medium={vulnerability_summary.medium_count} "
                f"low={vulnerability_summary.low_count} "
                f"none={vulnerability_summary.none_count} "
                f"unknown={vulnerability_summary.unknown_count}"
            )

            if vulnerability_summary.max_cvss_score is not None:
                print(
                    "Max CVSS observed: "
                    f"{vulnerability_summary.max_cvss_score}"
                )

        print(f"Session ID: {report.session_id}")
        print(f"Session status: {report.status}")
        print(f"Connection timeout: {config.connect_timeout}")
        print(f"Max workers: {config.max_workers}")
        print(f"Result file: {output_path}")
        if inventory_update is not None:
            print(
                f"Inventory changes: {len(inventory_update.changes)}"
            )

            for change in inventory_update.changes:
                line = (
                    f"ASSET CHANGE {change.address} "
                    f"{change.change_type}"
                )

                if change.port is not None:
                    line += f" port={change.port}"

                if change.before:
                    line += f" before={change.before}"

                if change.after:
                    line += f" after={change.after}"

                print(line)

            print(
                f"Inventory file: {inventory_path}"
            )


    if __name__ == "__main__":
        main()



_GUARD_VALUE_OPTIONS = frozenset({"--guard-workspace-root", "--guard-engagement-id"})


def _pop_guard_options(arguments: tuple[str, ...]) -> tuple[tuple[str, ...], str | None, str | None, bool]:
    remaining: list[str] = []
    workspace_root: str | None = None
    engagement_id: str | None = None
    approved = False
    index = 0
    while index < len(arguments):
        item = arguments[index]
        if item in _GUARD_VALUE_OPTIONS:
            if index + 1 >= len(arguments):
                print(f"red-night: {item} requires a value.", file=sys.stderr)
                raise SystemExit(2)
            value = arguments[index + 1]
            if item == "--guard-workspace-root":
                workspace_root = value
            else:
                engagement_id = value
            index += 2
            continue
        if item == "--guard-approved":
            approved = True
            index += 1
            continue
        remaining.append(item)
        index += 1
    return tuple(remaining), workspace_root, engagement_id, approved


def _flag_value(arguments: tuple[str, ...], name: str) -> str | None:
    try:
        index = arguments.index(name)
    except ValueError:
        return None
    if index + 1 >= len(arguments):
        return None
    return arguments[index + 1]


def _guard_subject(arguments: tuple[str, ...]) -> tuple[str, str, str] | None:
    if not arguments:
        return None
    command = arguments[0]

    if command == "discover" and len(arguments) >= 2:
        return "discovery", arguments[1], "standard"
    if command == "scan" and len(arguments) >= 2:
        impact = "high" if _flag_value(arguments, "--max-check-intrusiveness") == "intrusive" else "standard"
        return "scan", arguments[1], impact
    if command == "crawl" and len(arguments) >= 2:
        host = urlsplit(arguments[1]).hostname
        if host is None:
            return None
        return "web.crawl", host, "standard"
    if command == "infra" and len(arguments) >= 3:
        return f"infrastructure.{arguments[1]}", arguments[2], "standard"
    if command == "api" and len(arguments) >= 2:
        operation = arguments[1]
        if operation == "probe":
            base_url = _flag_value(arguments, "--base-url")
            host = None if base_url is None else urlsplit(base_url).hostname
            return None if host is None else ("api.probe", host, "standard")
        if operation == "graphql-introspect":
            endpoint = _flag_value(arguments, "--endpoint-url")
            host = None if endpoint is None else urlsplit(endpoint).hostname
            return None if host is None else ("api.graphql-introspection", host, "standard")
        return None
    if command == "checks" and len(arguments) >= 2 and arguments[1] == "feed":
        url = _flag_value(arguments, "--url")
        if url:
            host = urlsplit(url).hostname
            if host is not None:
                return "checks.feed", host, "low"
        return None
    return None


def _authorize_guarded_execution(
    arguments: tuple[str, ...],
    *,
    workspace_root: str | None,
    engagement_id: str | None,
    approved: bool,
) -> None:
    if "-h" in arguments or "--help" in arguments:
        return
    subject = _guard_subject(arguments)
    if subject is None:
        return
    if workspace_root is None or engagement_id is None:
        print(
            "red-night: active command requires --guard-workspace-root and --guard-engagement-id.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    capability, target, impact = subject
    try:
        decision = LocalWorkspace(workspace_root).authorize_action(
            engagement_id,
            capability=capability,
            target=target,
            impact=impact,
            approval_present=approved,
            consume=True,
        )
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"red-night: engagement authorization failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    if not decision.allowed:
        print(
            f"red-night: engagement authorization denied "
            f"[{decision.reason_code}]: {decision.reason}",
            file=sys.stderr,
        )
        raise SystemExit(2)

def main(argv: tuple[str, ...] | None = None) -> None:
    """Run the Red-owned CLI composition without the legacy NightRecon package."""
    raw_arguments = tuple(sys.argv[1:] if argv is None else argv)
    arguments, workspace_root, engagement_id, approved = _pop_guard_options(raw_arguments)
    allowed = available_commands("red")

    if not arguments or arguments[0] in {"-h", "--help"}:
        print(f"NightRecon {edition_name('red')} command boundary")
        print("Available commands: " + ", ".join(allowed))
        print("Standalone edition packaging is not yet available.")
        return

    if arguments[0] == "--version":
        _command_main(arguments)
        return

    if arguments[0] not in allowed:
        print("red-night: Command is not available in this edition.", file=sys.stderr)
        raise SystemExit(2)

    if arguments[0] == "identity":
        from nightrecon_red_engine.red_directory_cli import main as identity_main
        identity_main(arguments[1:])
        return

    if arguments[0] == "workspace":
        from nightrecon_red_engine.red_workspace_cli import main as workspace_main
        workspace_main(arguments[1:])
        return

    _authorize_guarded_execution(
        arguments,
        workspace_root=workspace_root,
        engagement_id=engagement_id,
        approved=approved,
    )
    _command_main(arguments)
