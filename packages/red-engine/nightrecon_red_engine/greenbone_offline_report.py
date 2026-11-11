"""Strict offline Greenbone report importer; never connects to a scanner.

Only a minimal, explicit XML result subset is accepted. Third-party results
remain unverified observations and never grant scope or execution authority.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import xml.etree.ElementTree as ET


class GreenboneOfflineImportError(ValueError):
    """Malformed, unsafe, out-of-scope or over-budget report."""


def _host(value: str) -> str:
    if not isinstance(value, str) or not 0 < len(value) <= 253:
        raise ValueError("Invalid host")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if (value != value.lower() or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", value)
                or ".." in value or any(len(label) > 63 for label in value.split("."))):
            raise ValueError("Invalid host")
        return value


def import_greenbone_report(
    payload: bytes, *, allowed_hosts: tuple[str, ...],
    max_bytes: int = 2_000_000, max_results: int = 4096,
) -> dict:
    """Parse an offline Greenbone XML report subset under an exact host allowlist."""
    if (type(max_bytes) is not int or not 0 < max_bytes <= 10_000_000
            or type(max_results) is not int or not 0 < max_results <= 10000
            or not isinstance(payload, bytes) or not 0 < len(payload) <= max_bytes
            or not isinstance(allowed_hosts, tuple) or not 0 < len(allowed_hosts) <= 256):
        raise GreenboneOfflineImportError("Invalid payload, scope or budget")
    try:
        scope = {_host(host) for host in allowed_hosts}
        if len(scope) != len(allowed_hosts) or any(_host(host) != host for host in allowed_hosts):
            raise ValueError("Noncanonical or duplicate host")
    except ValueError as exc:
        raise GreenboneOfflineImportError("Invalid exact host scope") from exc
    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", payload, re.IGNORECASE):
        raise GreenboneOfflineImportError("XML declarations with entities are prohibited")
    try:
        root = ET.fromstring(payload)
    except (ET.ParseError, ValueError) as exc:
        raise GreenboneOfflineImportError("Malformed XML report") from exc
    if root.tag != "report":
        raise GreenboneOfflineImportError("Expected report root")
    results_nodes = root.findall("./results")
    if len(results_nodes) != 1 or len(root) != 1:
        raise GreenboneOfflineImportError("Unsupported report structure")
    results = results_nodes[0]
    if len(results) > max_results or any(node.tag != "result" for node in results):
        raise GreenboneOfflineImportError("Invalid result count or element")
    observations = []
    for index, node in enumerate(results):
        if len(node) != 3 or {child.tag for child in node} != {"host", "port", "severity"}:
            raise GreenboneOfflineImportError("Unsupported result structure")
        if any(len(child) or child.attrib for child in node):
            raise GreenboneOfflineImportError("Nested or attributed result fields")
        try:
            host = _host(node.findtext("host"))
        except ValueError as exc:
            raise GreenboneOfflineImportError("Invalid observed host") from exc
        if host not in scope:
            raise GreenboneOfflineImportError("Observed host outside exact scope")
        port = node.findtext("port")
        severity = node.findtext("severity")
        if not isinstance(port, str) or not re.fullmatch(r"(?:[1-9][0-9]{0,4})/(?:tcp|udp)", port):
            raise GreenboneOfflineImportError("Invalid port/protocol")
        if int(port.split("/")[0]) > 65535:
            raise GreenboneOfflineImportError("Invalid port range")
        if not isinstance(severity, str) or not re.fullmatch(r"(?:0|[1-9]|10)(?:\.[0-9])?", severity):
            raise GreenboneOfflineImportError("Invalid severity")
        if float(severity) > 10:
            raise GreenboneOfflineImportError("Invalid severity range")
        observations.append({
            "host": host, "port": port, "reported_severity": severity,
            "record_index": index, "classification": "unverified_tool_observation",
        })
    return {
        "schema": "red.greenbone_offline_report.v1",
        "source_tool": "Greenbone/OpenVAS",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "authority": "untrusted_offline_import",
        "record_count": len(observations),
        "observations": observations,
        "limitations": (
            "Offline scanner claims only; severity is unverified and does not establish "
            "vulnerability, exploitability, target authorization or remediation."
        ),
    }
