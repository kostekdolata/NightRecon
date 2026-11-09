"""Offline, bounded Greenbone XML report evidence import; never starts scans."""
from __future__ import annotations

import hashlib
import ipaddress
import re
import xml.etree.ElementTree as ET


class GreenboneEvidenceError(ValueError):
    """Malformed, excessive or out-of-scope third-party report."""


def _host(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise GreenboneEvidenceError("Invalid host")
    value = value.strip().rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    labels = value.split(".")
    if len(labels) < 2 or any(
        not 0 < len(x) <= 63 or x[0] == "-" or x[-1] == "-"
        or not re.fullmatch(r"[a-z0-9-]+", x) for x in labels
    ):
        raise GreenboneEvidenceError("Invalid host")
    return value


def _text(node: ET.Element, tag: str, *, required: bool = False, limit: int = 4096) -> str:
    element = node.find(tag)
    value = "" if element is None or element.text is None else element.text.strip()
    if len(value) > limit or (required and not value):
        raise GreenboneEvidenceError("Invalid " + tag)
    return value


def import_greenbone_xml(
    payload: bytes, *, source_name: str, allowed_hosts: tuple[str, ...],
    max_bytes: int = 8_000_000, max_results: int = 10_000,
) -> dict:
    """Import Greenbone get_reports XML results as non-authoritative observations.

    The host allowlist is exact. A rejected result rejects the entire report.
    This function neither invokes Greenbone nor makes network requests.
    """
    if not isinstance(payload, bytes) or not 0 < len(payload) <= max_bytes or max_bytes <= 0:
        raise GreenboneEvidenceError("Invalid payload size")
    if not isinstance(source_name, str) or not 0 < len(source_name) <= 256:
        raise GreenboneEvidenceError("Invalid source name")
    if not isinstance(allowed_hosts, tuple) or not allowed_hosts:
        raise GreenboneEvidenceError("Explicit host scope required")
    if type(max_results) is not int or max_results <= 0:
        raise GreenboneEvidenceError("Invalid result budget")
    scope = {_host(host) for host in allowed_hosts}
    # ElementTree does not resolve external entities; prohibit DTDs altogether.
    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", payload, re.IGNORECASE):
        raise GreenboneEvidenceError("XML declarations not permitted")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise GreenboneEvidenceError("Invalid XML") from exc
    if root.tag not in ("get_reports_response", "report"):
        raise GreenboneEvidenceError("Unexpected report root")
    reports = [root] if root.tag == "report" else root.findall("./report")
    if len(reports) != 1:
        raise GreenboneEvidenceError("Exactly one report required")
    result_nodes = reports[0].findall("./results/result")
    if len(result_nodes) > max_results:
        raise GreenboneEvidenceError("Result budget exceeded")
    observations = []
    for item in result_nodes:
        host = _host(_text(item, "host", required=True, limit=253))
        if host not in scope:
            raise GreenboneEvidenceError("Result outside exact host scope")
        name = _text(item, "name", required=True, limit=2048)
        port = _text(item, "port", limit=128)
        severity_raw = _text(item, "severity", limit=32)
        try:
            severity = float(severity_raw) if severity_raw else None
        except ValueError as exc:
            raise GreenboneEvidenceError("Invalid severity") from exc
        if severity is not None and not 0 <= severity <= 10:
            raise GreenboneEvidenceError("Invalid severity")
        observations.append({
            "host": host, "name": name, "port": port,
            "reported_severity": severity,
            "classification": "unverified_tool_observation",
        })
    return {
        "source_tool": "Greenbone/OpenVAS", "source_name": source_name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "record_count": len(observations), "observations": observations,
        "authority": "untrusted_offline_import",
    }
