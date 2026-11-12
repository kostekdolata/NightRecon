"""Offline Greenbone/OpenVAS result evidence; no scanner or service execution."""
from __future__ import annotations

import hashlib
import ipaddress
import re
import xml.etree.ElementTree as ET


class GreenboneEvidenceError(ValueError):
    """Malformed, excessive or out-of-engagement third-party evidence."""


_HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")


def _host(value: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise GreenboneEvidenceError("Invalid host")
    host = value.lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        if (len(host) > 253 or not _HOST.fullmatch(host) or
                "." not in host or any(not part or len(part) > 63 or
                part.startswith("-") or part.endswith("-") for part in host.split("."))):
            raise GreenboneEvidenceError("Invalid DNS host")
        return host


def import_greenbone_xml(payload: bytes, *, approved_hosts: tuple[str, ...],
                         max_results: int = 500) -> dict:
    """Import a previously generated bounded result list; no authority is derived."""
    if (not isinstance(approved_hosts, tuple) or not approved_hosts or
            len(approved_hosts) > 100 or type(max_results) is not int or
            not 0 < max_results <= 2000):
        raise GreenboneEvidenceError("Invalid scope or budget")
    scope = {_host(host) for host in approved_hosts}
    if not isinstance(payload, bytes) or not payload or len(payload) > 2_000_000:
        raise GreenboneEvidenceError("Invalid report size")
    # Do not accept document types, entities or processing instructions in untrusted reports.
    if re.search(br"<!|<\?", payload, re.IGNORECASE):
        raise GreenboneEvidenceError("XML declarations, DTDs and entities forbidden")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise GreenboneEvidenceError("Malformed XML") from exc
    if root.tag != "report":
        raise GreenboneEvidenceError("Expected report root")
    container = root.find("results")
    if container is None or any(child.tag != "result" for child in container):
        raise GreenboneEvidenceError("Invalid result container")
    results = list(container)
    if len(results) > max_results:
        raise GreenboneEvidenceError("Result budget exceeded")
    observations = set()
    for item in results:
        host_node = item.find("host")
        nvt = item.find("nvt")
        oid = nvt.get("oid") if nvt is not None else None
        severity_node = item.find("severity")
        port_node = item.find("port")
        if (host_node is None or host_node.text is None or
                not isinstance(oid, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", oid) or
                severity_node is None or severity_node.text is None or
                port_node is None or port_node.text is None):
            raise GreenboneEvidenceError("Incomplete finding identity")
        host = _host(host_node.text)
        if host not in scope:
            raise GreenboneEvidenceError("Finding outside exact approved hosts")
        port = port_node.text
        if not re.fullmatch(r"(?:[0-9]{1,5})/(?:tcp|udp)", port):
            raise GreenboneEvidenceError("Invalid port/protocol")
        if not 1 <= int(port.split("/")[0]) <= 65535:
            raise GreenboneEvidenceError("Invalid port number")
        try:
            severity = float(severity_node.text)
        except ValueError as exc:
            raise GreenboneEvidenceError("Invalid severity") from exc
        if not 0 <= severity <= 10:
            raise GreenboneEvidenceError("Invalid severity")
        observations.add((host, oid, port, severity))
    return {
        "schema": "red.greenbone_offline_result_evidence.v1",
        "source_tool": "Greenbone/OpenVAS",
        "source_report_sha256": hashlib.sha256(payload).hexdigest(),
        "result_count": len(results),
        "unique_observation_count": len(observations),
        "observations": [
            {"observation_id": hashlib.sha256(
                f"{host}|{oid}|{port}|{severity}".encode()).hexdigest(),
             "status": "unverified_third_party_observation",
             "exploitability": "not_established"}
            for host, oid, port, severity in sorted(observations)
        ],
        "authority": "evidence_only_not_authorization",
        "limitations": "Offline XML results only; no Greenbone service, scan or finding verification",
    }
