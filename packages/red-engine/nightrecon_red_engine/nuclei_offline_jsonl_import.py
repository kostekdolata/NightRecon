"""Bounded, exact-scope offline Nuclei JSONL evidence importer.

Never runs Nuclei, templates, network requests or third-party instructions.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from urllib.parse import urlsplit


class NucleiOfflineImportError(ValueError):
    """Malformed, excessive, ambiguous or out-of-scope third-party evidence."""


def _host(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise NucleiOfflineImportError("Invalid exact host")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if (value != value.lower() or value.endswith(".") or
                any(not label or len(label) > 63 or label[0] == "-" or
                    label[-1] == "-" or not all(c.isascii() and (c.isalnum() or c == "-")
                                                for c in label)
                    for label in value.split("."))):
            raise NucleiOfflineImportError("Invalid exact host")
        return value


def import_nuclei_jsonl(payload: bytes, *, allowed_hosts: tuple[str, ...],
                        source_name: str = "nuclei.jsonl", max_bytes: int = 2_000_000,
                        max_records: int = 4096) -> dict:
    """Import tool alerts as unverified observations, never confirmed findings."""
    if (type(max_bytes) is not int or not 0 < max_bytes <= 10_000_000 or
            type(max_records) is not int or not 0 < max_records <= 10000 or
            not isinstance(payload, bytes) or not 0 < len(payload) <= max_bytes or
            not isinstance(allowed_hosts, tuple) or not 0 < len(allowed_hosts) <= 256 or
            not isinstance(source_name, str) or not 0 < len(source_name) <= 256):
        raise NucleiOfflineImportError("Invalid payload, scope or budget")
    scope = {_host(h) for h in allowed_hosts}
    if len(scope) != len(allowed_hosts):
        raise NucleiOfflineImportError("Duplicate exact host")
    lines = payload.splitlines()
    if not lines or len(lines) > max_records or any(not line.strip() for line in lines):
        raise NucleiOfflineImportError("Invalid record count")
    observations = []
    for line in lines:
        try:
            record = json.loads(line)
        except (UnicodeDecodeError, ValueError) as exc:
            raise NucleiOfflineImportError("Malformed JSONL") from exc
        if not isinstance(record, dict):
            raise NucleiOfflineImportError("Invalid Nuclei record")
        template = record.get("template-id")
        matched = record.get("matched-at")
        info = record.get("info")
        if (not isinstance(template, str) or not 0 < len(template) <= 256 or
                not isinstance(matched, str) or not 0 < len(matched) <= 2048 or
                not isinstance(info, dict)):
            raise NucleiOfflineImportError("Missing structured evidence")
        try:
            parsed = urlsplit(matched)
            if (parsed.scheme not in ("http", "https") or not parsed.netloc or
                    parsed.username is not None or parsed.password is not None or
                    parsed.fragment or parsed.hostname is None or
                    parsed.port is not None and not 1 <= parsed.port <= 65535):
                raise ValueError("Unsupported target URL")
            host = _host(parsed.hostname)
        except ValueError as exc:
            raise NucleiOfflineImportError("Invalid matched URL") from exc
        if host not in scope:
            raise NucleiOfflineImportError("Observation outside exact scope")
        severity = info.get("severity")
        if severity not in ("info", "low", "medium", "high", "critical", "unknown"):
            raise NucleiOfflineImportError("Invalid severity classification")
        observations.append({
            "host": host, "template_id": template, "reported_severity": severity,
            "classification": "unverified_tool_observation",
        })
    return {
        "schema": "red.nuclei_offline_jsonl_import.v1",
        "source_tool": "Nuclei", "source_name": source_name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "authority": "untrusted_offline_import",
        "record_count": len(observations), "observations": observations,
        "limitations": "Template matches and reported severities are unverified tool observations; no vulnerability, exploitability or authorization is established.",
    }
