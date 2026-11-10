"""Bounded offline OWASP ZAP JSON alert importer; never contacts targets."""
from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit

from .nuclei_offline_jsonl_import import _host


class ZapOfflineImportError(ValueError):
    """Malformed, out-of-scope, or over-budget third-party alert evidence."""


def _url_host(url: str) -> str:
    if not isinstance(url, str) or not 0 < len(url) <= 2048:
        raise ZapOfflineImportError("Invalid URL")
    try:
        parsed = urlsplit(url)
        if (parsed.scheme not in ("http", "https") or not parsed.netloc
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment or parsed.hostname is None
                or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
            raise ValueError("Unsupported URL")
        return _host(parsed.hostname)
    except ValueError as exc:
        raise ZapOfflineImportError("Invalid URL host") from exc


def import_zap_json(payload: bytes, *, allowed_hosts: tuple[str, ...],
                    source_name: str = "zap.json", max_bytes: int = 2_000_000,
                    max_records: int = 4096) -> dict:
    """Import site/alert/instance observations with exact-host scope and provenance.

    This is an untrusted file parser, not a ZAP service adapter or vulnerability verdict.
    """
    if (type(max_bytes) is not int or not 0 < max_bytes <= 10_000_000
            or type(max_records) is not int or not 0 < max_records <= 10000
            or not isinstance(payload, bytes) or not 0 < len(payload) <= max_bytes
            or not isinstance(allowed_hosts, tuple)
            or not 0 < len(allowed_hosts) <= 256
            or not isinstance(source_name, str) or not 0 < len(source_name) <= 256):
        raise ZapOfflineImportError("Invalid payload, scope or budget")
    try:
        scope = {_host(h) for h in allowed_hosts}
        if len(scope) != len(allowed_hosts):
            raise ZapOfflineImportError("Duplicate scope host")
        doc = json.loads(payload)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ZapOfflineImportError("Malformed JSON or host scope") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("site"), list):
        raise ZapOfflineImportError("Missing ZAP site array")
    if len(doc["site"]) > max_records:
        raise ZapOfflineImportError("Site budget exceeded")
    observations = []
    for site in doc["site"]:
        if not isinstance(site, dict) or not isinstance(site.get("alerts"), list):
            raise ZapOfflineImportError("Invalid site")
        site_host = _url_host(site.get("@name"))
        if site_host not in scope:
            raise ZapOfflineImportError("Site outside exact scope")
        for alert in site["alerts"]:
            if not isinstance(alert, dict):
                raise ZapOfflineImportError("Invalid alert")
            rule = alert.get("pluginid")
            risk = alert.get("riskcode")
            instances = alert.get("instances")
            if (not isinstance(rule, str) or not 0 < len(rule) <= 128
                    or risk not in ("0", "1", "2", "3", "4")
                    or not isinstance(instances, list) or not instances):
                raise ZapOfflineImportError("Invalid alert fields")
            for instance in instances:
                if len(observations) >= max_records:
                    raise ZapOfflineImportError("Observation budget exceeded")
                if not isinstance(instance, dict):
                    raise ZapOfflineImportError("Invalid instance")
                host = _url_host(instance.get("uri"))
                if host != site_host or host not in scope:
                    raise ZapOfflineImportError("Instance outside exact scope")
                observations.append({
                    "host": host, "plugin_id": rule, "reported_riskcode": risk,
                    "classification": "unverified_tool_observation",
                    "record_index": len(observations),
                })
    return {
        "schema": "red.zap_offline_json_import.v1",
        "authority": "untrusted_offline_import", "source_tool": "OWASP ZAP",
        "source_name": source_name, "sha256": hashlib.sha256(payload).hexdigest(),
        "record_count": len(observations), "observations": observations,
        "limitations": "ZAP alerts and risk codes are unverified observations, not confirmed vulnerabilities, exploitability, remediation, or authorization.",
    }
