"""Offline OWASP ZAP JSON alert evidence; never calls a ZAP service."""
from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit


class ZapEvidenceError(ValueError):
    """Untrusted, malformed or out-of-scope ZAP evidence."""


def _origin(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ZapEvidenceError("Invalid URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
    except ValueError as exc:
        raise ZapEvidenceError("Invalid URL") from exc
    if (parsed.scheme not in ("http", "https") or not host or
            parsed.username is not None or parsed.password is not None or
            parsed.query or parsed.fragment or parsed.path not in ("", "/") or
            "\\" in value or any(c.isspace() for c in value) or
            host.endswith(".") or "%" in host or
            any(ord(c) > 127 for c in host)):
        raise ZapEvidenceError("Only exact clean origins allowed")
    labels = host.split(".")
    if ":" not in host and (len(labels) < 2 and host != "localhost" or
            any(not part or len(part) > 63 or not part[0].isalnum() or
            not part[-1].isalnum() or
            not all(c.isascii() and (c.isalnum() or c == "-") for c in part)
            for part in labels)):
        raise ZapEvidenceError("Invalid host")
    return f"{parsed.scheme}://{('[' + host + ']') if ':' in host else host}" + (
        f":{port}" if port is not None else "")


def import_zap_alerts(payload: bytes, *, approved_origins: tuple[str, ...],
                      max_alerts: int = 500) -> dict:
    """Import ZAP alert JSON as unverified third-party observations only."""
    if (not isinstance(approved_origins, tuple) or not approved_origins or
            len(approved_origins) > 100 or type(max_alerts) is not int or
            not 0 < max_alerts <= 2000):
        raise ZapEvidenceError("Invalid scope or budget")
    scope = {_origin(origin) for origin in approved_origins}
    if not isinstance(payload, bytes) or not payload or len(payload) > 2_000_000:
        raise ZapEvidenceError("Invalid payload size")
    try:
        report = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ZapEvidenceError("Invalid JSON report") from exc
    if not isinstance(report, dict) or not isinstance(report.get("alerts"), list):
        raise ZapEvidenceError("Expected alerts array")
    alerts = report["alerts"]
    if len(alerts) > max_alerts:
        raise ZapEvidenceError("Alert budget exceeded")
    seen = set()
    for alert in alerts:
        if not isinstance(alert, dict):
            raise ZapEvidenceError("Invalid alert")
        origin = _origin(alert.get("url"))
        if origin not in scope:
            raise ZapEvidenceError("Alert outside exact approved origins")
        plugin = alert.get("pluginId")
        risk = alert.get("riskcode")
        if (not isinstance(plugin, str) or not plugin.isascii() or
                not plugin.isdigit() or not 1 <= len(plugin) <= 12 or
                type(risk) is not int or risk not in (0, 1, 2, 3)):
            raise ZapEvidenceError("Invalid alert identity or risk")
        seen.add((origin, plugin, risk))
    return {
        "schema": "red.zap_offline_alert_evidence.v1",
        "source_tool": "OWASP ZAP",
        "source_report_sha256": hashlib.sha256(payload).hexdigest(),
        "alert_count": len(alerts),
        "unique_observation_count": len(seen),
        "observations": [
            {"observation_id": hashlib.sha256(
                f"{origin}|{plugin}|{risk}".encode()).hexdigest(),
             "risk_code": risk, "status": "unverified_third_party_observation",
             "exploitability": "not_established"}
            for origin, plugin, risk in sorted(seen)
        ],
        "authority": "evidence_only_not_authorization",
        "limitations": "Offline alert JSON only; no ZAP service, scan or verification",
    }
