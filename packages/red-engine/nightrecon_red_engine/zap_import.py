"""Bounded, passive OWASP ZAP JSON alert import.

Data model intentionally stores only metadata, never request/response bodies,
cookies, authentication secrets, or untrusted HTML.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import json
from urllib.parse import urlsplit

MAX_BYTES = 8 * 1024 * 1024
MAX_ALERTS = 10000

@dataclass(frozen=True)
class ZapAlert:
    site: str
    plugin_id: str
    name: str
    risk: str
    confidence: str
    count: int

@dataclass(frozen=True)
class ZapEvidence:
    source: str
    alerts: tuple[ZapAlert, ...]

def parse_zap_json(data: bytes) -> ZapEvidence:
    """Parse ZAP traditional JSON report shape: site[].alerts[]."""
    if len(data) > MAX_BYTES:
        raise ValueError("ZAP report exceeds size limit.")
    try:
        obj = json.loads(data)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid ZAP JSON.") from exc
    if not isinstance(obj, dict) or not isinstance(obj.get("site"), list):
        raise ValueError("Expected ZAP site array.")
    output = []
    for site in obj["site"]:
        if not isinstance(site, dict):
            raise ValueError("Invalid ZAP site record.")
        url = site.get("@name", "")
        if not isinstance(url, str) or len(url) > 2048:
            raise ValueError("Invalid site origin.")
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Invalid site origin.")
        origin = parsed.scheme + "://" + parsed.netloc
        alerts = site.get("alerts", [])
        if not isinstance(alerts, list):
            raise ValueError("Invalid ZAP alerts.")
        for alert in alerts:
            if len(output) >= MAX_ALERTS:
                raise ValueError("Too many ZAP alerts.")
            if not isinstance(alert, dict):
                raise ValueError("Invalid ZAP alert.")
            def val(key: str, limit: int = 256) -> str:
                result = alert.get(key, "")
                if not isinstance(result, (str, int)):
                    raise ValueError("Invalid ZAP alert field.")
                return str(result)[:limit]
            instances = alert.get("instances", [])
            if not isinstance(instances, list):
                raise ValueError("Invalid ZAP instances.")
            output.append(ZapAlert(
                site=origin,
                plugin_id=val("pluginid", 64),
                name=val("name"),
                risk=val("riskdesc", 128),
                confidence=val("confidence", 64),
                count=len(instances),
            ))
    return ZapEvidence(source="zap-json-unverified", alerts=tuple(output))

def import_zap_json_file(path: str | Path) -> ZapEvidence:
    with Path(path).open("rb") as stream:
        return parse_zap_json(stream.read(MAX_BYTES + 1))
