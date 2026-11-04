"""Read-only local OWASP ZAP API health and site-inventory connector.

Only contacts a user-running ZAP instance on IPv4 loopback using two fixed
read-only Core API view endpoints. It does not initiate scans or proxy traffic.
"""
from __future__ import annotations

from dataclasses import dataclass
import http.client
import json
import re

_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+~-]{0,79}$")
MAX_RESPONSE_BYTES = 65536


@dataclass(frozen=True)
class ZapLocalStatus:
    version: str
    site_count: int

    def operator_report(self) -> dict:
        return {
            "tool": "owasp-zap",
            "operation": "local-read-only-status",
            "execution_status": "succeeded",
            "api_calls": ("core/view/version", "core/view/sites"),
            "tool_version": self.version,
            "observed_site_count": self.site_count,
            "scan_started": False,
            "evidence_status": "unverified-local-observation",
            "limitations": (
                "Only locally reported API metadata was observed.",
                "No active scan or vulnerability confirmation was performed.",
            ),
        }


def inspect_local_zap(*, port: int = 8080, api_key: str, timeout: float = 3.0) -> ZapLocalStatus:
    """Inspect explicitly configured loopback ZAP without executing actions."""
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Invalid local ZAP port")
    if not isinstance(api_key, str) or not 1 <= len(api_key) <= 512 or any(
        c in api_key for c in "\r\n"
    ):
        raise PermissionError("ZAP API key must be supplied through the protected environment")
    if not 0.1 <= timeout <= 10:
        raise ValueError("Invalid ZAP API timeout")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"X-ZAP-API-Key": api_key, "Accept": "application/json"}
    def read_fixed(path: str) -> dict:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError(f"ZAP read-only endpoint failed with HTTP {response.status}")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("ZAP API response exceeded size limit")
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Invalid ZAP API response") from exc
        if not isinstance(payload, dict):
            raise ValueError("Invalid ZAP API response")
        return payload
    try:
        version_record = read_fixed("/JSON/core/view/version/")
        sites_record = read_fixed("/JSON/core/view/sites/")
    finally:
        connection.close()
    version = version_record.get("version")
    sites = sites_record.get("sites")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise ValueError("Invalid ZAP version metadata")
    if not isinstance(sites, list) or len(sites) > 10000 or not all(
        isinstance(site, str) for site in sites
    ):
        raise ValueError("Invalid ZAP site inventory")
    return ZapLocalStatus(version=version, site_count=len(sites))
