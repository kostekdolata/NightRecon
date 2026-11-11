"""Offline, evidence-honest correlation of already validated Amass and httpx imports.

Never performs DNS/HTTP requests or turns imported observations into authorization.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from .amass_offline_jsonl_import import import_amass_jsonl
from .httpx_offline_jsonl_import import import_httpx_jsonl


class OfflineWebCorrelationError(ValueError):
    """Invalid or conflicting offline evidence."""


def correlate_amass_httpx(
    amass_payload: bytes, httpx_payload: bytes, *,
    allowed_hosts: tuple[str, ...], allowed_urls: tuple[str, ...],
    max_links: int = 4096,
) -> dict:
    """Correlate exact-scope DNS observations with HTTP status observations.

    A matching hostname is only an unverified association, not proof that
    the HTTP endpoint belongs to or is reachable at the DNS observation.
    """
    if type(max_links) is not int or not 0 < max_links <= 10000:
        raise OfflineWebCorrelationError("Invalid correlation budget")
    try:
        dns = import_amass_jsonl(amass_payload, allowed_hosts=allowed_hosts)
        web = import_httpx_jsonl(httpx_payload, allowed_urls=allowed_urls)
    except ValueError as exc:
        raise OfflineWebCorrelationError("Invalid or out-of-scope source evidence") from exc
    dns_hosts = {obs["host"] for obs in dns["observations"]}
    links = []
    seen = set()
    for observation in web["observations"]:
        url = observation["url"]
        host = urlsplit(url).hostname
        if host not in dns_hosts:
            continue
        key = (host, url, observation["status_code"])
        if key in seen:
            continue
        if len(links) >= max_links:
            raise OfflineWebCorrelationError("Correlation budget exceeded")
        seen.add(key)
        links.append({
            "host": host, "url": url, "http_status": observation["status_code"],
            "classification": "unverified_cross_tool_association",
            "source_amass_sha256": dns["sha256"],
            "source_httpx_sha256": web["sha256"],
        })
    links.sort(key=lambda row: (row["host"], row["url"], row["http_status"]))
    return {
        "schema": "red.amass_httpx_offline_correlation.v1",
        "authority": "untrusted_offline_import",
        "sources": {
            "amass": {"sha256": dns["sha256"], "record_count": dns["record_count"]},
            "httpx": {"sha256": web["sha256"], "record_count": web["record_count"]},
        },
        "link_count": len(links),
        "links": links,
        "limitations": (
            "Unverified offline host-to-URL associations only; no DNS or HTTP "
            "verification, scope authorization, vulnerability, or exploitability established."
        ),
    }
