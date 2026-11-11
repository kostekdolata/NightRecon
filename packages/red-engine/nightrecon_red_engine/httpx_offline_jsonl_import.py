"""Bounded offline ProjectDiscovery httpx JSONL evidence import; no HTTP requests."""
from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit


class HttpxOfflineImportError(ValueError):
    """Invalid, untrusted or out-of-scope httpx observations."""


def _exact_url(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("Invalid URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL") from exc
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or any(c.isspace() for c in value)
            or parsed.hostname.lower() != parsed.hostname):
        raise ValueError("Invalid URL")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    if parsed.geturl() != value:
        raise ValueError("Noncanonical URL")
    return value


def import_httpx_jsonl(
    payload: bytes, *, allowed_urls: tuple[str, ...],
    source_name: str = "httpx.jsonl", max_bytes: int = 2_000_000,
    max_records: int = 4096,
) -> dict:
    """Import exact allowlisted URLs only; imported observations grant no authority."""
    if (not isinstance(payload, bytes) or not 0 < len(payload) <= max_bytes
            or type(max_bytes) is not int or not 0 < max_bytes <= 10_000_000
            or type(max_records) is not int or not 0 < max_records <= 10000
            or not isinstance(allowed_urls, tuple) or not 0 < len(allowed_urls) <= 256
            or not isinstance(source_name, str) or not 0 < len(source_name) <= 256):
        raise HttpxOfflineImportError("Invalid payload, scope or budget")
    try:
        scope = {_exact_url(url) for url in allowed_urls}
    except ValueError as exc:
        raise HttpxOfflineImportError("Invalid URL scope") from exc
    if len(scope) != len(allowed_urls):
        raise HttpxOfflineImportError("Duplicate exact URL")
    lines = payload.splitlines()
    if not lines or len(lines) > max_records or any(not line.strip() for line in lines):
        raise HttpxOfflineImportError("Invalid record count")
    observations = []
    for index, line in enumerate(lines):
        try:
            record = json.loads(line)
        except (UnicodeDecodeError, ValueError) as exc:
            raise HttpxOfflineImportError("Malformed JSONL") from exc
        if not isinstance(record, dict) or not isinstance(record.get("url"), str):
            raise HttpxOfflineImportError("Missing URL")
        try:
            url = _exact_url(record["url"])
        except ValueError as exc:
            raise HttpxOfflineImportError("Invalid observed URL") from exc
        if url not in scope:
            raise HttpxOfflineImportError("Observed URL outside exact scope")
        status = record.get("status_code")
        if type(status) is not int or not 100 <= status <= 599:
            raise HttpxOfflineImportError("Invalid HTTP status")
        observations.append({
            "url": url, "status_code": status, "record_index": index,
            "classification": "unverified_tool_observation",
        })
    return {
        "schema": "red.httpx_offline_jsonl_import.v1",
        "source_tool": "ProjectDiscovery httpx",
        "source_name": source_name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "authority": "untrusted_offline_import",
        "record_count": len(observations),
        "observations": observations,
        "limitations": "Imported status codes are unverified; no HTTP request, target authorization, vulnerability, or exploitability is established.",
    }
