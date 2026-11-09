"""Bounded, offline ProjectDiscovery httpx JSONL import. No network activity."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from urllib.parse import urlsplit


class HttpxEvidenceError(ValueError):
    """Untrusted or out-of-scope httpx evidence."""


def _host(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise HttpxEvidenceError("Invalid host")
    value = value.rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    labels = value.split(".")
    if len(labels) < 2 or any(
        not 0 < len(label) <= 63 or label[0] == "-" or label[-1] == "-"
        or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in label)
        for label in labels
    ):
        raise HttpxEvidenceError("Invalid host")
    return value


def import_httpx_jsonl(
    payload: bytes, *, source_name: str, allowed_hosts: tuple[str, ...],
    max_bytes: int = 8_000_000, max_records: int = 10_000,
) -> dict:
    """Parse httpx JSONL without trusting findings or expanding authorised host scope.

    allowed_hosts are exact hosts, not wildcard domain suffixes. URL paths are evidence
    only and are never fetched or executed. Fail closed on any malformed record.
    """
    if not isinstance(payload, bytes) or not 0 < len(payload) <= max_bytes:
        raise HttpxEvidenceError("Invalid payload size")
    if not isinstance(source_name, str) or not 0 < len(source_name) <= 256:
        raise HttpxEvidenceError("Invalid source name")
    if not isinstance(allowed_hosts, tuple) or not allowed_hosts:
        raise HttpxEvidenceError("Explicit host scope required")
    scope = {_host(host) for host in allowed_hosts}
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise HttpxEvidenceError("Invalid UTF-8") from exc
    if not lines or len(lines) > max_records:
        raise HttpxEvidenceError("Record budget exceeded")
    observations = []
    for line in lines:
        if not line.strip():
            raise HttpxEvidenceError("Empty JSONL record")
        try:
            record = json.loads(line)
        except (ValueError, TypeError) as exc:
            raise HttpxEvidenceError("Invalid JSONL") from exc
        if not isinstance(record, dict):
            raise HttpxEvidenceError("Invalid httpx record")
        url = record.get("url")
        if not isinstance(url, str) or not 0 < len(url) <= 8192:
            raise HttpxEvidenceError("Invalid URL")
        try:
            parts = urlsplit(url)
            port = parts.port
            hostname = parts.hostname
        except ValueError as exc:
            raise HttpxEvidenceError("Invalid URL") from exc
        if parts.scheme.lower() not in ("http", "https") or not hostname or (
            parts.username is not None or parts.password is not None
        ) or not parts.netloc or port == 0:
            raise HttpxEvidenceError("Unsupported URL")
        host = _host(hostname)
        if host not in scope:
            raise HttpxEvidenceError("URL outside exact authorised host scope")
        status = record.get("status_code")
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            raise HttpxEvidenceError("Invalid HTTP status")
        title = record.get("title")
        if title is not None and (not isinstance(title, str) or len(title) > 2048):
            raise HttpxEvidenceError("Invalid title")
        technologies = record.get("tech", [])
        if not isinstance(technologies, list) or len(technologies) > 100 or any(
            not isinstance(item, str) or len(item) > 256 for item in technologies
        ):
            raise HttpxEvidenceError("Invalid technologies")
        observations.append({
            "url": url, "host": host, "status_code": status, "title": title,
            "technologies": technologies,
            "classification": "unverified_tool_observation",
        })
    return {
        "source_tool": "ProjectDiscovery httpx", "source_name": source_name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "record_count": len(observations), "observations": observations,
        "authority": "untrusted_offline_import",
    }
