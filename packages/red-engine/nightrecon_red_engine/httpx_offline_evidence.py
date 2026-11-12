"""Offline ProjectDiscovery httpx JSONL importer; never executes probes."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from urllib.parse import urlsplit


class HttpxEvidenceError(ValueError):
    """Untrusted evidence is malformed or outside the approved exact origins."""


def _origin(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise HttpxEvidenceError("Invalid origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
    except ValueError as exc:
        raise HttpxEvidenceError("Invalid URL") from exc
    if (parsed.scheme not in ("http", "https") or not host or
            parsed.username is not None or parsed.password is not None or
            parsed.path not in ("", "/") or parsed.query or parsed.fragment or
            any(c.isspace() for c in value) or "\\" in value):
        raise HttpxEvidenceError("Only clean HTTP(S) origins are allowed")
    if host.endswith(".") or "%" in host or any(ord(c) > 127 for c in host):
        raise HttpxEvidenceError("Invalid host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if (len(labels) < 2 or any(not label or len(label) > 63 or
            not label[0].isalnum() or not label[-1].isalnum() or
            not all(c.isascii() and (c.isalnum() or c == "-") for c in label)
            for label in labels)):
            raise HttpxEvidenceError("Invalid DNS host")
    hostpart = f"[{host}]" if ":" in host else host
    return f"{parsed.scheme}://{hostpart}" + (f":{port}" if port is not None else "")


def import_httpx_jsonl(payload: bytes, *, approved_origins: tuple[str, ...],
                      max_records: int = 500) -> dict:
    """Import unverified observations without granting scanning authority."""
    if (not isinstance(approved_origins, tuple) or not approved_origins or
            len(approved_origins) > 100 or
            type(max_records) is not int or not 0 < max_records <= 2000):
        raise HttpxEvidenceError("Invalid scope or budget")
    origins = {_origin(value) for value in approved_origins}
    if not isinstance(payload, bytes) or not payload or len(payload) > 2_000_000:
        raise HttpxEvidenceError("Invalid payload size")
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise HttpxEvidenceError("Invalid UTF-8") from exc
    if not lines or len(lines) > max_records:
        raise HttpxEvidenceError("Missing or over-budget records")
    observations = set()
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError as exc:
            raise HttpxEvidenceError("Malformed JSONL") from exc
        if not isinstance(record, dict) or not isinstance(record.get("url"), str):
            raise HttpxEvidenceError("Missing URL")
        # Exact-origin evidence only: paths, queries, credentials and redirects
        # are not retained or used to infer additional authority.
        origin = _origin(record["url"])
        if origin not in origins:
            raise HttpxEvidenceError("Origin outside exact approved scope")
        status = record.get("status_code")
        if type(status) is not int or not 100 <= status <= 599:
            raise HttpxEvidenceError("Invalid HTTP status")
        observations.add((origin, status))
    return {
        "schema": "red.httpx_offline_origin_evidence.v1",
        "source_tool": "ProjectDiscovery httpx",
        "source_report_sha256": hashlib.sha256(payload).hexdigest(),
        "record_count": len(lines),
        "unique_observation_count": len(observations),
        "observations": [
            {"observation_id": hashlib.sha256(f"{origin}|{status}".encode()).hexdigest(),
             "http_status": status, "status": "unverified_third_party_observation"}
            for origin, status in sorted(observations)
        ],
        "authority": "evidence_only_not_authorization",
        "limitations": "Offline exact-origin JSONL only; no probing, redirect following or verification",
    }
