"""Bounded offline Amass JSONL importer; never performs domain enumeration."""
from __future__ import annotations

import hashlib
import json

from .nuclei_offline_jsonl_import import _host


class AmassOfflineImportError(ValueError):
    """Untrusted, malformed, oversized or out-of-scope enumeration evidence."""


def import_amass_jsonl(payload: bytes, *, allowed_hosts: tuple[str, ...],
                       source_name: str = "amass.jsonl", max_bytes: int = 2_000_000,
                       max_records: int = 4096) -> dict:
    """Accept only explicitly allowlisted DNS names, not implied subdomains."""
    if (type(max_bytes) is not int or not 0 < max_bytes <= 10_000_000
            or type(max_records) is not int or not 0 < max_records <= 10000
            or not isinstance(payload, bytes) or not 0 < len(payload) <= max_bytes
            or not isinstance(allowed_hosts, tuple) or not 0 < len(allowed_hosts) <= 256
            or not isinstance(source_name, str) or not 0 < len(source_name) <= 256):
        raise AmassOfflineImportError("Invalid payload, scope or budget")
    try:
        scope = {_host(host) for host in allowed_hosts}
    except ValueError as exc:
        raise AmassOfflineImportError("Invalid exact scope") from exc
    if len(scope) != len(allowed_hosts):
        raise AmassOfflineImportError("Duplicate exact host")
    lines = payload.splitlines()
    if not lines or len(lines) > max_records or any(not line.strip() for line in lines):
        raise AmassOfflineImportError("Invalid record count")
    observations = []
    for index, line in enumerate(lines):
        try:
            record = json.loads(line)
        except (UnicodeDecodeError, ValueError) as exc:
            raise AmassOfflineImportError("Malformed JSONL") from exc
        if not isinstance(record, dict):
            raise AmassOfflineImportError("Invalid Amass record")
        name = record.get("name")
        if not isinstance(name, str):
            raise AmassOfflineImportError("Missing DNS name")
        try:
            canonical = _host(name)
        except ValueError as exc:
            raise AmassOfflineImportError("Invalid DNS name") from exc
        if canonical != name or canonical not in scope:
            raise AmassOfflineImportError("Name outside exact scope")
        if not any(c.isalpha() for c in name) or "." not in name:
            raise AmassOfflineImportError("Expected DNS name, not IP or single label")
        # Never trust arbitrary third-party fields as instructions or credentials.
        observations.append({"host": canonical, "record_index": index,
                             "classification": "unverified_tool_observation"})
    return {"schema": "red.amass_offline_jsonl_import.v1",
            "source_tool": "Amass", "source_name": source_name,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "authority": "untrusted_offline_import",
            "record_count": len(observations), "observations": observations,
            "limitations": "Imported DNS names are unverified; no DNS resolution, target authorization, active enumeration, or exploitability is established."}
