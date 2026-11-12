"""Offline Amass JSONL evidence importer; no discovery or subprocess execution."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re

class AmassEvidenceError(ValueError):
    """Untrusted evidence is outside exact engagement scope or malformed."""

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\Z")
_MAX_BYTES = 2_000_000
_MAX_RECORDS = 2000


def _domain(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise AmassEvidenceError("Invalid domain")
    name = value.lower().removesuffix(".")
    if len(name) > 253 or not all(_LABEL.fullmatch(part) for part in name.split(".")):
        raise AmassEvidenceError("Invalid DNS name")
    if len(name.split(".")) < 2:
        raise AmassEvidenceError("Fully qualified DNS name required")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise AmassEvidenceError("IP addresses are not DNS names")


def import_amass_jsonl(payload: bytes, *, approved_domain: str, max_records: int = 500) -> dict:
    """Parse previously generated records for one exact authorized DNS suffix.

    A record is third-party unverified evidence, not an authorization or proof
    of ownership, reachability, vulnerability, or permission to scan.
    """
    domain = _domain(approved_domain)
    if type(max_records) is not int or not 0 < max_records <= _MAX_RECORDS:
        raise AmassEvidenceError("Invalid record budget")
    if not isinstance(payload, bytes) or not payload or len(payload) > _MAX_BYTES:
        raise AmassEvidenceError("Invalid payload size")
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise AmassEvidenceError("Invalid UTF-8") from exc
    if not lines or len(lines) > max_records:
        raise AmassEvidenceError("Missing or over-budget records")
    names = set()
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError as exc:
            raise AmassEvidenceError("Malformed JSONL") from exc
        if not isinstance(record, dict) or not isinstance(record.get("name"), str):
            raise AmassEvidenceError("Missing DNS identity")
        name = _domain(record["name"])
        if name != domain and not name.endswith("." + domain):
            raise AmassEvidenceError("DNS identity outside exact approved suffix")
        names.add(name)
    return {
        "schema": "red.amass_offline_dns_evidence.v1",
        "source_tool": "Amass",
        "approved_domain": domain,
        "source_report_sha256": hashlib.sha256(payload).hexdigest(),
        "record_count": len(lines),
        "unique_observation_count": len(names),
        "observations": [
            {"observation_id": hashlib.sha256(name.encode()).hexdigest(),
             "status": "unverified_third_party_observation",
             "reachability": "not_established"} for name in sorted(names)
        ],
        "authority": "evidence_only_not_authorization",
        "limitations": "Offline JSONL only; no Amass execution or DNS validation",
    }
