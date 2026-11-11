"""Bounded offline Nuclei JSONL evidence ingestion; never runs templates or tools."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit


class NucleiEvidenceError(ValueError):
    """Untrusted, malformed, or out-of-scope offline evidence."""


def import_nuclei_jsonl(
    payload: bytes, *, engagement_id: str, authorized_hosts: tuple[str, ...],
    max_bytes: int = 262144, max_records: int = 512,
) -> dict:
    """Parse a deliberately narrow Nuclei JSONL subset without confirming findings."""
    if (type(payload) is not bytes or type(max_bytes) is not int
            or not 0 < max_bytes <= 1048576 or not 0 < len(payload) <= max_bytes
            or type(max_records) is not int or not 0 < max_records <= 4096
            or not isinstance(engagement_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", engagement_id) is None
            or type(authorized_hosts) is not tuple or not 0 < len(authorized_hosts) <= 256
            or any(type(host) is not str or not host or host != host.strip()
                   or host.lower() != host or not re.fullmatch(r"[a-z0-9.:-]{1,253}", host)
                   for host in authorized_hosts)
            or len(set(authorized_hosts)) != len(authorized_hosts)):
        raise NucleiEvidenceError("Invalid engagement, host scope or budget")
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise NucleiEvidenceError("Invalid UTF-8 evidence") from exc
    if not 0 < len(lines) <= max_records or any(not line.strip() for line in lines):
        raise NucleiEvidenceError("Invalid record count or blank record")
    observations = []
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise NucleiEvidenceError("Malformed JSONL record") from exc
        if type(row) is not dict or not {"template-id", "matched-at", "info"} <= row.keys():
            raise NucleiEvidenceError("Missing Nuclei fields")
        template = row["template-id"]
        info = row["info"]
        if (type(template) is not str
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", template) is None
                or type(info) is not dict
                or info.get("severity") not in ("info", "low", "medium", "high", "critical")):
            raise NucleiEvidenceError("Invalid template or severity")
        url = row["matched-at"]
        if type(url) is not str or len(url) > 4096:
            raise NucleiEvidenceError("Invalid matched target")
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise NucleiEvidenceError("Malformed matched target") from exc
        if (parsed.scheme not in ("http", "https") or not parsed.netloc
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment or host not in authorized_hosts
                or port is not None and not 1 <= port <= 65535):
            raise NucleiEvidenceError("Out-of-scope or unsafe matched target")
        observations.append({
            "template_id": template, "host": host,
            "severity_claimed": info["severity"],
            "classification": "unverified_external_observation",
        })
    return {
        "schema": "red.nuclei_offline_evidence.v1",
        "engagement_id": engagement_id,
        "source_sha256": hashlib.sha256(payload).hexdigest(),
        "observation_count": len(observations),
        "observations": observations,
        "external_execution": False,
        "integration_verified": False,
        "confirmed_findings": 0,
        "limitations": "Imported third-party alerts are unverified, not proof of exploitability or authorization.",
    }
