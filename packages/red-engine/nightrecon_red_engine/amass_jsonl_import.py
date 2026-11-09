"""Bounded offline Amass JSONL evidence import; never performs DNS or network requests."""
from __future__ import annotations

import hashlib
import ipaddress
import json


class AmassEvidenceError(ValueError):
    """Malformed or unsupported Amass evidence."""


def import_amass_jsonl(payload: bytes, *, source_name: str, allowed_domains: tuple[str, ...],
                       max_bytes: int = 8_000_000, max_records: int = 10_000) -> dict:
    """Import Amass enumeration JSONL as untrusted observations within exact DNS suffix scope."""
    if not isinstance(payload, bytes) or not 0 < len(payload) <= max_bytes:
        raise AmassEvidenceError("JSONL payload size invalid")
    if not isinstance(source_name, str) or not 0 < len(source_name) <= 256:
        raise AmassEvidenceError("Invalid source name")
    if not isinstance(allowed_domains, tuple) or not allowed_domains:
        raise AmassEvidenceError("Explicit domain scope required")
    def canonical(value: str) -> str:
        if not isinstance(value, str):
            raise AmassEvidenceError("Invalid DNS name")
        value = value.rstrip(".").lower()
        if not value or len(value) > 253:
            raise AmassEvidenceError("Invalid DNS name")
        labels = value.split(".")
        if any(not 0 < len(label) <= 63 or label[0] == "-" or label[-1] == "-"
               or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in label)
               for label in labels):
            raise AmassEvidenceError("Invalid DNS name")
        return value

    domains = tuple(canonical(domain) for domain in allowed_domains)
    if any("." not in domain for domain in domains):
        raise AmassEvidenceError("Fully qualified domain scope required")
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise AmassEvidenceError("Invalid UTF-8") from exc
    if not lines or len(lines) > max_records:
        raise AmassEvidenceError("Record budget exceeded")
    observations = []
    for line in lines:
        if not line.strip():
            raise AmassEvidenceError("Empty JSONL record")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AmassEvidenceError("Invalid JSONL record") from exc
        if not isinstance(record, dict):
            raise AmassEvidenceError("Invalid Amass record")
        name = canonical(record.get("name"))
        if not any(name == domain or name.endswith("." + domain) for domain in domains):
            raise AmassEvidenceError("Discovered name outside authorized domain scope")
        addresses = record.get("addresses", [])
        if not isinstance(addresses, list) or len(addresses) > 100:
            raise AmassEvidenceError("Invalid address list")
        ips = []
        for address in addresses:
            if not isinstance(address, dict) or not isinstance(address.get("ip"), str):
                raise AmassEvidenceError("Invalid address record")
            try:
                ips.append(str(ipaddress.ip_address(address["ip"])))
            except ValueError as exc:
                raise AmassEvidenceError("Invalid IP address") from exc
        source = record.get("source", "")
        tag = record.get("tag", "")
        if any(not isinstance(value, str) or len(value) > 256 for value in (source, tag)):
            raise AmassEvidenceError("Invalid source metadata")
        observations.append({"name": name, "addresses": ips, "source": source, "tag": tag,
                             "classification": "unverified_tool_observation"})
    return {"source_tool": "Amass", "source_name": source_name,
            "sha256": hashlib.sha256(payload).hexdigest(), "record_count": len(observations),
            "observations": observations, "authority": "untrusted_offline_import"}
