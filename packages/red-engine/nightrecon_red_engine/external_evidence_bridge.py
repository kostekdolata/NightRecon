"""Convert scope-reviewed external observations to native Red Night evidence.

This module never authorises scanning or writes to an engagement store.
Callers must derive allowed addresses from the active engagement policy.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json

from nightrecon_shared_core.contracts import EvidenceRecord
from .evidence_correlation import EvidenceSummary


def build_external_evidence(
    *,
    engagement_id: str,
    summary: EvidenceSummary,
    allowed_addresses: frozenset[str],
    observed_at: str | None = None,
) -> tuple[EvidenceRecord, ...]:
    """Produce deterministic IDs, preserve source and mark imports unverified."""
    allowed = frozenset(str(ipaddress.ip_address(value)) for value in allowed_addresses)
    timestamp = observed_at or datetime.now(timezone.utc).isoformat()
    records = []
    for host in summary.hosts:
        if host.address not in allowed:
            raise ValueError("Imported host is outside the authorised engagement scope")
        data = {
            "address": host.address,
            "nmap_observed": host.discovered_by_nmap,
            "pcap_observed": host.observed_in_pcap,
            "services": [
                {"protocol": protocol, "port": port, "state": state, "name": name}
                for protocol, port, state, name in host.services
            ],
            "verification": "unverified",
            "import_sources": list(summary.sources),
        }
        stable = json.dumps(data, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256((engagement_id + "\n" + stable).encode("utf-8")).hexdigest()[:24]
        records.append(EvidenceRecord(
            engagement_id=engagement_id,
            evidence_id="external-import-" + digest,
            source_night="red",
            evidence_type="external-network-observation",
            observed_at=timestamp,
            provenance="third-party-import",
            data=data,
            limitations=(
                "Imported observations are not independently validated by Red Night.",
                "No exploitability or vulnerability claim is inferred from these observations.",
            ),
        ))
    return tuple(records)
