"""Source-bound offline Nuclei review: reparse original bytes before operator triage.

No network, tool execution or finding promotion. The supplied source bytes are
authoritative; a separately supplied imported object cannot substitute for them.
"""
from __future__ import annotations

import hashlib
import hmac

from .nuclei_offline_evidence import import_nuclei_jsonl
from .nuclei_operator_triage import build_nuclei_triage, NucleiTriageError


def review_nuclei_source(
    payload: bytes, *, engagement_id: str, authorized_hosts: tuple[str, ...],
    expected_source_sha256: str, decisions: dict | None = None,
    max_bytes: int = 262144, max_records: int = 512,
) -> dict:
    """Review exact offline source bytes only when their pinned digest matches.

    The source digest must originate from an independently trusted manifest.
    Merely supplying a digest calculated from the same untrusted payload does
    not establish authenticity, acquisition integrity or tool integration.
    """
    if (type(payload) is not bytes or type(expected_source_sha256) is not str
            or len(expected_source_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_source_sha256)):
        raise NucleiTriageError("Missing or malformed pinned source digest")
    actual = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(actual, expected_source_sha256):
        raise NucleiTriageError("Offline source digest mismatch")
    imported = import_nuclei_jsonl(
        payload, engagement_id=engagement_id, authorized_hosts=authorized_hosts,
        max_bytes=max_bytes, max_records=max_records,
    )
    report = build_nuclei_triage(
        imported, decisions=decisions, max_observations=max_records,
    )
    report["source_binding"] = "verified_against_supplied_pinned_digest"
    report["source_binding_limitations"] = (
        "Digest comparison does not authenticate the manifest or establish tool execution."
    )
    # Rebind the report digest to the final, source-bound representation.
    import json
    report.pop("report_sha256")
    report["report_sha256"] = hashlib.sha256(
        json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return report
