"""Bounded offline Prowler JSON evidence import. No tool execution or authority transfer."""
from __future__ import annotations

import hashlib
import json


class ProwlerEvidenceError(ValueError):
    pass


def import_prowler_json(payload: bytes, *, approved_account: str,
                        max_bytes: int = 2_000_000, max_findings: int = 5000) -> dict:
    """Accept only exact-account, structured Prowler findings as unverified observations."""
    if not isinstance(payload, bytes) or not 0 < len(payload) <= max_bytes:
        raise ProwlerEvidenceError("Invalid evidence size")
    if not isinstance(approved_account, str) or not approved_account.strip() or approved_account != approved_account.strip():
        raise ProwlerEvidenceError("Explicit approved account required")
    if type(max_findings) is not int or not 0 < max_findings <= 100000:
        raise ProwlerEvidenceError("Invalid finding budget")
    try:
        records = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProwlerEvidenceError("Malformed Prowler JSON") from exc
    if not isinstance(records, list) or len(records) > max_findings:
        raise ProwlerEvidenceError("Expected bounded findings array")
    normalized = []
    for record in records:
        if not isinstance(record, dict):
            raise ProwlerEvidenceError("Invalid finding")
        account = record.get("account_uid")
        check = record.get("check_id")
        status = record.get("status")
        resource = record.get("resource_uid")
        if account != approved_account or not all(isinstance(x, str) and x.strip() and len(x) <= 512 for x in (check, status, resource)):
            raise ProwlerEvidenceError("Out-of-scope or malformed finding")
        if status not in ("PASS", "FAIL", "MANUAL"):
            raise ProwlerEvidenceError("Unsupported finding status")
        normalized.append({"check_id": check, "resource_uid": resource, "observed_status": status,
                           "evidence_state": "unverified_third_party_observation"})
    return {"schema": "red.prowler_offline_evidence.v1",
            "tool": "Prowler", "account_uid": approved_account,
            "source_sha256": hashlib.sha256(payload).hexdigest(),
            "findings": normalized, "finding_count": len(normalized),
            "authority": "evidence_only_not_authorization",
            "limitations": "Offline imported findings; no cloud access, scope authorization, exploitability or remediation verified"}
