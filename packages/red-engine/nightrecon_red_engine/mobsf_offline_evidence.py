"""Bounded offline MobSF static-report evidence contract; never invokes a service."""
from __future__ import annotations

import hashlib
import json
import re

class MobSFEvidenceError(ValueError):
    """Untrusted evidence failed a fail-closed contract."""

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SEVERITIES = frozenset(("high", "warning", "info", "secure"))
_MAX_BYTES = 2_000_000
_MAX_FINDINGS = 2000


def import_mobsf_static_report(payload: bytes, *, approved_artifact_sha256: str,
                               max_findings: int = 500) -> dict:
    """Import a previously produced static report for one explicitly approved artifact.

    Does not confer authorization or validate a vulnerability. MobSF installation,
    service execution, and mobile-artifact submission are separate acceptance gates.
    """
    if not isinstance(approved_artifact_sha256, str) or not _SHA.fullmatch(approved_artifact_sha256):
        raise MobSFEvidenceError("Exact approved artifact digest required")
    if type(max_findings) is not int or not 0 < max_findings <= _MAX_FINDINGS:
        raise MobSFEvidenceError("Invalid finding budget")
    if not isinstance(payload, bytes) or not payload or len(payload) > _MAX_BYTES:
        raise MobSFEvidenceError("Invalid report size")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise MobSFEvidenceError("Invalid report JSON") from exc
    if not isinstance(document, dict):
        raise MobSFEvidenceError("Report object required")
    # The MobSF report hash is commonly MD5; it is not a sufficient scope identity.
    # An explicit SHA-256 field must match the approved artifact, without fallback.
    artifact_sha = document.get("sha256")
    if not isinstance(artifact_sha, str) or artifact_sha.lower() != approved_artifact_sha256:
        raise MobSFEvidenceError("Artifact SHA-256 outside approved scope")
    if document.get("app_type") not in ("apk", "ipa", "android", "ios"):
        raise MobSFEvidenceError("Unsupported static report platform")
    findings = document.get("code_analysis")
    if not isinstance(findings, dict) or len(findings) > max_findings:
        raise MobSFEvidenceError("Missing or over-budget static findings")
    normalized = []
    for key, entry in sorted(findings.items()):
        if not isinstance(key, str) or not key or len(key) > 256 or not isinstance(entry, dict):
            raise MobSFEvidenceError("Malformed finding")
        severity = entry.get("metadata", {}).get("severity") if isinstance(entry.get("metadata"), dict) else None
        if severity not in _SEVERITIES:
            raise MobSFEvidenceError("Unsupported finding severity")
        # Never export source snippets, filenames, raw descriptions, or other untrusted fields.
        normalized.append({"observation_id": hashlib.sha256(key.encode("utf-8")).hexdigest(),
                           "severity": severity, "status": "unverified_third_party_observation",
                           "exploitability": "not_established"})
    return {
        "schema": "red.mobsf_offline_static_evidence.v1",
        "source_tool": "MobSF",
        "approved_artifact_sha256": approved_artifact_sha256,
        "source_report_sha256": hashlib.sha256(payload).hexdigest(),
        "observation_count": len(normalized),
        "observations": normalized,
        "authority": "evidence_only_not_authorization",
        "limitations": "Offline static report only; no MobSF execution, validation, remediation or retest",
    }
