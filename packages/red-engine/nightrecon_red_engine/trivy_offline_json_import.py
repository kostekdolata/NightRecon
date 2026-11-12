"""Bounded offline Trivy JSON vulnerability evidence, never execution or authorization."""
from __future__ import annotations

import hashlib
import json


class TrivyEvidenceError(ValueError):
    """Untrusted Trivy input failed a strict evidence contract."""


def import_trivy_json(payload: bytes, *, approved_targets: tuple[str, ...],
                      max_bytes: int = 8_000_000, max_findings: int = 10000) -> dict:
    """Accept only explicitly selected exact targets; never infer engagement scope."""
    if not isinstance(payload, bytes) or not 0 < len(payload) <= max_bytes:
        raise TrivyEvidenceError("Invalid payload budget")
    if (not isinstance(approved_targets, tuple) or not approved_targets or
            len(approved_targets) > 100 or any(
                not isinstance(x, str) or not 0 < len(x) <= 2048 for x in approved_targets
            ) or len(set(approved_targets)) != len(approved_targets)):
        raise TrivyEvidenceError("Explicit exact approved targets required")
    if type(max_findings) is not int or not 0 < max_findings <= 100000:
        raise TrivyEvidenceError("Invalid finding budget")
    try:
        root = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrivyEvidenceError("Invalid JSON") from exc
    if not isinstance(root, dict) or not isinstance(root.get("Results"), list):
        raise TrivyEvidenceError("Trivy Results array required")
    version = root.get("SchemaVersion")
    if type(version) is not int or version != 2:
        raise TrivyEvidenceError("Unsupported Trivy schema")
    results = root["Results"]
    if len(results) > 1000:
        raise TrivyEvidenceError("Result budget exceeded")
    findings = []
    observed = set()
    for result in results:
        if not isinstance(result, dict):
            raise TrivyEvidenceError("Invalid result")
        target = result.get("Target")
        if not isinstance(target, str) or target not in approved_targets:
            raise TrivyEvidenceError("Unapproved or missing target")
        observed.add(target)
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list) or len(vulnerabilities) + len(findings) > max_findings:
            raise TrivyEvidenceError("Finding budget exceeded")
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                raise TrivyEvidenceError("Invalid vulnerability")
            fields = ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity")
            if any(not isinstance(vuln.get(f, ""), str) or len(vuln.get(f, "")) > 512 for f in fields):
                raise TrivyEvidenceError("Invalid vulnerability field")
            if not vuln.get("VulnerabilityID") or not vuln.get("PkgName"):
                raise TrivyEvidenceError("Missing vulnerability identity")
            findings.append({
                "target": target,
                "vulnerability_id": vuln["VulnerabilityID"],
                "package": vuln["PkgName"],
                "installed_version": vuln.get("InstalledVersion", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
                "reported_severity": vuln.get("Severity", "UNKNOWN"),
                "classification": "unverified_tool_observation",
            })
    return {
        "schema": "red.trivy_offline_import.v1",
        "source_tool": "Trivy",
        "source_schema_version": version,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "approved_target_count": len(approved_targets),
        "observed_target_count": len(observed),
        "finding_count": len(findings),
        "findings": findings,
        "authority": "untrusted_offline_import_not_authorization",
        "limitations": "No execution, exploitability verification, remediation or retest established",
    }
