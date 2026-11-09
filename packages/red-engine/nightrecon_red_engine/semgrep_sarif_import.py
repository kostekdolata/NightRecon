"""Offline Semgrep SARIF evidence import. Never launches Semgrep or trusts SARIF as authority."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


class SemgrepEvidenceError(ValueError):
    """Malformed or unsupported Semgrep evidence."""


def import_semgrep_sarif(payload: bytes, *, source_name: str, max_bytes: int = 8_000_000,
                         max_results: int = 10_000) -> dict:
    """Return bounded, untrusted findings; no filesystem, network or process execution."""
    if not isinstance(payload, bytes) or not 0 < len(payload) <= max_bytes:
        raise SemgrepEvidenceError("SARIF payload size invalid")
    if not isinstance(source_name, str) or not 0 < len(source_name) <= 256:
        raise SemgrepEvidenceError("Invalid source name")
    try:
        root = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SemgrepEvidenceError("Invalid JSON") from exc
    if not isinstance(root, dict) or root.get("version") != "2.1.0" or not isinstance(root.get("runs"), list):
        raise SemgrepEvidenceError("SARIF 2.1.0 runs required")
    findings = []
    for run in root["runs"]:
        if not isinstance(run, dict) or not isinstance(run.get("tool"), dict):
            raise SemgrepEvidenceError("Malformed run")
        driver = run["tool"].get("driver")
        if not isinstance(driver, dict) or driver.get("name") != "Semgrep":
            raise SemgrepEvidenceError("Only Semgrep SARIF accepted")
        results = run.get("results", [])
        if not isinstance(results, list) or len(results) + len(findings) > max_results:
            raise SemgrepEvidenceError("Result budget exceeded")
        for result in results:
            if not isinstance(result, dict):
                raise SemgrepEvidenceError("Malformed result")
            rule = result.get("ruleId")
            if not isinstance(rule, str) or not 0 < len(rule) <= 512:
                raise SemgrepEvidenceError("Invalid rule ID")
            locations = result.get("locations", [])
            if not isinstance(locations, list) or len(locations) > 100:
                raise SemgrepEvidenceError("Invalid locations")
            paths = []
            for loc in locations:
                if not isinstance(loc, dict):
                    raise SemgrepEvidenceError("Invalid location")
                physical = loc.get("physicalLocation", {})
                if not isinstance(physical, dict):
                    raise SemgrepEvidenceError("Invalid physical location")
                artifact = physical.get("artifactLocation", {})
                if not isinstance(artifact, dict):
                    raise SemgrepEvidenceError("Invalid artifact location")
                uri = artifact.get("uri")
                if uri is not None:
                    if not isinstance(uri, str) or len(uri) > 4096:
                        raise SemgrepEvidenceError("Invalid artifact URI")
                    paths.append(uri)
            msg = result.get("message", {})
            if not isinstance(msg, dict):
                raise SemgrepEvidenceError("Invalid message")
            message = msg.get("text", "")
            if not isinstance(message, str) or len(message) > 8192:
                raise SemgrepEvidenceError("Invalid message text")
            findings.append({"rule_id": rule, "level": result.get("level", "warning")
                             if result.get("level", "warning") in ("error", "warning", "note", "none")
                             else "unknown", "message": message, "artifact_uris": paths,
                             "classification": "unverified_tool_observation"})
    return {"source_tool": "Semgrep", "source_name": source_name,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "finding_count": len(findings), "findings": findings,
            "authority": "untrusted_offline_import"}
