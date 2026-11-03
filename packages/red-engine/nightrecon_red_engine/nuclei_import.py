"""Passive import of bounded Nuclei JSONL findings; no template execution."""
from __future__ import annotations
from dataclasses import dataclass
import json
from pathlib import Path
from urllib.parse import urlsplit

MAX_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 10000
MAX_LINE_BYTES = 16384

@dataclass(frozen=True)
class NucleiFinding:
    template_id: str
    severity: str
    matched_origin: str
    matcher_name: str

@dataclass(frozen=True)
class NucleiEvidence:
    source: str
    findings: tuple[NucleiFinding, ...]


def parse_nuclei_jsonl(data: bytes) -> NucleiEvidence:
    if len(data) > MAX_BYTES:
        raise ValueError("Nuclei output exceeds size limit.")
    findings = []
    for line in data.splitlines():
        if not line.strip():
            continue
        if len(line) > MAX_LINE_BYTES:
            raise ValueError("Nuclei finding exceeds line limit.")
        if len(findings) >= MAX_FINDINGS:
            raise ValueError("Too many Nuclei findings.")
        try:
            obj = json.loads(line)
        except (UnicodeError, ValueError) as exc:
            raise ValueError("Invalid Nuclei JSONL.") from exc
        if not isinstance(obj, dict):
            raise ValueError("Invalid Nuclei finding record.")
        info = obj.get("info", {})
        if not isinstance(info, dict):
            raise ValueError("Invalid Nuclei info.")
        template = obj.get("template-id", "")
        severity = info.get("severity", "unknown")
        matched = obj.get("matched-at", "")
        matcher = obj.get("matcher-name", "")
        if not all(isinstance(x, str) for x in (template, severity, matched, matcher)):
            raise ValueError("Invalid Nuclei metadata.")
        parsed = urlsplit(matched)
        if parsed.scheme in ("http", "https") and parsed.hostname:
            origin = parsed.scheme + "://" + parsed.netloc
        else:
            # Nuclei also supports non-URL targets. Do not retain arbitrary
            # raw targets or secret-bearing matched-at strings.
            origin = "non-http-target"
        findings.append(NucleiFinding(
            template_id=template[:256],
            severity=severity[:64].lower(),
            matched_origin=origin,
            matcher_name=matcher[:128],
        ))
    return NucleiEvidence("nuclei-jsonl-unverified", tuple(findings))


def import_nuclei_jsonl_file(path: str | Path) -> NucleiEvidence:
    with Path(path).open("rb") as stream:
        return parse_nuclei_jsonl(stream.read(MAX_BYTES + 1))
