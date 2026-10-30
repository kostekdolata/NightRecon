"""Declarative bounded service probes for Red Night.

Probe packs are data, not executable scripts: fixed TCP payload bytes plus
bounded regular-expression matches. No Python, shell, template, or callback
execution is permitted.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import json
import re
import socket


MAX_PROBES_PER_PACK = 128
MAX_PROBE_BYTES = 1024
MAX_RESPONSE_BYTES = 8192
MAX_REGEX_CHARS = 512


@dataclass(frozen=True)
class DeclarativeServiceProbe:
    probe_id: str
    ports: tuple[int, ...]
    payload: bytes
    response_regex: str
    protocol: str
    product: str = ""
    confidence: str = "medium"

    def __post_init__(self) -> None:
        if not self.probe_id or self.probe_id != self.probe_id.strip():
            raise ValueError("probe_id must be a nonblank trimmed string")
        if not self.ports:
            raise ValueError("ports must not be empty")
        if len(set(self.ports)) != len(self.ports):
            raise ValueError("ports must not contain duplicates")
        if any(
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
            for port in self.ports
        ):
            raise ValueError("ports must be between 1 and 65535")
        if len(self.payload) > MAX_PROBE_BYTES:
            raise ValueError("probe payload exceeds maximum size")
        if not self.response_regex or len(self.response_regex) > MAX_REGEX_CHARS:
            raise ValueError("response_regex is invalid or too large")
        re.compile(self.response_regex)
        if self.confidence not in {"low", "medium", "high"}:
            raise ValueError("confidence must be low, medium, or high")


@dataclass(frozen=True)
class DeclarativeProbeMatch:
    probe_id: str
    protocol: str
    product: str
    confidence: str
    evidence: str


def load_probe_pack_json(text: str) -> tuple[DeclarativeServiceProbe, ...]:
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("probe pack must be a JSON object")
    entries = payload.get("probes")
    if not isinstance(entries, list) or not entries:
        raise ValueError("probe pack must contain a non-empty probes array")
    if len(entries) > MAX_PROBES_PER_PACK:
        raise ValueError("probe pack exceeds maximum probe count")

    probes = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("each probe must be a JSON object")
        probe_id = str(entry.get("id", ""))
        if probe_id in seen:
            raise ValueError("probe ids must be unique")
        seen.add(probe_id)

        encoded = entry.get("payload_base64", "")
        if not isinstance(encoded, str):
            raise ValueError("payload_base64 must be a string")
        try:
            raw = base64.b64decode(encoded, validate=True) if encoded else b""
        except Exception as exc:
            raise ValueError("payload_base64 is invalid") from exc

        probes.append(DeclarativeServiceProbe(
            probe_id=probe_id,
            ports=tuple(entry.get("ports", ())),
            payload=raw,
            response_regex=str(entry.get("response_regex", "")),
            protocol=str(entry.get("protocol", "unknown")).strip().lower(),
            product=str(entry.get("product", "")).strip(),
            confidence=str(entry.get("confidence", "medium")).strip().lower(),
        ))
    return tuple(probes)


def match_probe_response(
    probe: DeclarativeServiceProbe,
    response: bytes,
) -> DeclarativeProbeMatch | None:
    text = response[:MAX_RESPONSE_BYTES].decode("latin-1", "replace")
    match = re.search(probe.response_regex, text, flags=re.IGNORECASE)
    if match is None:
        return None
    evidence = match.group(0)[:256]
    return DeclarativeProbeMatch(
        probe_id=probe.probe_id,
        protocol=probe.protocol,
        product=probe.product,
        confidence=probe.confidence,
        evidence=evidence,
    )


def run_declarative_probe(
    *,
    address: str,
    port: int,
    timeout: float,
    probe: DeclarativeServiceProbe,
) -> DeclarativeProbeMatch | None:
    if port not in probe.ports:
        raise ValueError("probe is not declared for this port")
    if timeout <= 0 or timeout > 10:
        raise ValueError("timeout must be between 0 and 10 seconds")

    with socket.create_connection((address, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if probe.payload:
            sock.sendall(probe.payload)
        response = sock.recv(MAX_RESPONSE_BYTES)
    return match_probe_response(probe, response)
