"""Secret-minimized credential exposure detection.

The detector reports the type/location of suspected exposure and a one-way
fingerprint; it never returns the discovered secret value.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re


MAX_SCAN_TEXT = 2_000_000


@dataclass(frozen=True)
class CredentialExposureFinding:
    kind: str
    location: str
    confidence: str
    fingerprint: str
    summary: str


_PATTERNS = (
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "high",
    ),
    (
        "bearer-token",
        re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+([^\s]+)"),
        "high",
    ),
    (
        "api-key-assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\b"
            r"\s*[:=]\s*['\"]?([^\s'\",;]+)"
        ),
        "medium",
    ),
    (
        "password-assignment",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd)\b"
            r"\s*[:=]\s*['\"]?([^\s'\",;]+)"
        ),
        "medium",
    ),
)


def detect_credential_exposure(
    text: str,
    *,
    location: str,
) -> tuple[CredentialExposureFinding, ...]:
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if len(text) > MAX_SCAN_TEXT:
        raise ValueError("text exceeds credential exposure scan limit")
    if not location.strip():
        raise ValueError("location must not be empty")

    results = []
    seen: set[tuple[str, str]] = set()

    for kind, pattern, confidence in _PATTERNS:
        for match in pattern.finditer(text):
            captured = (
                match.group(1)
                if match.lastindex
                else match.group(0)
            )
            digest = sha256(captured.encode("utf-8", "replace")).hexdigest()[:20]
            key = (kind, digest)
            if key in seen:
                continue
            seen.add(key)
            results.append(CredentialExposureFinding(
                kind=kind,
                location=location.strip(),
                confidence=confidence,
                fingerprint=digest,
                summary=f"Potential {kind} exposure detected; secret value suppressed.",
            ))

    return tuple(results)
