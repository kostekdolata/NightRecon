"""Evidence-backed coarse device-role fingerprinting."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.service_detection import ServiceDetectionResult


@dataclass(frozen=True)
class DeviceFingerprint:
    role: str
    confidence: str
    evidence: tuple[str, ...]


def fingerprint_device_role(
    services: tuple[ServiceDetectionResult, ...],
) -> DeviceFingerprint | None:
    names = {
        item.service.lower()
        for item in services
        if item.error_code == 0 and item.service
    }
    evidence = tuple(sorted(names))

    if {"msrpc", "netbios-ssn", "smb"} & names:
        strength = len({"msrpc", "netbios-ssn", "smb", "rdp"} & names)
        return DeviceFingerprint(
            role="windows-host",
            confidence="high" if strength >= 2 else "medium",
            evidence=evidence,
        )

    if "snmp" in names and ({"telnet", "ssh"} & names):
        return DeviceFingerprint(
            role="network-device",
            confidence="medium",
            evidence=evidence,
        )

    if "jetdirect" in names or any(item.port == 9100 for item in services):
        return DeviceFingerprint(
            role="printer",
            confidence="medium",
            evidence=evidence,
        )

    if {"http", "https", "http-alt"} & names:
        return DeviceFingerprint(
            role="web-appliance-or-server",
            confidence="low",
            evidence=evidence,
        )

    return None
