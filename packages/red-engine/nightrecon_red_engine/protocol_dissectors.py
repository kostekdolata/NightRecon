"""Protocol metadata dissectors for Red Night packet intelligence.

The dissectors intentionally return metadata and fingerprints rather than
credential values or arbitrary application payloads.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import struct


@dataclass(frozen=True)
class ProtocolMetadata:
    protocol: str
    fields: tuple[tuple[str, str], ...]
    confidence: str = "high"

    def get(self, name: str, default: str = "") -> str:
        for key, value in self.fields:
            if key == name:
                return value
        return default


def _field_pairs(values: dict[str, object]) -> tuple[tuple[str, str], ...]:
    return tuple(
        (str(key), str(value))
        for key, value in sorted(values.items())
        if value not in {"", None}
    )


def dissect_http(payload: bytes) -> ProtocolMetadata | None:
    if not payload:
        return None
    first_line = payload.split(b"\r\n", 1)[0][:2048]
    text = first_line.decode("latin-1", "replace")
    parts = text.split()
    methods = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT"}
    if parts and parts[0].upper() in methods:
        path = parts[1] if len(parts) > 1 else "/"
        return ProtocolMetadata(
            protocol="http",
            fields=_field_pairs({
                "message_type": "request",
                "method": parts[0].upper(),
                "path": path.split("?", 1)[0][:512],
                "version": parts[2] if len(parts) > 2 else "",
            }),
        )
    if text.startswith("HTTP/") and len(parts) >= 2:
        return ProtocolMetadata(
            protocol="http",
            fields=_field_pairs({
                "message_type": "response",
                "version": parts[0],
                "status": parts[1],
            }),
        )
    return None


def dissect_ssh(payload: bytes) -> ProtocolMetadata | None:
    if not payload.startswith(b"SSH-"):
        return None
    banner = payload.splitlines()[0][:255].decode("ascii", "replace")
    parts = banner.split("-", 2)
    return ProtocolMetadata(
        protocol="ssh",
        fields=_field_pairs({
            "banner_sha256": sha256(banner.encode()).hexdigest(),
            "protocol_version": parts[1] if len(parts) > 1 else "",
            "software": parts[2] if len(parts) > 2 else "",
        }),
    )


def dissect_smb(payload: bytes) -> ProtocolMetadata | None:
    if payload.startswith(b"\xfeSMB") and len(payload) >= 16:
        command = int.from_bytes(payload[12:14], "little")
        return ProtocolMetadata(
            protocol="smb2",
            fields=_field_pairs({
                "dialect_family": "SMB2/3",
                "command": command,
            }),
        )
    if payload.startswith(b"\xffSMB") and len(payload) >= 5:
        return ProtocolMetadata(
            protocol="smb1",
            fields=_field_pairs({
                "dialect_family": "SMB1",
                "command": payload[4],
            }),
        )
    return None


def dissect_tls_client_hello(payload: bytes) -> ProtocolMetadata | None:
    """Parse TLS record/ClientHello metadata and SNI without decrypting traffic."""
    if len(payload) < 9 or payload[0] != 0x16:
        return None
    record_version = f"{payload[1]}.{payload[2]}"
    record_length = int.from_bytes(payload[3:5], "big")
    if record_length + 5 > len(payload):
        return ProtocolMetadata(
            protocol="tls",
            fields=_field_pairs({
                "record_type": "handshake",
                "record_version": record_version,
                "truncated": "true",
            }),
            confidence="medium",
        )
    if payload[5] != 0x01:
        return ProtocolMetadata(
            protocol="tls",
            fields=_field_pairs({
                "record_type": "handshake",
                "record_version": record_version,
                "handshake_type": payload[5],
            }),
            confidence="medium",
        )

    body = memoryview(payload)[9:5 + record_length]
    if len(body) < 34:
        return None
    pos = 34
    if pos >= len(body):
        return None
    session_len = body[pos]
    pos += 1 + session_len
    if pos + 2 > len(body):
        return None
    cipher_len = int.from_bytes(body[pos:pos+2], "big")
    pos += 2 + cipher_len
    if pos >= len(body):
        return None
    compression_len = body[pos]
    pos += 1 + compression_len
    if pos + 2 > len(body):
        return ProtocolMetadata(
            protocol="tls",
            fields=_field_pairs({
                "record_version": record_version,
                "handshake": "client-hello",
            }),
        )
    extensions_len = int.from_bytes(body[pos:pos+2], "big")
    pos += 2
    end = min(len(body), pos + extensions_len)
    sni = ""
    alpn: list[str] = []
    supported_versions: list[str] = []

    while pos + 4 <= end:
        ext_type = int.from_bytes(body[pos:pos+2], "big")
        ext_len = int.from_bytes(body[pos+2:pos+4], "big")
        ext = body[pos+4:pos+4+ext_len]
        pos += 4 + ext_len
        if len(ext) != ext_len:
            break

        if ext_type == 0 and len(ext) >= 5:
            list_len = int.from_bytes(ext[0:2], "big")
            cursor = 2
            list_end = min(len(ext), 2 + list_len)
            while cursor + 3 <= list_end:
                name_type = ext[cursor]
                name_len = int.from_bytes(ext[cursor+1:cursor+3], "big")
                name = bytes(ext[cursor+3:cursor+3+name_len])
                cursor += 3 + name_len
                if name_type == 0 and name:
                    sni = name.decode("idna", "replace")[:253]
                    break
        elif ext_type == 16 and len(ext) >= 3:
            list_len = int.from_bytes(ext[0:2], "big")
            cursor = 2
            list_end = min(len(ext), 2 + list_len)
            while cursor < list_end:
                size = ext[cursor]
                cursor += 1
                value = bytes(ext[cursor:cursor+size])
                cursor += size
                if value:
                    alpn.append(value.decode("ascii", "replace")[:64])
        elif ext_type == 43 and len(ext) >= 3:
            size = ext[0]
            for cursor in range(1, min(len(ext), 1 + size), 2):
                if cursor + 1 < len(ext):
                    supported_versions.append(
                        f"0x{int.from_bytes(ext[cursor:cursor+2], 'big'):04x}"
                    )

    return ProtocolMetadata(
        protocol="tls",
        fields=_field_pairs({
            "record_version": record_version,
            "handshake": "client-hello",
            "sni": sni,
            "alpn": ",".join(alpn),
            "supported_versions": ",".join(supported_versions),
        }),
    )


def dissect_dns_payload(payload: bytes) -> ProtocolMetadata | None:
    if len(payload) < 12:
        return None
    flags = int.from_bytes(payload[2:4], "big")
    qdcount = int.from_bytes(payload[4:6], "big")
    ancount = int.from_bytes(payload[6:8], "big")
    return ProtocolMetadata(
        protocol="dns",
        fields=_field_pairs({
            "transaction_id": f"0x{int.from_bytes(payload[0:2], 'big'):04x}",
            "response": bool(flags & 0x8000),
            "rcode": flags & 0xF,
            "questions": qdcount,
            "answers": ancount,
        }),
        confidence="medium",
    )


def dissect_payload(
    payload: bytes,
    *,
    src_port: int | None = None,
    dst_port: int | None = None,
) -> ProtocolMetadata | None:
    for parser in (
        dissect_tls_client_hello,
        dissect_http,
        dissect_ssh,
        dissect_smb,
    ):
        result = parser(payload)
        if result is not None:
            return result
    if 53 in {src_port, dst_port}:
        return dissect_dns_payload(payload)
    return None
