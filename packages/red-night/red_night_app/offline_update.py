"""Signed offline Red Night release bundle verification."""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from red_night_app.release_integrity import (
    RedReleaseManifest,
    verify_red_release_manifest,
)

SIGNED_UPDATE_FORMAT = "nightrecon-red-signed-offline-update-v1"


def canonicalize_update_payload(payload: object) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("offline update payload is not canonicalizable") from exc
    return encoded.encode("utf-8")


def verify_signed_offline_update(
    text: str,
    *,
    trusted_keys: Mapping[str, bytes],
    release_root: Path,
) -> RedReleaseManifest:
    """Verify signer, schema, and every artifact before an offline update."""

    try:
        document = json.loads(text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("signed offline update is not valid JSON") from exc

    if not isinstance(document, dict) or set(document) != {
        "format", "key_id", "payload", "signature"
    }:
        raise ValueError("signed offline update schema is not supported")
    if document["format"] != SIGNED_UPDATE_FORMAT:
        raise ValueError("unsupported signed offline update format")

    key_id = document["key_id"]
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("signed offline update requires key_id")
    key_bytes = trusted_keys.get(key_id)
    if key_bytes is None:
        raise ValueError(f"untrusted offline update signer: {key_id}")
    if not isinstance(key_bytes, bytes) or len(key_bytes) != 32:
        raise ValueError(f"invalid trusted Ed25519 key: {key_id}")

    payload = document["payload"]
    if not isinstance(payload, dict):
        raise ValueError("signed offline update payload must be an object")

    signature_text = document["signature"]
    if not isinstance(signature_text, str):
        raise ValueError("invalid offline update signature encoding")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid offline update signature encoding") from exc

    try:
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(
            signature,
            canonicalize_update_payload(payload),
        )
    except (ValueError, InvalidSignature) as exc:
        raise ValueError("invalid offline update signature") from exc

    manifest = RedReleaseManifest.from_dict(payload)
    verify_red_release_manifest(manifest, release_root=release_root)
    return manifest
