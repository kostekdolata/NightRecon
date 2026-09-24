"""Signature verification for NightRecon declarative check packs."""

from __future__ import annotations

import base64
import binascii
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from nightrecon.check_packs import (
    CheckPack,
    load_check_pack_payload,
)


SIGNED_CHECK_PACK_FORMAT = (
    "nightrecon-signed-check-pack-v1"
)


def canonicalize_pack_payload(
    payload: object,
) -> bytes:
    """Return stable UTF-8 JSON bytes used for signing."""

    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Check-pack payload is not canonicalizable."
        ) from exc

    return encoded.encode("utf-8")


def load_signed_check_pack(
    text: str,
    *,
    trusted_keys: dict[str, bytes],
) -> CheckPack:
    """Verify a signed envelope before loading its declarative pack."""

    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid signed check-pack JSON: {exc.msg}"
        ) from exc

    if not isinstance(document, dict):
        raise ValueError(
            "Signed check pack must be a JSON object."
        )

    if document.get("format") != SIGNED_CHECK_PACK_FORMAT:
        raise ValueError(
            "Unsupported signed check-pack format."
        )

    key_id = document.get("key_id")

    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError(
            "Signed check pack requires key_id."
        )

    public_key_bytes = trusted_keys.get(
        key_id,
    )

    if public_key_bytes is None:
        raise ValueError(
            f"Untrusted check-pack signer: {key_id}"
        )

    payload = document.get("payload")

    if not isinstance(payload, dict):
        raise ValueError(
            "Signed check pack requires object payload."
        )

    signature_text = document.get("signature")

    if not isinstance(signature_text, str):
        raise ValueError(
            "Invalid check-pack signature encoding."
        )

    try:
        signature = base64.b64decode(
            signature_text,
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise ValueError(
            "Invalid check-pack signature encoding."
        ) from exc

    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )
        public_key.verify(
            signature,
            canonicalize_pack_payload(
                payload
            ),
        )
    except (ValueError, InvalidSignature) as exc:
        raise ValueError(
            "Invalid check-pack signature."
        ) from exc

    return load_check_pack_payload(
        payload
    )
