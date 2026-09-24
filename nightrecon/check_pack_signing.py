"""Signature verification for NightRecon declarative check packs."""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path

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


def parse_trusted_key_specs(
    specs: tuple[str, ...],
) -> dict[str, bytes]:
    """Parse KEY_ID=BASE64_ED25519_PUBLIC_KEY trust specifications."""

    trusted: dict[str, bytes] = {}

    for spec in specs:
        key_id, separator, encoded = spec.partition("=")

        key_id = key_id.strip()
        encoded = encoded.strip()

        if not separator or not key_id or not encoded:
            raise ValueError(
                "Trusted check-pack key must use "
                "KEY_ID=BASE64_PUBLIC_KEY."
            )

        if key_id in trusted:
            raise ValueError(
                f"Duplicate trusted check-pack key: {key_id}"
            )

        try:
            key_bytes = base64.b64decode(
                encoded,
                validate=True,
            )
        except (ValueError, binascii.Error) as exc:
            raise ValueError(
                f"Invalid trusted check-pack key encoding: {key_id}"
            ) from exc

        if len(key_bytes) != 32:
            raise ValueError(
                f"Invalid Ed25519 public key length: {key_id}"
            )

        trusted[key_id] = key_bytes

    return trusted


def load_signed_check_pack_file(
    path: str | Path,
    *,
    trusted_keys: dict[str, bytes],
) -> CheckPack:
    """Read and verify one signed check-pack file."""

    file_path = Path(path)

    try:
        text = file_path.read_text(
            encoding="utf-8"
        )
    except OSError as exc:
        raise ValueError(
            f"Unable to read check-pack file: {file_path}"
        ) from exc

    return load_signed_check_pack(
        text,
        trusted_keys=trusted_keys,
    )


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
