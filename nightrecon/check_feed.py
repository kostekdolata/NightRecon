"""Signed declarative check-feed support for NightRecon."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from nightrecon.check_pack_signing import (
    canonicalize_pack_payload,
    load_signed_check_pack,
)
from nightrecon.check_packs import CheckPack


CHECK_FEED_SCHEMA_VERSION = 1
SIGNED_CHECK_FEED_FORMAT = (
    "nightrecon-signed-check-feed-v1"
)
MAX_FEED_BYTES = 2_000_000
MAX_PACK_BYTES = 4_000_000
_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class CheckFeedPackEntry:
    """One signed check-pack advertised by a verified feed."""

    pack_id: str
    version: str
    url: str
    sha256: str
    signer_key_id: str


@dataclass(frozen=True)
class CheckPackFeed:
    """Verified check-feed manifest."""

    schema_version: int
    feed_id: str
    generated_at: str
    packs: tuple[CheckFeedPackEntry, ...] = ()


def load_signed_check_feed(
    text: str,
    *,
    trusted_keys: dict[str, bytes],
) -> CheckPackFeed:
    """Verify a signed feed envelope and return its validated manifest."""

    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid signed check-feed JSON: {exc.msg}"
        ) from exc

    if not isinstance(document, dict):
        raise ValueError(
            "Signed check feed must be a JSON object."
        )

    if document.get("format") != SIGNED_CHECK_FEED_FORMAT:
        raise ValueError(
            "Unsupported signed check-feed format."
        )

    key_id = document.get("key_id")

    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError(
            "Signed check feed requires key_id."
        )

    public_key_bytes = trusted_keys.get(key_id)

    if public_key_bytes is None:
        raise ValueError(
            f"Untrusted check-feed signer: {key_id}"
        )

    payload = document.get("payload")

    if not isinstance(payload, dict):
        raise ValueError(
            "Signed check feed requires object payload."
        )

    signature_text = document.get("signature")

    if not isinstance(signature_text, str):
        raise ValueError(
            "Invalid check-feed signature encoding."
        )

    try:
        signature = base64.b64decode(
            signature_text,
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise ValueError(
            "Invalid check-feed signature encoding."
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
            "Invalid check-feed signature."
        ) from exc

    return _load_feed_payload(payload)


def fetch_signed_check_feed(
    url: str,
    *,
    trusted_keys: dict[str, bytes],
    timeout: float = 10.0,
) -> CheckPackFeed:
    """Fetch and verify one HTTPS signed check-feed manifest."""

    _require_https_url(
        url,
        label="check-feed",
    )
    data = _download_bounded(
        url,
        timeout=timeout,
        max_bytes=MAX_FEED_BYTES,
        label="check-feed",
    )

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "Check-feed response is not valid UTF-8."
        ) from exc

    return load_signed_check_feed(
        text,
        trusted_keys=trusted_keys,
    )


def fetch_signed_check_pack_text(
    entry: CheckFeedPackEntry,
    *,
    trusted_pack_keys: dict[str, bytes],
    timeout: float = 10.0,
) -> str:
    """Fetch, verify, and return one signed check-pack envelope."""

    if entry.signer_key_id not in trusted_pack_keys:
        raise ValueError(
            "Untrusted check-pack signer: "
            f"{entry.signer_key_id}"
        )

    _require_https_url(
        entry.url,
        label="check-pack",
    )

    data = _download_bounded(
        entry.url,
        timeout=timeout,
        max_bytes=MAX_PACK_BYTES,
        label="check-pack",
    )

    observed_sha256 = hashlib.sha256(
        data
    ).hexdigest()

    if not hmac.compare_digest(
        observed_sha256,
        entry.sha256,
    ):
        raise ValueError(
            "Downloaded check-pack SHA-256 does not match feed."
        )

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "Check-pack response is not valid UTF-8."
        ) from exc

    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid signed check-pack JSON: {exc.msg}"
        ) from exc

    if (
        not isinstance(document, dict)
        or document.get("key_id")
        != entry.signer_key_id
    ):
        raise ValueError(
            "Check-pack signer does not match feed entry."
        )

    pack = load_signed_check_pack(
        text,
        trusted_keys=trusted_pack_keys,
    )

    if pack.pack_id != entry.pack_id:
        raise ValueError(
            "Check-pack ID does not match feed entry."
        )

    if pack.version != entry.version:
        raise ValueError(
            "Check-pack version does not match feed entry."
        )

    return text


def fetch_check_pack(
    entry: CheckFeedPackEntry,
    *,
    trusted_pack_keys: dict[str, bytes],
    timeout: float = 10.0,
) -> CheckPack:
    """Fetch and verify one signed check pack advertised by a feed."""

    text = fetch_signed_check_pack_text(
        entry,
        trusted_pack_keys=trusted_pack_keys,
        timeout=timeout,
    )

    return load_signed_check_pack(
        text,
        trusted_keys=trusted_pack_keys,
    )


def _load_feed_payload(
    payload: dict[str, object],
) -> CheckPackFeed:
    schema_version = payload.get(
        "schema_version"
    )

    if schema_version != CHECK_FEED_SCHEMA_VERSION:
        raise ValueError(
            "Unsupported check-feed schema version: "
            f"{schema_version!r}"
        )

    feed_id = _required_text(
        payload,
        "feed_id",
    )
    generated_at = _optional_text(
        payload.get("generated_at")
    )

    raw_packs = payload.get("packs", [])

    if not isinstance(raw_packs, list):
        raise ValueError(
            "Check-feed packs must be a list."
        )

    packs = tuple(
        _parse_feed_entry(item)
        for item in raw_packs
    )

    pack_ids = [
        entry.pack_id
        for entry in packs
    ]

    if len(pack_ids) != len(set(pack_ids)):
        raise ValueError(
            "Duplicate pack_id in check feed."
        )

    return CheckPackFeed(
        schema_version=schema_version,
        feed_id=feed_id,
        generated_at=generated_at,
        packs=packs,
    )


def _parse_feed_entry(
    item: object,
) -> CheckFeedPackEntry:
    if not isinstance(item, dict):
        raise ValueError(
            "Each check-feed pack must be an object."
        )

    pack_id = _required_text(
        item,
        "pack_id",
    )
    version = _required_text(
        item,
        "version",
    )
    url = _required_text(
        item,
        "url",
    )
    sha256 = _required_text(
        item,
        "sha256",
    )
    signer_key_id = _required_text(
        item,
        "signer_key_id",
    )

    _require_https_url(
        url,
        label="check-pack",
    )

    if _SHA256_PATTERN.fullmatch(
        sha256
    ) is None:
        raise ValueError(
            "Check-feed pack SHA-256 must be 64 hexadecimal characters."
        )

    return CheckFeedPackEntry(
        pack_id=pack_id,
        version=version,
        url=url,
        sha256=sha256.lower(),
        signer_key_id=signer_key_id,
    )


def _download_bounded(
    url: str,
    *,
    timeout: float,
    max_bytes: int,
    label: str,
) -> bytes:
    if timeout <= 0:
        raise ValueError(
            "timeout must be greater than 0."
        )

    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "NightRecon",
        },
    )

    with urlopen(
        request,
        timeout=timeout,
    ) as response:
        data = response.read(
            max_bytes + 1
        )

    if len(data) > max_bytes:
        raise ValueError(
            f"{label} download exceeds size limit."
        )

    return data


def _require_https_url(
    url: str,
    *,
    label: str,
) -> None:
    parsed = urlparse(url)

    if (
        parsed.scheme.lower() != "https"
        or not parsed.netloc
    ):
        raise ValueError(
            f"{label} URL must use HTTPS."
        )


def _required_text(
    payload: dict[str, object],
    key: str,
) -> str:
    value = payload.get(key)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"{key} must be a non-empty string."
        )

    return value.strip()


def _optional_text(
    value: object,
) -> str:
    if isinstance(value, str):
        return value.strip()

    return ""
