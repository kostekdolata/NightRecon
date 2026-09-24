"""Feed-to-store lifecycle management for NightRecon check packs."""

from __future__ import annotations

from nightrecon.check_feed import (
    fetch_check_pack_artifact,
    fetch_signed_check_feed,
)
from nightrecon.check_pack_store import (
    CheckPackStore,
    InstalledCheckPackRecord,
)


def install_pack_from_feed(
    *,
    feed_url: str,
    pack_id: str,
    feed_trusted_keys: dict[str, bytes],
    pack_trusted_keys: dict[str, bytes],
    store: CheckPackStore,
    timeout: float = 10.0,
) -> InstalledCheckPackRecord:
    """Verify a named feed pack and install its signed envelope locally."""

    feed = fetch_signed_check_feed(
        feed_url,
        trusted_keys=feed_trusted_keys,
        timeout=timeout,
    )

    entry = next(
        (
            candidate
            for candidate in feed.packs
            if candidate.pack_id == pack_id
        ),
        None,
    )

    if entry is None:
        raise ValueError(
            f"Check pack '{pack_id}' is not advertised by feed "
            f"'{feed.feed_id}'."
        )

    artifact = fetch_check_pack_artifact(
        entry,
        trusted_pack_keys=pack_trusted_keys,
        timeout=timeout,
    )

    record = store.install_signed_pack(
        artifact.signed_text,
        trusted_keys=pack_trusted_keys,
    )

    if (
        record.pack_id != entry.pack_id
        or record.version != entry.version
    ):
        raise ValueError(
            "Installed check-pack metadata does not match feed entry."
        )

    return record
