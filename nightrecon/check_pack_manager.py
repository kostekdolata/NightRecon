"""Feed-to-store lifecycle management for NightRecon check packs."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon.check_feed import (
    CheckPackFeed,
    fetch_check_pack_artifact,
    fetch_signed_check_feed,
)
from nightrecon.check_pack_store import (
    CheckPackStore,
    InstalledCheckPackRecord,
)


@dataclass(frozen=True)
class CheckPackSyncResult:
    """Outcome for one feed-advertised pack during synchronization."""

    pack_id: str
    advertised_version: str
    previous_version: str | None
    active_version: str | None
    status: str
    error: str = ""


def sync_check_feed(
    *,
    feed_url: str,
    feed_trusted_keys: dict[str, bytes],
    pack_trusted_keys: dict[str, bytes],
    store: CheckPackStore,
    timeout: float = 10.0,
) -> tuple[CheckPackSyncResult, ...]:
    """Fetch, verify, and synchronize all packs in one signed feed."""

    feed = fetch_signed_check_feed(
        feed_url,
        trusted_keys=feed_trusted_keys,
        timeout=timeout,
    )
    store.accept_feed(
        feed,
        source_url=feed_url,
    )

    return sync_verified_check_feed(
        feed=feed,
        pack_trusted_keys=pack_trusted_keys,
        store=store,
        timeout=timeout,
    )


def sync_verified_check_feed(
    *,
    feed: CheckPackFeed,
    pack_trusted_keys: dict[str, bytes],
    store: CheckPackStore,
    timeout: float = 10.0,
) -> tuple[CheckPackSyncResult, ...]:
    """Synchronize all packs from an already verified feed manifest."""

    results: list[CheckPackSyncResult] = []

    for entry in feed.packs:
        previous = store.active_version(
            entry.pack_id
        )

        if previous == entry.version:
            record = _find_installed_record(
                store,
                entry.pack_id,
                entry.version,
            )

            if record is None:
                results.append(
                    CheckPackSyncResult(
                        pack_id=entry.pack_id,
                        advertised_version=entry.version,
                        previous_version=previous,
                        active_version=previous,
                        status="failed",
                        error=(
                            "Active immutable check-pack metadata "
                            "is missing."
                        ),
                    )
                )
                continue

            if record.sha256 != entry.sha256:
                results.append(
                    CheckPackSyncResult(
                        pack_id=entry.pack_id,
                        advertised_version=entry.version,
                        previous_version=previous,
                        active_version=previous,
                        status="failed",
                        error=(
                            "Feed attempts to mutate an immutable "
                            "installed check-pack version."
                        ),
                    )
                )
                continue

            results.append(
                CheckPackSyncResult(
                    pack_id=entry.pack_id,
                    advertised_version=entry.version,
                    previous_version=previous,
                    active_version=previous,
                    status="unchanged",
                )
            )
            continue

        try:
            record = install_pack_from_verified_feed(
                feed=feed,
                pack_id=entry.pack_id,
                pack_trusted_keys=pack_trusted_keys,
                store=store,
                timeout=timeout,
            )
        except Exception as exc:
            results.append(
                CheckPackSyncResult(
                    pack_id=entry.pack_id,
                    advertised_version=entry.version,
                    previous_version=previous,
                    active_version=previous,
                    status="failed",
                    error=(
                        str(exc)
                        or exc.__class__.__name__
                    ),
                )
            )
            continue

        results.append(
            CheckPackSyncResult(
                pack_id=entry.pack_id,
                advertised_version=entry.version,
                previous_version=previous,
                active_version=record.version,
                status=(
                    "installed"
                    if previous is None
                    else "updated"
                ),
            )
        )

    return tuple(results)


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
    store.accept_feed(
        feed,
        source_url=feed_url,
    )

    return install_pack_from_verified_feed(
        feed=feed,
        pack_id=pack_id,
        pack_trusted_keys=pack_trusted_keys,
        store=store,
        timeout=timeout,
    )


def install_pack_from_verified_feed(
    *,
    feed: CheckPackFeed,
    pack_id: str,
    pack_trusted_keys: dict[str, bytes],
    store: CheckPackStore,
    timeout: float = 10.0,
) -> InstalledCheckPackRecord:
    """Install one named pack from an already verified feed manifest."""

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
        or record.sha256 != artifact.sha256
    ):
        raise ValueError(
            "Installed check-pack metadata does not match feed entry."
        )

    return record


def _find_installed_record(
    store: CheckPackStore,
    pack_id: str,
    version: str,
) -> InstalledCheckPackRecord | None:
    for record in store.list_versions(
        pack_id
    ):
        if record.version == version:
            return record

    return None
