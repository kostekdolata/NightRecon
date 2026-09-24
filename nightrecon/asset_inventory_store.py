"""Persistent JSON storage for NightRecon asset inventory."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path

from nightrecon.asset_inventory import (
    AssetInventory,
    AssetRecord,
    AssetServiceRecord,
)


class AssetInventoryStore:
    """Load and atomically persist the NightRecon asset inventory."""

    def __init__(
        self,
        root: str | Path = "inventory",
    ) -> None:
        self.root = Path(root)
        self.path = self.root / "assets.json"

    def load(self) -> AssetInventory:
        """Load inventory state, returning empty state when none exists."""

        if not self.path.exists():
            return AssetInventory.empty()

        try:
            with self.path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)
        except (
            json.JSONDecodeError,
            OSError,
        ) as exc:
            raise ValueError(
                "Invalid asset inventory JSON."
            ) from exc

        return _parse_inventory(data)

    def save(
        self,
        inventory: AssetInventory,
    ) -> Path:
        """Atomically save inventory state."""

        self.root.mkdir(
            parents=True,
            exist_ok=True,
        )
        temporary = self.root / "assets.json.tmp"

        with temporary.open(
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                asdict(inventory),
                file,
                indent=2,
                sort_keys=True,
            )
            file.write("\n")

        temporary.replace(self.path)
        return self.path


def _parse_inventory(
    data: object,
) -> AssetInventory:
    if not isinstance(data, dict):
        raise ValueError(
            "Invalid asset inventory JSON."
        )

    schema_version = data.get(
        "schema_version",
        1,
    )

    if schema_version != 1:
        raise ValueError(
            "Unsupported asset inventory schema version: "
            f"{schema_version}"
        )

    raw_assets = data.get(
        "assets",
        [],
    )

    if not isinstance(raw_assets, list):
        raise ValueError(
            "Invalid asset inventory JSON."
        )

    assets: list[AssetRecord] = []

    for raw_asset in raw_assets:
        assets.append(
            _parse_asset(raw_asset)
        )

    updated_at = data.get(
        "updated_at",
        "",
    )

    if not isinstance(updated_at, str):
        raise ValueError(
            "Invalid asset inventory JSON."
        )

    return AssetInventory(
        assets=tuple(assets),
        schema_version=1,
        updated_at=updated_at,
    )


def _parse_asset(
    data: object,
) -> AssetRecord:
    if not isinstance(data, dict):
        raise ValueError(
            "Invalid asset inventory JSON."
        )

    services = data.get(
        "services",
        [],
    )

    if not isinstance(services, list):
        raise ValueError(
            "Invalid asset inventory JSON."
        )

    try:
        return AssetRecord(
            address=_required_text(
                data,
                "address",
            ),
            first_seen=_required_text(
                data,
                "first_seen",
            ),
            last_seen=_required_text(
                data,
                "last_seen",
            ),
            last_checked_at=_required_text(
                data,
                "last_checked_at",
            ),
            hostnames=_string_tuple(
                data.get(
                    "hostnames",
                    [],
                )
            ),
            last_discovery_responsive=(
                _optional_bool(
                    data.get(
                        "last_discovery_responsive"
                    )
                )
            ),
            discovery_methods=_string_tuple(
                data.get(
                    "discovery_methods",
                    [],
                )
            ),
            services=tuple(
                _parse_service(
                    service
                )
                for service in services
            ),
            source_session_ids=_string_tuple(
                data.get(
                    "source_session_ids",
                    [],
                )
            ),
        )
    except (
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise ValueError(
            "Invalid asset inventory JSON."
        ) from exc


def _parse_service(
    data: object,
) -> AssetServiceRecord:
    if not isinstance(data, dict):
        raise ValueError(
            "Invalid asset inventory JSON."
        )

    port = data.get("port")

    if (
        isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
    ):
        raise ValueError(
            "Invalid asset inventory JSON."
        )

    return AssetServiceRecord(
        port=port,
        service=_required_text(
            data,
            "service",
        ),
        product=_optional_text(
            data.get("product")
        ),
        version=_optional_text(
            data.get("version")
        ),
        tls_certificate_sha256=_optional_text(
            data.get(
                "tls_certificate_sha256"
            )
        ),
    )


def _required_text(
    data: dict,
    key: str,
) -> str:
    value = data[key]

    if (
        not isinstance(value, str)
        or not value.strip()
    ):
        raise ValueError(
            "Invalid asset inventory JSON."
        )

    return value


def _optional_text(
    value: object,
) -> str:
    if value is None:
        return ""

    if not isinstance(value, str):
        raise ValueError(
            "Invalid asset inventory JSON."
        )

    return value


def _string_tuple(
    value: object,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(
            "Invalid asset inventory JSON."
        )

    if not all(
        isinstance(item, str)
        for item in value
    ):
        raise ValueError(
            "Invalid asset inventory JSON."
        )

    return tuple(value)


def _optional_bool(
    value: object,
) -> bool | None:
    if value is None:
        return None

    if not isinstance(value, bool):
        raise ValueError(
            "Invalid asset inventory JSON."
        )

    return value
