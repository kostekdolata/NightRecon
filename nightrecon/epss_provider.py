"""FIRST EPSS provider for NightRecon threat context."""

from __future__ import annotations

import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from nightrecon.threat_context import EpssRecord


FIRST_EPSS_API_URL = (
    "https://api.first.org/data/v1/epss"
)
MAX_CVE_PARAMETER_LENGTH = 2000


class FirstEpssProvider:
    """Query current FIRST EPSS data for requested CVE identifiers."""

    name = "first-epss"

    def __init__(self, timeout: float = 10.0) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than 0.")

        self.timeout = timeout

    def lookup(
        self,
        vulnerability_ids: tuple[str, ...],
    ) -> dict[str, EpssRecord]:
        """Return current EPSS records keyed by CVE ID."""

        vulnerability_ids = _unique_ids(
            vulnerability_ids
        )

        if not vulnerability_ids:
            return {}

        result: dict[str, EpssRecord] = {}

        for batch in _batch_cve_ids(
            vulnerability_ids
        ):
            params = urlencode(
                {
                    "cve": ",".join(batch),
                }
            )
            request = Request(
                f"{FIRST_EPSS_API_URL}?{params}",
                headers={
                    "Accept": "application/json",
                    "User-Agent": "NightRecon",
                },
            )

            with urlopen(
                request,
                timeout=self.timeout,
            ) as response:
                payload = json.load(response)

            if not isinstance(payload, dict):
                raise ValueError(
                    "FIRST EPSS response must be a JSON object."
                )

            data = payload.get("data", [])

            if not isinstance(data, list):
                raise ValueError(
                    "FIRST EPSS data must be a list."
                )

            for item in data:
                record = _parse_record(item)

                if record is not None:
                    result[record.vulnerability_id] = (
                        record
                    )

        return result


def _parse_record(
    item: object,
) -> EpssRecord | None:
    if not isinstance(item, dict):
        return None

    vulnerability_id = item.get("cve")

    if (
        not isinstance(vulnerability_id, str)
        or not vulnerability_id.strip()
    ):
        return None

    probability = _as_float(
        item.get("epss")
    )
    percentile = _as_float(
        item.get("percentile")
    )

    if probability is None or percentile is None:
        return None

    date = item.get("date")

    if not isinstance(date, str):
        date = item.get("created")

    if not isinstance(date, str):
        date = ""

    try:
        return EpssRecord(
            vulnerability_id=vulnerability_id.strip(),
            probability=probability,
            percentile=percentile,
            date=date.strip(),
        )
    except ValueError:
        return None


def _unique_ids(
    vulnerability_ids: tuple[str, ...],
) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []

    for vulnerability_id in vulnerability_ids:
        normalized = vulnerability_id.strip()

        if normalized and normalized not in seen:
            result.append(normalized)
            seen.add(normalized)

    return tuple(result)


def _batch_cve_ids(
    vulnerability_ids: tuple[str, ...],
) -> tuple[tuple[str, ...], ...]:
    batches: list[tuple[str, ...]] = []
    current: list[str] = []
    current_length = 0

    for vulnerability_id in vulnerability_ids:
        additional = len(vulnerability_id)

        if current:
            additional += 1

        if (
            current
            and current_length + additional
            > MAX_CVE_PARAMETER_LENGTH
        ):
            batches.append(tuple(current))
            current = [vulnerability_id]
            current_length = len(vulnerability_id)
            continue

        current.append(vulnerability_id)
        current_length += additional

    if current:
        batches.append(tuple(current))

    return tuple(batches)


def _as_float(
    value: object,
) -> float | None:
    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        return float(value)

    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None

    return None
