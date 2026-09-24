"""CISA Known Exploited Vulnerabilities provider for NightRecon."""

from __future__ import annotations

import json
from urllib.request import Request, urlopen

from nightrecon.threat_context import KevRecord


CISA_KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


class CisaKevProvider:
    """Query the CISA KEV catalog for requested CVE identifiers."""

    name = "cisa-kev"

    def __init__(self, timeout: float = 10.0) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than 0.")

        self.timeout = timeout

    def lookup(
        self,
        vulnerability_ids: tuple[str, ...],
    ) -> dict[str, KevRecord]:
        """Return requested KEV records keyed by CVE ID."""

        requested = {
            vulnerability_id.strip()
            for vulnerability_id in vulnerability_ids
            if vulnerability_id.strip()
        }

        if not requested:
            return {}

        request = Request(
            CISA_KEV_JSON_URL,
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
                "CISA KEV response must be a JSON object."
            )

        vulnerabilities = payload.get(
            "vulnerabilities",
            [],
        )

        if not isinstance(vulnerabilities, list):
            raise ValueError(
                "CISA KEV vulnerabilities must be a list."
            )

        result: dict[str, KevRecord] = {}

        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue

            vulnerability_id = item.get("cveID")

            if (
                not isinstance(vulnerability_id, str)
                or vulnerability_id not in requested
            ):
                continue

            result[vulnerability_id] = KevRecord(
                vulnerability_id=vulnerability_id,
                date_added=_text(
                    item.get("dateAdded")
                ),
                due_date=_text(
                    item.get("dueDate")
                ),
                known_ransomware_campaign_use=_text(
                    item.get(
                        "knownRansomwareCampaignUse"
                    )
                ),
                required_action=_text(
                    item.get("requiredAction")
                ),
            )

        return result


def _text(value: object) -> str:
    if isinstance(value, str):
        return value.strip()

    return ""
