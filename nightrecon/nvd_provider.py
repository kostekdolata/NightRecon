"""NVD CVE 2.0 vulnerability provider for NightRecon."""

from __future__ import annotations

import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from nightrecon.cpe_identity import cpe_identity_from_software
from nightrecon.software_identity import SoftwareIdentity
from nightrecon.vulnerability_intelligence import VulnerabilityFinding


NVD_CVE_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)


class NvdVulnerabilityProvider:
    """Query NVD CVE 2.0 using deterministic CPE identities."""

    name = "nvd"

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than 0.")

        self.api_key = api_key
        self.timeout = timeout

    def lookup(
        self,
        software_identity: SoftwareIdentity,
    ) -> tuple[VulnerabilityFinding, ...]:
        """Return NVD findings for one supported observed software identity."""

        cpe_identity = cpe_identity_from_software(
            software_identity
        )

        if cpe_identity is None:
            return ()

        cpe_name = cpe_identity.to_cpe23()
        findings: list[VulnerabilityFinding] = []
        seen_ids: set[str] = set()
        start_index = 0

        while True:
            payload = self._fetch_page(
                cpe_name=cpe_name,
                start_index=start_index,
            )

            vulnerabilities = payload.get(
                "vulnerabilities",
                [],
            )

            if not isinstance(vulnerabilities, list):
                vulnerabilities = []

            for item in vulnerabilities:
                finding = _parse_vulnerability(item)

                if (
                    finding is not None
                    and finding.vulnerability_id not in seen_ids
                ):
                    findings.append(finding)
                    seen_ids.add(finding.vulnerability_id)

            total_results = _as_int(
                payload.get("totalResults"),
                default=len(findings),
            )

            if not vulnerabilities:
                break

            start_index += len(vulnerabilities)

            if start_index >= total_results:
                break

        return tuple(findings)

    def _fetch_page(
        self,
        cpe_name: str,
        start_index: int,
    ) -> dict:
        params = urlencode(
            {
                "cpeName": cpe_name,
                "resultsPerPage": 2000,
                "startIndex": start_index,
            }
        )

        headers = {
            "Accept": "application/json",
            "User-Agent": "NightRecon",
        }

        if self.api_key:
            headers["apiKey"] = self.api_key

        request = Request(
            f"{NVD_CVE_API_URL}?{params}",
            headers=headers,
        )

        with urlopen(
            request,
            timeout=self.timeout,
        ) as response:
            payload = json.load(response)

        if not isinstance(payload, dict):
            raise ValueError(
                "NVD response must be a JSON object."
            )

        return payload


def _parse_vulnerability(
    item: object,
) -> VulnerabilityFinding | None:
    if not isinstance(item, dict):
        return None

    cve = item.get("cve")

    if not isinstance(cve, dict):
        return None

    vulnerability_id = cve.get("id")

    if (
        not isinstance(vulnerability_id, str)
        or not vulnerability_id.strip()
    ):
        return None

    summary = _english_description(
        cve.get("descriptions")
    )
    severity, cvss_score = _cvss_metadata(
        cve.get("metrics")
    )
    references = _reference_urls(
        cve.get("references")
    )

    return VulnerabilityFinding(
        vulnerability_id=vulnerability_id.strip(),
        source="nvd",
        summary=summary,
        severity=severity,
        cvss_score=cvss_score,
        references=references,
    )


def _english_description(
    descriptions: object,
) -> str:
    if not isinstance(descriptions, list):
        return ""

    for description in descriptions:
        if not isinstance(description, dict):
            continue

        if description.get("lang") != "en":
            continue

        value = description.get("value")

        if isinstance(value, str):
            return value.strip()

    return ""


def _cvss_metadata(
    metrics: object,
) -> tuple[str, float | None]:
    if not isinstance(metrics, dict):
        return "", None

    for metric_name in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        entries = metrics.get(metric_name)

        if not isinstance(entries, list):
            continue

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            cvss_data = entry.get("cvssData")

            if not isinstance(cvss_data, dict):
                continue

            score = _as_float(
                cvss_data.get("baseScore")
            )
            severity = cvss_data.get("baseSeverity")

            if not isinstance(severity, str):
                severity = entry.get("baseSeverity")

            if not isinstance(severity, str):
                severity = ""

            if score is not None or severity:
                return severity.strip(), score

    return "", None


def _reference_urls(
    references: object,
) -> tuple[str, ...]:
    if not isinstance(references, list):
        return ()

    urls: list[str] = []

    for reference in references:
        if not isinstance(reference, dict):
            continue

        url = reference.get("url")

        if (
            isinstance(url, str)
            and url.strip()
            and url.strip() not in urls
        ):
            urls.append(url.strip())

    return tuple(urls)


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


def _as_int(
    value: object,
    default: int,
) -> int:
    if isinstance(value, bool):
        return default

    if isinstance(value, int):
        return value

    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default

    return default
