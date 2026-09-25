"""Structured service fingerprinting for NightRecon."""

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class ServiceFingerprint:
    """Evidence-backed service implementation fingerprint."""

    protocol: str
    protocol_version: str = ""
    product: str = ""
    version: str = ""
    platform: str = ""
    source: str = ""
    evidence: str = ""
    confidence: str = ""


def fingerprint_banner(
    banner: str,
) -> ServiceFingerprint | None:
    """Fingerprint supported service banners without speculative guessing."""

    evidence = banner.strip()

    if not evidence:
        return None

    ssh = _fingerprint_ssh(evidence)

    if ssh is not None:
        return ssh

    ftp = _fingerprint_ftp(evidence)

    if ftp is not None:
        return ftp

    smtp = _fingerprint_smtp(evidence)

    if smtp is not None:
        return smtp

    return None


def fingerprint_http_server(
    server: str,
) -> ServiceFingerprint | None:
    """Fingerprint an explicit HTTP Server observation."""

    evidence = server.strip()

    if not evidence:
        return None

    first_token = evidence.split()[0]

    if "/" not in first_token:
        return None

    product, version = first_token.split("/", 1)
    product = product.strip()
    version = version.strip()

    if not product or not version:
        return None

    return ServiceFingerprint(
        protocol="http",
        product=product,
        version=version,
        platform=_parenthetical_platform(evidence),
        source="http-server",
        evidence=evidence,
        confidence="high",
    )


def _fingerprint_ssh(
    evidence: str,
) -> ServiceFingerprint | None:
    match = re.match(
        r"^SSH-(?P<protocol>[^-]+)-"
        r"(?P<software>\S+)"
        r"(?:\s+(?P<comment>.*))?$",
        evidence,
    )

    if match is None:
        return None

    software = match.group("software")
    comment = (match.group("comment") or "").strip()

    product = ""
    version = ""

    if software.startswith("OpenSSH_"):
        product = "OpenSSH"
        version = software[len("OpenSSH_"):]

    platform = ""

    if comment:
        platform = comment.split("-", 1)[0].strip()

    return ServiceFingerprint(
        protocol="ssh",
        protocol_version=match.group("protocol"),
        product=product,
        version=version,
        platform=platform,
        source="banner",
        evidence=evidence,
        confidence="high",
    )


def _fingerprint_ftp(
    evidence: str,
) -> ServiceFingerprint | None:
    if not evidence.lower().startswith("220 "):
        return None

    match = re.search(
        r"\b(ProFTPD|FileZilla)(?:\s+|/)"
        r"(?P<version>[0-9][^\s;]*)",
        evidence,
        flags=re.IGNORECASE,
    )

    if match is None:
        return None

    product = match.group(1)
    product = (
        "ProFTPD"
        if product.lower() == "proftpd"
        else "FileZilla"
    )

    return ServiceFingerprint(
        protocol="ftp",
        product=product,
        version=match.group("version"),
        source="banner",
        evidence=evidence,
        confidence="high",
    )


def _fingerprint_smtp(
    evidence: str,
) -> ServiceFingerprint | None:
    normalized = evidence.lower()

    if (
        not normalized.startswith("220 ")
        or "smtp" not in normalized
    ):
        return None

    product = ""

    if "postfix" in normalized:
        product = "Postfix"
    elif "exim" in normalized:
        product = "Exim"

    if not product:
        return None

    return ServiceFingerprint(
        protocol="smtp",
        product=product,
        source="banner",
        evidence=evidence,
        confidence="high",
    )


def _parenthetical_platform(
    evidence: str,
) -> str:
    match = re.search(
        r"\(([^()]+)\)",
        evidence,
    )

    if match is None:
        return ""

    return match.group(1).strip()
