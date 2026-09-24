"""Built-in passive assessment checks for NightRecon."""

from __future__ import annotations

from nightrecon.assessment_engine import (
    AssessmentCheckMetadata,
    AssessmentContext,
    AssessmentFinding,
    CheckIntrusiveness,
)


class MissingSecurityHeadersCheck:
    """Report expected HTTP security headers observed as missing."""

    metadata = AssessmentCheckMetadata(
        check_id="web.security_headers.missing",
        name="Missing HTTP Security Headers",
        family="web",
        description=(
            "Reports expected HTTP security headers that were observed "
            "as missing during NightRecon HTTP/HTTPS probing."
        ),
        intrusiveness=CheckIntrusiveness.PASSIVE,
        supported_services=("http", "http-alt", "https"),
        tags=("http", "headers", "hardening"),
    )

    def run(
        self,
        context: AssessmentContext,
    ) -> tuple[AssessmentFinding, ...]:
        service = context.service_result

        if service is None:
            return ()

        missing = tuple(
            getattr(
                service,
                "security_headers_missing",
                (),
            )
        )

        if not missing:
            return ()

        return (
            AssessmentFinding(
                check_id=self.metadata.check_id,
                title="Expected HTTP security headers are missing",
                summary=(
                    "The observed HTTP response did not include one or "
                    "more expected security headers."
                ),
                evidence=(
                    "missing_headers="
                    + ",".join(missing),
                ),
                severity="informational",
                remediation=(
                    "Review the missing headers in application context "
                    "and configure appropriate response headers where "
                    "they are applicable."
                ),
            ),
        )


class LegacyTlsProtocolCheck:
    """Report an observed TLS protocol older than TLS 1.2."""

    metadata = AssessmentCheckMetadata(
        check_id="tls.legacy_protocol",
        name="Legacy TLS Protocol",
        family="tls",
        description=(
            "Reports TLS 1.0 or TLS 1.1 when observed during the "
            "NightRecon TLS handshake."
        ),
        intrusiveness=CheckIntrusiveness.PASSIVE,
        supported_services=("https",),
        tags=("tls", "crypto", "hardening"),
    )

    def run(
        self,
        context: AssessmentContext,
    ) -> tuple[AssessmentFinding, ...]:
        service = context.service_result

        if service is None:
            return ()

        tls_version = str(
            getattr(
                service,
                "tls_version",
                "",
            )
        ).strip()

        if tls_version not in {
            "TLSv1",
            "TLSv1.0",
            "TLSv1.1",
        }:
            return ()

        return (
            AssessmentFinding(
                check_id=self.metadata.check_id,
                title="Legacy TLS protocol observed",
                summary=(
                    "NightRecon observed a TLS protocol version older "
                    "than TLS 1.2."
                ),
                evidence=(
                    f"tls_version={tls_version}",
                ),
                severity="medium",
                remediation=(
                    "Review compatibility requirements and disable TLS "
                    "1.0/1.1 where they are not required."
                ),
            ),
        )


def builtin_checks() -> tuple[object, ...]:
    """Return NightRecon's built-in assessment checks."""

    checks = (
        MissingSecurityHeadersCheck(),
        LegacyTlsProtocolCheck(),
    )

    return tuple(
        sorted(
            checks,
            key=lambda check: check.metadata.check_id,
        )
    )
