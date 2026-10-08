"""Scoped HTTPS interception primitives for Red Night.

The assessment CA is generated locally, is never trusted automatically, and
exists only where the operator explicitly installs/trusts it. Recorded evidence
suppresses credential and cookie values by design.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import ipaddress
from pathlib import Path
import ssl
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from nightrecon_shared_core.authorization import Scope, parse_target


MAX_MITM_HOST_CERTS = 256
_SECRET_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
})


@dataclass(frozen=True)
class MitmCertificateMaterial:
    hostname: str
    certificate_path: str
    private_key_path: str
    certificate_sha256: str


@dataclass(frozen=True)
class DecryptedHttpMetadata:
    method: str
    path: str
    host: str
    header_names: tuple[str, ...]
    body_bytes: int
    body_sha256: str
    secret_header_names: tuple[str, ...]


class AssessmentCertificateAuthority:
    """Ephemeral/local CA for explicitly authorised HTTPS assessment."""

    def __init__(
        self,
        *,
        common_name: str = "Red Night Assessment CA",
        directory: str | None = None,
    ):
        self._owned_temp = directory is None
        self._temp = (
            tempfile.TemporaryDirectory(prefix="red-night-ca-")
            if self._owned_temp
            else None
        )
        self.directory = Path(
            self._temp.name if self._temp is not None else directory
        ).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._issued: dict[str, MitmCertificateMaterial] = {}

        self._key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        now = datetime.now(timezone.utc)
        subject = issuer = x509.Name((
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ))
        self._certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=7))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._key, hashes.SHA256())
        )

        self.ca_certificate_path = self.directory / "assessment-ca.pem"
        self.ca_private_key_path = self.directory / "assessment-ca-key.pem"
        self.ca_certificate_path.write_bytes(
            self._certificate.public_bytes(serialization.Encoding.PEM)
        )
        self.ca_private_key_path.write_bytes(
            self._key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        try:
            self.ca_private_key_path.chmod(0o600)
        except OSError:
            pass

    @property
    def ca_fingerprint_sha256(self) -> str:
        return sha256(
            self._certificate.public_bytes(serialization.Encoding.DER)
        ).hexdigest()

    def issue_host_certificate(
        self,
        hostname: str,
    ) -> MitmCertificateMaterial:
        normalized = hostname.strip().lower().rstrip(".")
        if not normalized:
            raise ValueError("hostname must not be empty")

        with self._lock:
            existing = self._issued.get(normalized)
            if existing is not None:
                return existing
            if len(self._issued) >= MAX_MITM_HOST_CERTS:
                raise ValueError(
                    f"issued host certificate limit {MAX_MITM_HOST_CERTS} reached"
                )

            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            now = datetime.now(timezone.utc)
            subject = x509.Name((
                x509.NameAttribute(NameOID.COMMON_NAME, normalized),
            ))
            san_values: list[x509.GeneralName] = []
            try:
                san_values.append(
                    x509.IPAddress(ipaddress.ip_address(normalized))
                )
            except ValueError:
                san_values.append(x509.DNSName(normalized))

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(self._certificate.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5))
                .not_valid_after(now + timedelta(days=2))
                .add_extension(
                    x509.SubjectAlternativeName(san_values),
                    critical=False,
                )
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
                .sign(self._key, hashes.SHA256())
            )

            token = sha256(normalized.encode()).hexdigest()[:20]
            cert_path = self.directory / f"host-{token}.pem"
            key_path = self.directory / f"host-{token}-key.pem"
            cert_path.write_bytes(
                cert.public_bytes(serialization.Encoding.PEM)
            )
            key_path.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            try:
                key_path.chmod(0o600)
            except OSError:
                pass
            material = MitmCertificateMaterial(
                hostname=normalized,
                certificate_path=str(cert_path),
                private_key_path=str(key_path),
                certificate_sha256=sha256(
                    cert.public_bytes(serialization.Encoding.DER)
                ).hexdigest(),
            )
            self._issued[normalized] = material
            return material

    def server_context(self, hostname: str) -> ssl.SSLContext:
        material = self.issue_host_certificate(hostname)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            certfile=material.certificate_path,
            keyfile=material.private_key_path,
        )
        context.set_alpn_protocols(["http/1.1"])
        return context

    def close(self) -> None:
        if self._temp is not None:
            self._temp.cleanup()
            self._temp = None

    def __enter__(self) -> "AssessmentCertificateAuthority":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def authorize_connect_target(
    host: str,
    port: int,
    scope: Scope,
) -> None:
    if not host.strip():
        raise ValueError("CONNECT host must not be empty")
    if not 1 <= port <= 65535:
        raise ValueError("CONNECT port must be between 1 and 65535")
    target = parse_target(host)
    if not scope.is_authorized(target):
        raise PermissionError(
            f"Target '{host}' is outside the authorized scope."
        )


def summarize_decrypted_request(
    *,
    method: str,
    path: str,
    host: str,
    headers: tuple[tuple[str, str], ...],
    body: bytes,
) -> DecryptedHttpMetadata:
    """Build secret-minimized metadata from a decrypted HTTPS request."""
    safe_names = []
    secret_names = []
    for name, _value in headers:
        lowered = name.strip().lower()
        if not lowered:
            continue
        if lowered in _SECRET_HEADERS:
            secret_names.append(lowered)
        else:
            safe_names.append(lowered)

    safe_path = (path or "/").split("?", 1)[0][:1024]
    return DecryptedHttpMetadata(
        method=method.upper()[:16],
        path=safe_path,
        host=host.strip().lower()[:253],
        header_names=tuple(sorted(set(safe_names))),
        body_bytes=len(body),
        body_sha256=sha256(body).hexdigest() if body else "",
        secret_header_names=tuple(sorted(set(secret_names))),
    )
