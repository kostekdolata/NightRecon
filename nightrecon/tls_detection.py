"""TLS intelligence primitives for NightRecon."""

from dataclasses import dataclass
import socket
import ssl
from cryptography.hazmat.primitives import hashes
from cryptography import x509


@dataclass(frozen=True)
class TlsMetadata:
    """Observed TLS metadata from an authorized service."""

    tls_version: str
    cipher: str
    certificate_subject: str
    certificate_issuer: str
    certificate_not_before: str = ""
    certificate_not_after: str = ""
    certificate_sans: tuple[str, ...] = ()
    certificate_sha256: str = ""
    http_status: str = ""
    http_server: str = ""
    http_headers: tuple[tuple[str, str], ...] = ()


def format_certificate_name(
    name: tuple[tuple[tuple[str, str], ...], ...],
) -> str:
    """Format an SSL certificate subject or issuer name."""

    parts = []

    for group in name:
        for key, value in group:
            parts.append(f"{key}={value}")

    return ", ".join(parts)


def probe_tls_service(
    address: str,
    port: int,
    timeout: float,
    server_hostname: str | None = None,
) -> TlsMetadata:
    """Perform a bounded TLS handshake and collect basic metadata."""

    if port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535.")

    if timeout <= 0:
        raise ValueError("Timeout must be greater than 0.")

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        raw_socket = socket.create_connection(
            (address, port),
            timeout=timeout,
        )
    except OSError:
        return TlsMetadata(
            tls_version="",
            cipher="",
            certificate_subject="",
            certificate_issuer="",
            certificate_sans=(),
            certificate_not_before="",
            certificate_not_after="",
            certificate_sha256="",
        )

    sni_hostname = server_hostname or address

    try:
        try:
            with context.wrap_socket(
                raw_socket,
                server_hostname=sni_hostname,
            ) as tls_socket:
                tls_version = tls_socket.version() or ""

                cipher_info = tls_socket.cipher()
                cipher = (
                    cipher_info[0]
                    if cipher_info
                    else ""
                )

                certificate_subject = ""
                certificate_issuer = ""
                certificate_not_before = ""
                certificate_not_after = ""
                certificate_sans = ()
                certificate_sha256 = ""
                http_status = ""
                http_server = ""
                http_headers: tuple[tuple[str, str], ...] = ()

                der_certificate = tls_socket.getpeercert(
                    binary_form=True,
                )

                if der_certificate:
                    try:
                        certificate = (
                            x509.load_der_x509_certificate(
                                der_certificate
                            )
                        )
                    except ValueError:
                        certificate = None

                    if certificate is not None:
                        certificate_subject = (
                            certificate.subject.rfc4514_string()
                        )
                        certificate_issuer = (
                            certificate.issuer.rfc4514_string()
                        )
                        certificate_not_before = (
                            certificate
                            .not_valid_before_utc
                            .isoformat()
                        )
                        certificate_not_after = (
                            certificate
                            .not_valid_after_utc
                            .isoformat()
                        )
                        try:
                            sans_extension = (
                                certificate.extensions.get_extension_for_class(
                                    x509.SubjectAlternativeName
                                )
                            )
                            certificate_sans = tuple(
                                sans_extension.value.get_values_for_type(
                                    x509.DNSName
                                )
                            )
                        except x509.ExtensionNotFound:
                            certificate_sans = ()
                        certificate_sha256 = (
                            certificate.fingerprint(hashes.SHA256())
                            .hex()
                        )
                try:
                    request = (
                        f"HEAD / HTTP/1.1\r\n"
                        f"Host: {sni_hostname}\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    ).encode("ascii")

                    tls_socket.sendall(request)
                    response = tls_socket.recv(4096)

                    if isinstance(response, bytes) and response:
                        response_text = response.decode(
                        "iso-8859-1",
                            errors="replace",
                        )
                        lines = response_text.splitlines()

                        if lines:
                            http_status = lines[0].strip()

                        parsed_headers: list[tuple[str, str]] = []

                        for line in lines[1:]:
                            name, separator, value = line.partition(":")

                            if not separator:
                                continue

                            header_name = name.strip().lower()
                            header_value = value.strip()

                            parsed_headers.append(
                                (header_name, header_value)
                            )

                            if header_name == "server":
                                http_server = header_value

                        http_headers = tuple(parsed_headers)

                except (socket.timeout, OSError, ssl.SSLError):
                    pass


                return TlsMetadata(
                    tls_version=tls_version,
                    cipher=cipher,
                    certificate_subject=certificate_subject,
                    certificate_issuer=certificate_issuer,
                    certificate_not_before=certificate_not_before,
                    certificate_not_after=certificate_not_after,
                    certificate_sans=certificate_sans,
                    certificate_sha256=certificate_sha256,
                    http_status=http_status,
                    http_server=http_server,
                    http_headers=http_headers,
                )



        except (ssl.SSLError, OSError):
            return TlsMetadata(
                tls_version="",
                cipher="",
                certificate_subject="",
                certificate_issuer="",
                certificate_not_before="",
                certificate_not_after="",
                certificate_sans=(),
            )

    finally:
        raw_socket.close()
