"""Loopback-only HTTPS interception runtime verification."""

from __future__ import annotations

import os
from pathlib import Path
import socket
import ssl
from tempfile import TemporaryDirectory
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from nightrecon_red_engine.https_intercept import AssessmentCertificateAuthority
from nightrecon_red_engine.web_proxy_repeater import BoundedInterceptProxy
from nightrecon_shared_core.authorization import Scope


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Set-Cookie", "sid=upstream-secret; HttpOnly")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


def _read_headers(sock: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > 65536:
            raise AssertionError("header read exceeded bound")
    return bytes(data)


def main() -> int:
    previous_cert_file = os.environ.get("SSL_CERT_FILE")

    with TemporaryDirectory(prefix="red-night-https-runtime-") as root:
        root_path = Path(root)
        upstream_ca_dir = root_path / "upstream-ca"
        proxy_ca_dir = root_path / "proxy-ca"

        with AssessmentCertificateAuthority(
            common_name="Runtime Upstream CA",
            directory=str(upstream_ca_dir),
        ) as upstream_ca:
            server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
            upstream_port = int(server.server_address[1])
            context = upstream_ca.server_context("127.0.0.1")
            server.socket = context.wrap_socket(
                server.socket,
                server_side=True,
            )
            thread = threading.Thread(
                target=server.serve_forever,
                daemon=True,
            )
            thread.start()

            os.environ["SSL_CERT_FILE"] = str(
                upstream_ca.ca_certificate_path
            )

            proxy = BoundedInterceptProxy(
                scope=Scope.from_values(["127.0.0.1"]),
                https_intercept=True,
                ca_directory=str(proxy_ca_dir),
            )
            proxy.start()

            try:
                proxy_host, proxy_port = proxy.address
                raw = socket.create_connection(
                    (proxy_host, proxy_port),
                    timeout=5,
                )
                raw.sendall(
                    (
                        f"CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{upstream_port}\r\n"
                        "Connection: keep-alive\r\n\r\n"
                    ).encode("ascii")
                )
                connect_response = _read_headers(raw)
                assert b"200 Connection Established" in connect_response

                client_context = ssl.create_default_context(
                    cafile=proxy.ca_certificate_path
                )
                tls = client_context.wrap_socket(
                    raw,
                    server_hostname="127.0.0.1",
                )
                tls.sendall(
                    (
                        "GET /health?token=secret-query HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{upstream_port}\r\n"
                        "Authorization: Bearer secret-header\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("ascii")
                )
                response = bytearray()
                while True:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    response.extend(chunk)
                tls.close()

                assert b"200 OK" in response
                assert b"ok" in response
                assert len(proxy.records) == 1
                record = proxy.records[0]
                assert record.url.endswith("/health")
                assert "secret-query" not in str(record)
                assert "secret-header" not in str(record)
                assert "upstream-secret" not in str(record)
                assert record.parameters
            finally:
                proxy.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    if previous_cert_file is None:
        os.environ.pop("SSL_CERT_FILE", None)
    else:
        os.environ["SSL_CERT_FILE"] = previous_cert_file

    print("HTTPS interception loopback runtime: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
