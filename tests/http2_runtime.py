"""Non-network HTTP/2 repeater runtime compatibility check."""

from __future__ import annotations

from unittest.mock import patch

import h2
import httpx

from nightrecon_red_engine.http2_repeater import replay_http2_request
from nightrecon_shared_core.authorization import Scope


class _Response:
    status_code = 200
    http_version = "HTTP/2"
    headers = httpx.Headers({"content-type": "text/plain"})

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def iter_bytes(self):
        yield b"ok"


class _Client:
    def __init__(self, **kwargs):
        assert kwargs["http2"] is True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def stream(self, method, url, headers, content):
        assert method == "GET"
        assert url == "https://example.test/health"
        return _Response()


def main() -> int:
    assert httpx is not None
    assert h2 is not None

    with patch("httpx.Client", _Client):
        response = replay_http2_request(
            method="GET",
            url="https://example.test/health",
            scope=Scope.from_values(["example.test"]),
        )

    assert response.status == 200
    assert response.http_version == "HTTP/2"
    assert response.body == b"ok"
    print("HTTP/2 repeater runtime compatibility: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
