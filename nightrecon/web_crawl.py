"""Bounded same-origin web crawling for authorized NightRecon assessments."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen


_DEFAULT_USER_AGENT = "NightRecon/0.21 web-crawler"
_HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")


@dataclass(frozen=True)
class CrawlPage:
    """One bounded web-crawl observation."""

    url: str
    status: int | None
    content_type: str
    byte_count: int
    links: tuple[str, ...]
    error: str = ""


@dataclass(frozen=True)
class CrawlResult:
    """Deterministic result for one bounded same-origin crawl."""

    start_url: str
    origin: str
    pages: tuple[CrawlPage, ...]
    max_pages: int
    max_bytes_per_page: int

    @property
    def pages_fetched(self) -> int:
        return len(self.pages)

    @property
    def successful_pages(self) -> int:
        return sum(page.error == "" for page in self.pages)


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() not in {"a", "area"}:
            return

        for name, value in attrs:
            if name.lower() == "href" and value:
                self.links.append(value)
                break


def normalize_http_url(value: str) -> str:
    """Normalize one absolute HTTP(S) URL and remove fragments."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("URL must be a non-empty string.")

    without_fragment, _fragment = urldefrag(value.strip())
    parsed = urlsplit(without_fragment)

    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported.")

    if not parsed.hostname:
        raise ValueError("URL must include a hostname.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Embedded URL credentials are not supported.")

    host = parsed.hostname.lower()

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL port.") from exc

    default_port = (
        scheme == "http" and port == 80
    ) or (
        scheme == "https" and port == 443
    )

    if port is None or default_port:
        netloc = host
    else:
        netloc = f"{host}:{port}"

    path = parsed.path or "/"

    return urlunsplit(
        (
            scheme,
            netloc,
            path,
            parsed.query,
            "",
        )
    )


def url_origin(value: str) -> str:
    """Return the normalized scheme/host/port origin for an HTTP(S) URL."""

    normalized = normalize_http_url(value)
    parsed = urlsplit(normalized)
    return f"{parsed.scheme}://{parsed.netloc}"


def extract_same_origin_links(
    *,
    base_url: str,
    html: str,
    origin: str,
) -> tuple[str, ...]:
    """Extract deterministic same-origin HTTP(S) links from HTML."""

    parser = _LinkParser()
    parser.feed(html)

    links: set[str] = set()

    for raw_link in parser.links:
        candidate = raw_link.strip()

        if not candidate:
            continue

        lowered = candidate.lower()

        if lowered.startswith(
            (
                "javascript:",
                "mailto:",
                "tel:",
                "data:",
            )
        ):
            continue

        try:
            absolute = normalize_http_url(
                urljoin(base_url, candidate)
            )
        except ValueError:
            continue

        if url_origin(absolute) == origin:
            links.add(absolute)

    return tuple(sorted(links))


def crawl_site(
    *,
    start_url: str,
    max_pages: int = 50,
    max_bytes_per_page: int = 1_048_576,
    timeout: float = 5.0,
    user_agent: str = _DEFAULT_USER_AGENT,
) -> CrawlResult:
    """Crawl one HTTP(S) origin with explicit resource bounds."""

    if max_pages < 1:
        raise ValueError("max_pages must be at least 1.")

    if max_bytes_per_page < 1:
        raise ValueError(
            "max_bytes_per_page must be at least 1."
        )

    if timeout <= 0:
        raise ValueError("timeout must be greater than 0.")

    if not isinstance(user_agent, str) or not user_agent.strip():
        raise ValueError("user_agent must be a non-empty string.")

    normalized_start = normalize_http_url(start_url)
    origin = url_origin(normalized_start)
    pending: deque[str] = deque((normalized_start,))
    queued = {normalized_start}
    pages: list[CrawlPage] = []

    while pending and len(pages) < max_pages:
        current = pending.popleft()

        page = _fetch_page(
            url=current,
            origin=origin,
            max_bytes=max_bytes_per_page,
            timeout=timeout,
            user_agent=user_agent.strip(),
        )
        pages.append(page)

        for link in page.links:
            if link not in queued and len(queued) < max_pages:
                queued.add(link)
                pending.append(link)

    return CrawlResult(
        start_url=normalized_start,
        origin=origin,
        pages=tuple(pages),
        max_pages=max_pages,
        max_bytes_per_page=max_bytes_per_page,
    )


def _fetch_page(
    *,
    url: str,
    origin: str,
    max_bytes: int,
    timeout: float,
    user_agent: str,
) -> CrawlPage:
    request = Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", None)
            content_type = (
                response.headers.get_content_type()
                if response.headers is not None
                else ""
            )
            raw = response.read(max_bytes + 1)
    except Exception as exc:
        return CrawlPage(
            url=url,
            status=None,
            content_type="",
            byte_count=0,
            links=(),
            error=f"{type(exc).__name__}: {exc}",
        )

    if len(raw) > max_bytes:
        raw = raw[:max_bytes]

    links: tuple[str, ...] = ()

    if content_type in _HTML_CONTENT_TYPES:
        charset = response.headers.get_content_charset() or "utf-8"

        try:
            html = raw.decode(charset, errors="replace")
        except LookupError:
            html = raw.decode("utf-8", errors="replace")

        links = extract_same_origin_links(
            base_url=url,
            html=html,
            origin=origin,
        )

    return CrawlPage(
        url=url,
        status=status,
        content_type=content_type,
        byte_count=len(raw),
        links=links,
    )
