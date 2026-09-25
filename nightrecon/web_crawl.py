"""Bounded same-origin web crawling for authorized NightRecon assessments."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from http.cookies import CookieError, SimpleCookie
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


_DEFAULT_USER_AGENT = "NightRecon/0.23 web-crawler"
_HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")
_MAX_TITLE_LENGTH = 512


@dataclass(frozen=True)
class WebFormInput:
    """Non-sensitive HTML input metadata observed during crawling."""

    name: str
    input_type: str


@dataclass(frozen=True)
class WebFormObservation:
    """Passive HTML form metadata without field values."""

    action: str
    method: str
    inputs: tuple[WebFormInput, ...]


@dataclass(frozen=True)
class WebCookieObservation:
    """Cookie metadata observed without retaining the cookie value."""

    name: str
    path: str
    secure: bool
    http_only: bool
    same_site: str


@dataclass(frozen=True)
class HtmlContentDiscovery:
    """Passive structural metadata discovered in one HTML response."""

    title: str
    links: tuple[str, ...]
    forms: tuple[WebFormObservation, ...]
    script_sources: tuple[str, ...]


@dataclass(frozen=True)
class CrawlPage:
    """One bounded web-crawl observation."""

    url: str
    status: int | None
    content_type: str
    byte_count: int
    links: tuple[str, ...]
    error: str = ""
    title: str = ""
    forms: tuple[WebFormObservation, ...] = ()
    script_sources: tuple[str, ...] = ()
    cookies: tuple[WebCookieObservation, ...] = ()


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


class _SameOriginRedirectHandler(HTTPRedirectHandler):
    """Allow redirects only within the crawl's authorized origin."""

    def __init__(self, origin: str) -> None:
        super().__init__()
        self.origin = origin

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        absolute = normalize_http_url(
            urljoin(req.full_url, newurl)
        )

        if url_origin(absolute) != self.origin:
            raise ValueError(
                "Cross-origin redirect blocked: "
                f"{absolute}"
            )

        return super().redirect_request(
            req,
            fp,
            code,
            msg,
            headers,
            absolute,
        )


class _HtmlContentParser(HTMLParser):
    """Collect passive structural metadata from one HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.script_sources: list[str] = []
        self.forms: list[
            tuple[str, str, tuple[WebFormInput, ...]]
        ] = []
        self._current_form_action = ""
        self._current_form_method = ""
        self._current_form_inputs: list[WebFormInput] | None = None
        self._in_title = False
        self._title_parts: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        lowered_tag = tag.lower()
        attr_map = {
            name.lower(): value
            for name, value in attrs
        }

        if lowered_tag in {"a", "area"}:
            href = attr_map.get("href")

            if href:
                self.links.append(href)

        if lowered_tag == "script":
            source = attr_map.get("src")

            if source:
                self.script_sources.append(source)

        if lowered_tag == "title":
            self._in_title = True

        if lowered_tag == "form":
            self._flush_current_form()
            self._current_form_action = (
                attr_map.get("action")
                or ""
            )
            self._current_form_method = (
                attr_map.get("method")
                or "get"
            )
            self._current_form_inputs = []
            return

        if (
            lowered_tag == "input"
            and self._current_form_inputs is not None
        ):
            self._current_form_inputs.append(
                WebFormInput(
                    name=(
                        attr_map.get("name")
                        or ""
                    ).strip(),
                    input_type=(
                        attr_map.get("type")
                        or "text"
                    ).strip().lower(),
                )
            )

    def handle_endtag(
        self,
        tag: str,
    ) -> None:
        lowered_tag = tag.lower()

        if lowered_tag == "title":
            self._in_title = False
        elif lowered_tag == "form":
            self._flush_current_form()

    def handle_data(
        self,
        data: str,
    ) -> None:
        if self._in_title:
            self._title_parts.append(data)

    def close(self) -> None:
        super().close()
        self._flush_current_form()

    def title(self) -> str:
        normalized = " ".join(
            " ".join(self._title_parts).split()
        )
        return normalized[:_MAX_TITLE_LENGTH]

    def _flush_current_form(self) -> None:
        if self._current_form_inputs is None:
            return

        self.forms.append(
            (
                self._current_form_action,
                self._current_form_method,
                tuple(self._current_form_inputs),
            )
        )
        self._current_form_action = ""
        self._current_form_method = ""
        self._current_form_inputs = None


def parse_set_cookie_metadata(
    values: tuple[str, ...],
) -> tuple[WebCookieObservation, ...]:
    """Parse Set-Cookie headers while discarding all cookie values."""

    observations: list[WebCookieObservation] = []

    for raw_value in values:
        cookie = SimpleCookie()

        try:
            cookie.load(raw_value)
        except CookieError:
            continue

        for name, morsel in cookie.items():
            observations.append(
                WebCookieObservation(
                    name=name,
                    path=morsel["path"].strip(),
                    secure=bool(
                        morsel["secure"]
                    ),
                    http_only=bool(
                        morsel["httponly"]
                    ),
                    same_site=(
                        morsel["samesite"]
                        .strip()
                        .lower()
                    ),
                )
            )

    return tuple(
        sorted(
            observations,
            key=lambda item: (
                item.name,
                item.path,
                item.secure,
                item.http_only,
                item.same_site,
            ),
        )
    )


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

    host_for_netloc = (
        f"[{host}]"
        if ":" in host
        else host
    )

    if port is None or default_port:
        netloc = host_for_netloc
    else:
        netloc = f"{host_for_netloc}:{port}"

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


def discover_html_content(
    *,
    base_url: str,
    html: str,
    origin: str,
) -> HtmlContentDiscovery:
    """Extract passive structural metadata from bounded HTML content."""

    parser = _HtmlContentParser()
    parser.feed(html)
    parser.close()

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

    forms: list[WebFormObservation] = []

    for raw_action, raw_method, inputs in parser.forms:
        action_candidate = (
            raw_action.strip()
            if raw_action.strip()
            else base_url
        )

        try:
            action = normalize_http_url(
                urljoin(base_url, action_candidate)
            )
        except ValueError:
            action = ""

        method = raw_method.strip().upper() or "GET"

        forms.append(
            WebFormObservation(
                action=action,
                method=method,
                inputs=inputs,
            )
        )

    script_sources: set[str] = set()

    for raw_source in parser.script_sources:
        source_candidate = raw_source.strip()

        if not source_candidate:
            continue

        try:
            source = normalize_http_url(
                urljoin(base_url, source_candidate)
            )
        except ValueError:
            continue

        script_sources.add(source)

    return HtmlContentDiscovery(
        title=parser.title(),
        links=tuple(sorted(links)),
        forms=tuple(forms),
        script_sources=tuple(
            sorted(script_sources)
        ),
    )


def extract_same_origin_links(
    *,
    base_url: str,
    html: str,
    origin: str,
) -> tuple[str, ...]:
    """Extract deterministic same-origin HTTP(S) links from HTML."""

    return discover_html_content(
        base_url=base_url,
        html=html,
        origin=origin,
    ).links


def crawl_site(
    *,
    start_url: str,
    max_pages: int = 50,
    max_bytes_per_page: int = 1_048_576,
    timeout: float = 5.0,
    user_agent: str = _DEFAULT_USER_AGENT,
    authorization: str | None = None,
    cookie: str | None = None,
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

    if authorization is not None and (
        not isinstance(authorization, str)
        or not authorization.strip()
    ):
        raise ValueError(
            "authorization must be a non-empty string when provided."
        )

    if cookie is not None and (
        not isinstance(cookie, str)
        or not cookie.strip()
    ):
        raise ValueError(
            "cookie must be a non-empty string when provided."
        )

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
            authorization=(
                authorization.strip()
                if authorization is not None
                else None
            ),
            cookie=(
                cookie.strip()
                if cookie is not None
                else None
            ),
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
    authorization: str | None = None,
    cookie: str | None = None,
) -> CrawlPage:
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
    }

    if authorization is not None:
        headers["Authorization"] = authorization

    if cookie is not None:
        headers["Cookie"] = cookie

    request = Request(
        url,
        headers=headers,
        method="GET",
    )

    opener = build_opener(
        _SameOriginRedirectHandler(origin)
    )

    try:
        with opener.open(request, timeout=timeout) as response:
            status = getattr(response, "status", None)
            content_type = (
                response.headers.get_content_type()
                if response.headers is not None
                else ""
            )
            charset = (
                response.headers.get_content_charset()
                if response.headers is not None
                else None
            ) or "utf-8"
            set_cookie_headers = (
                tuple(
                    response.headers.get_all(
                        "Set-Cookie",
                        [],
                    )
                )
                if response.headers is not None
                else ()
            )
            final_url = normalize_http_url(
                response.geturl()
            )

            if url_origin(final_url) != origin:
                raise ValueError(
                    "Cross-origin response blocked: "
                    f"{final_url}"
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

    discovery = HtmlContentDiscovery(
        title="",
        links=(),
        forms=(),
        script_sources=(),
    )

    if content_type in _HTML_CONTENT_TYPES:
        try:
            html = raw.decode(charset, errors="replace")
        except LookupError:
            html = raw.decode("utf-8", errors="replace")

        discovery = discover_html_content(
            base_url=final_url,
            html=html,
            origin=origin,
        )

    return CrawlPage(
        url=url,
        status=status,
        content_type=content_type,
        byte_count=len(raw),
        links=discovery.links,
        title=discovery.title,
        forms=discovery.forms,
        script_sources=discovery.script_sources,
        cookies=parse_set_cookie_metadata(
            set_cookie_headers
        ),
    )
