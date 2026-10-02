"""Optional Playwright browser discovery adapter for NightRecon.

Playwright is imported lazily so the core NightRecon package does not require
browser dependencies unless browser-powered discovery is explicitly selected.
"""

from __future__ import annotations

from dataclasses import dataclass
from time import monotonic
from typing import Callable, Protocol
from urllib.parse import urljoin

from nightrecon_red_engine.browser_policy import (
    BrowserDiscoveryPolicy,
    BrowserResourceKind,
)
from nightrecon_red_engine.browser_worker import (
    BrowserDiscoveryController,
    BrowserDiscoverySnapshot,
)
from nightrecon_red_engine.web_crawl import normalize_http_url, url_origin


class BrowserRuntimeUnavailable(RuntimeError):
    """Raised when the optional Playwright runtime is not installed."""


@dataclass(frozen=True)
class BrowserFormFieldObservation:
    name: str
    input_type: str


@dataclass(frozen=True)
class BrowserFormObservation:
    action: str
    method: str
    inputs: tuple[BrowserFormFieldObservation, ...]


@dataclass(frozen=True)
class BrowserPageObservation:
    url: str
    title: str
    links: tuple[str, ...]
    forms: tuple[BrowserFormObservation, ...]


@dataclass(frozen=True)
class PlaywrightDiscoveryResult:
    page: BrowserPageObservation | None
    snapshot: BrowserDiscoverySnapshot
    error: str | None = None


class _SyncPlaywrightFactory(Protocol):
    def __call__(self): ...


_RESOURCE_KIND_MAP = {
    "document": BrowserResourceKind.DOCUMENT,
    "stylesheet": BrowserResourceKind.STYLESHEET,
    "xhr": BrowserResourceKind.XHR,
    "fetch": BrowserResourceKind.FETCH,
    "image": BrowserResourceKind.IMAGE,
    "font": BrowserResourceKind.FONT,
    "script": BrowserResourceKind.SCRIPT,
}


_DOM_DISCOVERY_SCRIPT = """
(maxItems) => {
  const clean = (value) => typeof value === "string" ? value : "";
  const anchors = Array.from(document.querySelectorAll("a[href]"))
    .slice(0, maxItems)
    .map((node) => clean(node.href));

  const forms = Array.from(document.forms)
    .slice(0, maxItems)
    .map((form) => ({
      action: clean(form.action),
      method: clean(form.method || "GET").toUpperCase(),
      inputs: Array.from(form.elements)
        .slice(0, maxItems)
        .map((field) => ({
          name: clean(field.name),
          type: clean(field.type || "text").toLowerCase(),
        })),
    }));

  return {
    title: clean(document.title).slice(0, 512),
    links: anchors,
    forms,
  };
}
"""


def _resource_kind(value: str) -> BrowserResourceKind:
    return _RESOURCE_KIND_MAP.get(
        value.strip().lower(),
        BrowserResourceKind.OTHER,
    )


def _normalize_same_origin_links(
    *,
    page_url: str,
    links: list[str],
    origin: str,
    max_items: int,
) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for raw in links[:max_items]:
        if not isinstance(raw, str) or not raw.strip():
            continue

        try:
            candidate = normalize_http_url(
                urljoin(page_url, raw)
            )
        except ValueError:
            continue

        if url_origin(candidate) != origin:
            continue

        if candidate in seen:
            continue

        seen.add(candidate)
        normalized.append(candidate)

    return tuple(normalized)


def _normalize_forms(
    *,
    page_url: str,
    forms: list[dict],
    origin: str,
    max_items: int,
) -> tuple[BrowserFormObservation, ...]:
    observations: list[BrowserFormObservation] = []

    for raw_form in forms[:max_items]:
        if not isinstance(raw_form, dict):
            continue

        raw_action = raw_form.get("action", "")
        action = ""

        if isinstance(raw_action, str) and raw_action.strip():
            try:
                candidate = normalize_http_url(
                    urljoin(page_url, raw_action)
                )

                if url_origin(candidate) == origin:
                    action = candidate
            except ValueError:
                action = ""

        method = str(
            raw_form.get("method", "GET")
        ).strip().upper() or "GET"

        fields: list[BrowserFormFieldObservation] = []

        raw_inputs = raw_form.get("inputs", [])

        if isinstance(raw_inputs, list):
            for raw_input in raw_inputs[:max_items]:
                if not isinstance(raw_input, dict):
                    continue

                fields.append(
                    BrowserFormFieldObservation(
                        name=str(
                            raw_input.get("name", "")
                        ).strip(),
                        input_type=(
                            str(
                                raw_input.get(
                                    "type",
                                    "text",
                                )
                            ).strip().lower()
                            or "text"
                        ),
                    )
                )

        observations.append(
            BrowserFormObservation(
                action=action,
                method=method,
                inputs=tuple(fields),
            )
        )

    return tuple(observations)


def _load_sync_playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise BrowserRuntimeUnavailable(
            "Browser-powered discovery requires the optional "
            "'playwright' package and a Chromium browser install."
        ) from exc

    return sync_playwright


def discover_with_playwright(
    *,
    start_url: str,
    policy: BrowserDiscoveryPolicy,
    headless: bool = True,
    authorization: str | None = None,
    playwright_factory: _SyncPlaywrightFactory | None = None,
    clock: Callable[[], float] = monotonic,
) -> PlaywrightDiscoveryResult:
    """Run one bounded browser navigation under NightRecon interception."""

    normalized_url = normalize_http_url(
        start_url
    )

    if url_origin(normalized_url) != policy.origin:
        raise PermissionError(
            "Browser start URL is outside the authorized origin."
        )

    if authorization is not None and (
        not isinstance(authorization, str)
        or not authorization.strip()
    ):
        raise ValueError(
            "authorization must be a non-empty string when provided."
        )

    controller = BrowserDiscoveryController(
        policy
    )
    factory = (
        playwright_factory
        if playwright_factory is not None
        else _load_sync_playwright()
    )
    timeout_ms = max(
        1,
        int(
            policy.max_runtime_seconds
            * 1000
        ),
    )
    started = clock()
    browser = None
    context = None

    try:
        with factory() as playwright:
            browser = playwright.chromium.launch(
                headless=headless
            )
            context_options = {
                "service_workers": "block",
            }
            if authorization is not None:
                context_options["extra_http_headers"] = {
                    "Authorization": authorization.strip(),
                }

            context = browser.new_context(
                **context_options
            )
            page = context.new_page()
            page.set_default_timeout(
                timeout_ms
            )
            page.set_default_navigation_timeout(
                timeout_ms
            )

            def handle_route(route) -> None:
                request = route.request
                kind = _resource_kind(
                    request.resource_type
                )
                decision = controller.intercept_request(
                    url=request.url,
                    method=request.method,
                    resource_kind=kind,
                    top_level_document=(
                        request.is_navigation_request()
                        and kind
                        == BrowserResourceKind.DOCUMENT
                    ),
                )

                if not decision.allowed:
                    route.abort(
                        "blockedbyclient"
                    )
                    return

                response = route.fetch(
                    max_redirects=0,
                    timeout=timeout_ms,
                )
                headers = getattr(
                    response,
                    "headers",
                    {},
                )
                raw_length = (
                    headers.get(
                        "content-length",
                        "0",
                    )
                    if isinstance(
                        headers,
                        dict,
                    )
                    else "0"
                )

                try:
                    byte_count = max(
                        int(raw_length),
                        0,
                    )
                except (TypeError, ValueError):
                    byte_count = 0

                response_status = getattr(
                    response,
                    "status",
                    None,
                )
                response_observation = controller.record_response(
                    url=request.url,
                    status=response_status,
                    byte_count=byte_count,
                )

                if (
                    response_status is not None
                    and 300 <= response_status < 400
                ):
                    route.abort(
                        "blockedbyresponse"
                    )
                    return

                if not response_observation.capture_allowed:
                    route.abort(
                        "blockedbyresponse"
                    )
                    return

                route.fulfill(
                    response=response
                )

            context.route(
                "**/*",
                handle_route,
            )

            page.goto(
                normalized_url,
                wait_until="domcontentloaded",
                timeout=timeout_ms,
            )
            elapsed = max(
                clock() - started,
                0.0,
            )
            controller.add_runtime_elapsed(
                elapsed_seconds=elapsed,
            )

            final_url = normalize_http_url(
                page.url
            )

            if url_origin(final_url) != policy.origin:
                raise PermissionError(
                    "Browser navigation escaped the authorized origin."
                )

            raw = page.evaluate(
                _DOM_DISCOVERY_SCRIPT,
                policy.max_dom_items,
            )

            if not isinstance(raw, dict):
                raise ValueError(
                    "Browser DOM discovery returned invalid metadata."
                )

            raw_links = raw.get(
                "links",
                [],
            )
            raw_forms = raw.get(
                "forms",
                [],
            )

            if not isinstance(raw_links, list):
                raw_links = []

            if not isinstance(raw_forms, list):
                raw_forms = []

            links = _normalize_same_origin_links(
                page_url=final_url,
                links=raw_links,
                origin=policy.origin,
                max_items=policy.max_dom_items,
            )
            forms = _normalize_forms(
                page_url=final_url,
                forms=raw_forms,
                origin=policy.origin,
                max_items=policy.max_dom_items,
            )
            title = str(
                raw.get(
                    "title",
                    "",
                )
            )[:512]

            encoded_metadata = repr(
                (
                    final_url,
                    title,
                    links,
                    forms,
                )
            ).encode(
                "utf-8",
                errors="replace",
            )
            dom_decision = controller.record_dom_snapshot(
                url=final_url,
                byte_count=len(
                    encoded_metadata
                ),
            )

            if not dom_decision.capture_allowed:
                return PlaywrightDiscoveryResult(
                    page=None,
                    snapshot=controller.snapshot(),
                    error=dom_decision.reason,
                )

            return PlaywrightDiscoveryResult(
                page=BrowserPageObservation(
                    url=final_url,
                    title=title,
                    links=links,
                    forms=forms,
                ),
                snapshot=controller.snapshot(),
                error=None,
            )
    except BrowserRuntimeUnavailable:
        raise
    except Exception as exc:
        return PlaywrightDiscoveryResult(
            page=None,
            snapshot=controller.snapshot(),
            error=(
                f"{exc.__class__.__name__}: "
                f"{str(exc)[:256]}"
            ),
        )
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass

        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
