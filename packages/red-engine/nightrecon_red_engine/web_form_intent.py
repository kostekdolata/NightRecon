"""Passive form-intent metadata for NightRecon web workflows.

This module classifies already observed form structure. It stores no field
values, sends no requests, and never submits forms.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from nightrecon_red_engine.web_crawl import (
    CrawlPage,
    WebFormInput,
    normalize_http_url,
    url_origin,
)


class WorkflowFieldClass(str, Enum):
    """Descriptive classification for one observed form field."""

    CREDENTIAL = "credential"
    ANTI_CSRF = "anti-csrf"
    SESSION_TOKEN = "session-token"
    HIDDEN = "hidden"
    ORDINARY = "ordinary"


@dataclass(frozen=True)
class WorkflowFormFieldIntent:
    """Non-secret workflow metadata for one observed form field."""

    name: str
    input_type: str
    field_class: WorkflowFieldClass
    sensitive: bool
    value_retained: bool = False


@dataclass(frozen=True)
class WorkflowFormIntent:
    """Passive description of one observed HTML form."""

    source_url: str
    action_url: str
    method: str
    action_same_origin: bool
    fields: tuple[WorkflowFormFieldIntent, ...]
    submission_enabled: bool = False


_CREDENTIAL_NAMES = frozenset(
    {
        "password",
        "passwd",
        "passcode",
        "pwd",
    }
)

_ANTI_CSRF_MARKERS = (
    "csrf",
    "xsrf",
    "authenticity_token",
    "request_verification_token",
    "requestverificationtoken",
)

_SESSION_MARKERS = (
    "session",
    "sessionid",
    "session_id",
    "auth_token",
    "access_token",
    "id_token",
)


def _normalized_field_name(value: str) -> str:
    return (
        value.strip()
        .lower()
        .replace("-", "_")
        .replace(".", "_")
        .replace(" ", "_")
    )


def classify_form_field(
    field: WebFormInput,
) -> WorkflowFormFieldIntent:
    """Classify observed field metadata without accepting a field value."""

    name = field.name.strip()
    input_type = (
        field.input_type.strip().lower()
        or "text"
    )
    normalized_name = _normalized_field_name(name)

    if (
        input_type == "password"
        or normalized_name in _CREDENTIAL_NAMES
    ):
        field_class = WorkflowFieldClass.CREDENTIAL
    elif any(
        marker in normalized_name
        for marker in _ANTI_CSRF_MARKERS
    ):
        field_class = WorkflowFieldClass.ANTI_CSRF
    elif any(
        marker in normalized_name
        for marker in _SESSION_MARKERS
    ):
        field_class = WorkflowFieldClass.SESSION_TOKEN
    elif input_type == "hidden":
        field_class = WorkflowFieldClass.HIDDEN
    else:
        field_class = WorkflowFieldClass.ORDINARY

    sensitive = field_class in {
        WorkflowFieldClass.CREDENTIAL,
        WorkflowFieldClass.ANTI_CSRF,
        WorkflowFieldClass.SESSION_TOKEN,
    }

    return WorkflowFormFieldIntent(
        name=name,
        input_type=input_type,
        field_class=field_class,
        sensitive=sensitive,
        value_retained=False,
    )


def observe_form_intents(
    *,
    pages: tuple[CrawlPage, ...],
    origin: str,
) -> tuple[WorkflowFormIntent, ...]:
    """Convert captured form structure into passive workflow intent metadata."""

    normalized_origin = url_origin(origin)
    intents: list[WorkflowFormIntent] = []

    for page in pages:
        if page.error:
            continue

        try:
            source_url = normalize_http_url(
                page.url
            )
        except ValueError:
            continue

        if url_origin(source_url) != normalized_origin:
            continue

        for form in page.forms:
            action_url = ""
            same_origin = False

            if form.action:
                try:
                    action_url = normalize_http_url(
                        form.action
                    )
                    same_origin = (
                        url_origin(action_url)
                        == normalized_origin
                    )
                except ValueError:
                    action_url = ""

            intents.append(
                WorkflowFormIntent(
                    source_url=source_url,
                    action_url=action_url,
                    method=(
                        form.method.strip().upper()
                        or "GET"
                    ),
                    action_same_origin=same_origin,
                    fields=tuple(
                        classify_form_field(field)
                        for field in form.inputs
                    ),
                    submission_enabled=False,
                )
            )

    return tuple(intents)
