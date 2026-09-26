"""Explicit policy gate for bounded NightRecon form submission.

This module authorizes form intent metadata only. It accepts field names, never
field values, performs no network activity, and defaults to deny.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from nightrecon.web_crawl import (
    normalize_http_url,
    url_origin,
)
from nightrecon.web_form_intent import (
    WorkflowFieldClass,
    WorkflowFormIntent,
)


_DEFAULT_DENIED_ACTION_MARKERS = (
    "logout",
    "delete",
    "remove",
    "destroy",
    "revoke",
    "change-password",
    "change_password",
    "reset-password",
    "reset_password",
)


@dataclass(frozen=True)
class FormSubmissionPolicy:
    """Explicit allowlist policy for future form submission execution."""

    origin: str
    enabled: bool = False
    max_submissions: int = 1
    allowed_methods: tuple[str, ...] = ("POST",)
    allowed_fields: tuple[str, ...] = ()
    allowed_sensitive_classes: tuple[WorkflowFieldClass, ...] = ()
    allow_destructive_actions: bool = False
    denied_action_markers: tuple[str, ...] = _DEFAULT_DENIED_ACTION_MARKERS

    def __post_init__(self) -> None:
        normalized_origin = url_origin(self.origin)

        if self.max_submissions < 1:
            raise ValueError(
                "max_submissions must be at least 1."
            )

        methods = tuple(
            method.strip().upper()
            for method in self.allowed_methods
            if isinstance(method, str) and method.strip()
        )

        if not methods:
            raise ValueError(
                "allowed_methods must include at least one HTTP method."
            )

        fields = tuple(
            dict.fromkeys(
                field.strip()
                for field in self.allowed_fields
                if isinstance(field, str) and field.strip()
            )
        )

        sensitive_classes = tuple(
            dict.fromkeys(
                value
                for value in self.allowed_sensitive_classes
                if isinstance(value, WorkflowFieldClass)
            )
        )

        markers = tuple(
            marker.strip().lower()
            for marker in self.denied_action_markers
            if isinstance(marker, str) and marker.strip()
        )

        object.__setattr__(
            self,
            "origin",
            normalized_origin,
        )
        object.__setattr__(
            self,
            "allowed_methods",
            methods,
        )
        object.__setattr__(
            self,
            "allowed_fields",
            fields,
        )
        object.__setattr__(
            self,
            "allowed_sensitive_classes",
            sensitive_classes,
        )
        object.__setattr__(
            self,
            "denied_action_markers",
            markers,
        )


@dataclass(frozen=True)
class FormSubmissionDecision:
    """Non-secret authorization result for one proposed form submission."""

    allowed: bool
    reason: str
    action_url: str
    method: str
    approved_fields: tuple[str, ...]
    submissions_used: int
    max_submissions: int


def authorize_form_submission(
    *,
    intent: WorkflowFormIntent,
    policy: FormSubmissionPolicy,
    provided_field_names: tuple[str, ...],
    submissions_used: int,
) -> FormSubmissionDecision:
    """Authorize form metadata without accepting or retaining field values."""

    if submissions_used < 0:
        raise ValueError(
            "submissions_used cannot be negative."
        )

    method = intent.method.strip().upper()
    action_url = ""

    if intent.action_url:
        action_url = normalize_http_url(
            intent.action_url
        )

    def deny(reason: str) -> FormSubmissionDecision:
        return FormSubmissionDecision(
            allowed=False,
            reason=reason,
            action_url=action_url,
            method=method,
            approved_fields=(),
            submissions_used=submissions_used,
            max_submissions=policy.max_submissions,
        )

    if not policy.enabled:
        return deny(
            "form_submission_not_enabled"
        )

    if submissions_used >= policy.max_submissions:
        return deny(
            "form_submission_budget_exhausted"
        )

    if not action_url or not intent.action_same_origin:
        return deny(
            "form_action_not_same_origin"
        )

    if url_origin(action_url) != policy.origin:
        return deny(
            "form_action_not_same_origin"
        )

    if method not in policy.allowed_methods:
        return deny(
            "form_method_not_allowed"
        )

    action_path = urlsplit(
        action_url
    ).path.lower()

    if (
        not policy.allow_destructive_actions
        and any(
            marker in action_path
            for marker in policy.denied_action_markers
        )
    ):
        return deny(
            "destructive_form_action_blocked"
        )

    field_by_name = {
        field.name: field
        for field in intent.fields
        if field.name
    }
    requested_names = tuple(
        dict.fromkeys(
            name.strip()
            for name in provided_field_names
            if isinstance(name, str) and name.strip()
        )
    )

    if not requested_names:
        return deny(
            "no_form_fields_approved"
        )

    for name in requested_names:
        field = field_by_name.get(name)

        if field is None:
            return deny(
                "unknown_form_field"
            )

        if name not in policy.allowed_fields:
            return deny(
                "form_field_not_allowlisted"
            )

        if (
            field.sensitive
            and field.field_class
            not in policy.allowed_sensitive_classes
        ):
            return deny(
                "sensitive_form_field_not_allowed"
            )

    return FormSubmissionDecision(
        allowed=True,
        reason="authorized",
        action_url=action_url,
        method=method,
        approved_fields=requested_names,
        submissions_used=submissions_used,
        max_submissions=policy.max_submissions,
    )
