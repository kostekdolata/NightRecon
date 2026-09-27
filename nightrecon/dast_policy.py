"""Safety policy and deterministic request budgeting for NightRecon DAST."""

from __future__ import annotations

from dataclasses import dataclass


_SAFE_ACTIVE_METHODS = frozenset(
    {
        "GET",
        "HEAD",
        "OPTIONS",
    }
)


@dataclass(frozen=True)
class DastCheckDefinition:
    """Static safe-active metadata for one deterministic DAST check."""

    check_id: str
    name: str
    family: str
    description: str
    max_requests: int
    allowed_methods: tuple[str, ...] = (
        "GET",
        "HEAD",
    )
    tags: tuple[str, ...] = ()
    requires_authentication: bool = False
    version: str = "1"

    def __post_init__(self) -> None:
        if not self.check_id.strip():
            raise ValueError(
                "check_id must not be empty."
            )

        if not self.name.strip():
            raise ValueError(
                "name must not be empty."
            )

        if not self.family.strip():
            raise ValueError(
                "family must not be empty."
            )

        if self.max_requests < 1:
            raise ValueError(
                "max_requests must be at least 1."
            )

        methods = tuple(
            dict.fromkeys(
                method.strip().upper()
                for method in self.allowed_methods
                if isinstance(
                    method,
                    str,
                )
                and method.strip()
            )
        )

        if not methods:
            raise ValueError(
                "allowed_methods must include at least one HTTP method."
            )

        unsafe_methods = tuple(
            method
            for method in methods
            if method not in _SAFE_ACTIVE_METHODS
        )

        if unsafe_methods:
            raise ValueError(
                "Safe-active DAST checks may use only GET, HEAD, or OPTIONS."
            )

        object.__setattr__(
            self,
            "allowed_methods",
            methods,
        )


@dataclass(frozen=True)
class DastBudgetPolicy:
    """Global and family-level request ceilings for one DAST run."""

    max_total_requests: int = 50
    default_family_requests: int = 10
    family_limits: tuple[
        tuple[str, int],
        ...,
    ] = ()

    def __post_init__(self) -> None:
        if self.max_total_requests < 1:
            raise ValueError(
                "max_total_requests must be at least 1."
            )

        if self.default_family_requests < 1:
            raise ValueError(
                "default_family_requests must be at least 1."
            )

        normalized: dict[
            str,
            int,
        ] = {}

        for family, limit in self.family_limits:
            name = family.strip()

            if not name:
                raise ValueError(
                    "family limit names must not be empty."
                )

            if limit < 1:
                raise ValueError(
                    "family request limits must be at least 1."
                )

            if name in normalized:
                raise ValueError(
                    f"Duplicate family request limit: {name}"
                )

            normalized[
                name
            ] = limit

        object.__setattr__(
            self,
            "family_limits",
            tuple(
                sorted(
                    normalized.items()
                )
            ),
        )

    def family_limit(
        self,
        family: str,
    ) -> int:
        limits = dict(
            self.family_limits
        )

        return limits.get(
            family,
            self.default_family_requests,
        )


@dataclass(frozen=True)
class DastBudgetState:
    """Immutable request accounting across a DAST run."""

    total_used: int = 0
    check_usage: tuple[
        tuple[str, int],
        ...,
    ] = ()
    family_usage: tuple[
        tuple[str, int],
        ...,
    ] = ()

    def __post_init__(self) -> None:
        if self.total_used < 0:
            raise ValueError(
                "total_used cannot be negative."
            )

        for label, usage in (
            *self.check_usage,
            *self.family_usage,
        ):
            if not label.strip():
                raise ValueError(
                    "budget usage labels must not be empty."
                )

            if usage < 0:
                raise ValueError(
                    "budget usage cannot be negative."
                )


@dataclass(frozen=True)
class DastBudgetDecision:
    """Pre-request budget authorization result."""

    allowed: bool
    reason: str
    check_id: str
    family: str
    method: str
    total_used: int
    check_used: int
    family_used: int
    total_limit: int
    check_limit: int
    family_limit: int


def _usage(
    entries: tuple[
        tuple[str, int],
        ...,
    ],
    key: str,
) -> int:
    return dict(
        entries
    ).get(
        key,
        0,
    )


def authorize_dast_request(
    *,
    check: DastCheckDefinition,
    method: str,
    policy: DastBudgetPolicy,
    state: DastBudgetState,
) -> DastBudgetDecision:
    """Authorize one safe-active DAST request before network execution."""

    normalized_method = method.strip().upper()

    if not normalized_method:
        raise ValueError(
            "method must not be empty."
        )

    check_used = _usage(
        state.check_usage,
        check.check_id,
    )
    family_used = _usage(
        state.family_usage,
        check.family,
    )
    family_limit = policy.family_limit(
        check.family
    )

    def decision(
        allowed: bool,
        reason: str,
    ) -> DastBudgetDecision:
        return DastBudgetDecision(
            allowed=allowed,
            reason=reason,
            check_id=check.check_id,
            family=check.family,
            method=normalized_method,
            total_used=state.total_used,
            check_used=check_used,
            family_used=family_used,
            total_limit=policy.max_total_requests,
            check_limit=check.max_requests,
            family_limit=family_limit,
        )

    if normalized_method not in check.allowed_methods:
        return decision(
            False,
            "method_not_allowed",
        )

    if state.total_used >= policy.max_total_requests:
        return decision(
            False,
            "total_request_budget_exhausted",
        )

    if check_used >= check.max_requests:
        return decision(
            False,
            "check_request_budget_exhausted",
        )

    if family_used >= family_limit:
        return decision(
            False,
            "family_request_budget_exhausted",
        )

    return decision(
        True,
        "authorized",
    )


def reserve_dast_request(
    *,
    state: DastBudgetState,
    decision: DastBudgetDecision,
) -> DastBudgetState:
    """Reserve one request slot after an allowed DAST decision."""

    if not decision.allowed:
        raise PermissionError(
            f"DAST request denied: {decision.reason}"
        )

    if state.total_used != decision.total_used:
        raise PermissionError(
            "DAST budget decision is stale for total request usage."
        )

    check_usage = dict(
        state.check_usage
    )
    family_usage = dict(
        state.family_usage
    )

    current_check = check_usage.get(
        decision.check_id,
        0,
    )
    current_family = family_usage.get(
        decision.family,
        0,
    )

    if current_check != decision.check_used:
        raise PermissionError(
            "DAST budget decision is stale for check usage."
        )

    if current_family != decision.family_used:
        raise PermissionError(
            "DAST budget decision is stale for family usage."
        )

    if state.total_used >= decision.total_limit:
        raise PermissionError(
            "DAST total request budget is exhausted."
        )

    if current_check >= decision.check_limit:
        raise PermissionError(
            "DAST check request budget is exhausted."
        )

    if current_family >= decision.family_limit:
        raise PermissionError(
            "DAST family request budget is exhausted."
        )

    check_usage[
        decision.check_id
    ] = current_check + 1
    family_usage[
        decision.family
    ] = current_family + 1

    return DastBudgetState(
        total_used=state.total_used + 1,
        check_usage=tuple(
            sorted(
                check_usage.items()
            )
        ),
        family_usage=tuple(
            sorted(
                family_usage.items()
            )
        ),
    )
