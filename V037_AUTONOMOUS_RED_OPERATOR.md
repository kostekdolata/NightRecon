# v0.37.0 Autonomous Red Operator

The v0.37 operator is deliberately plan-only.

A planning agent may propose only a capability identifier, target, rationale,
and approval-present flag. It cannot return shell commands, scripts, payloads,
or execution callbacks. The plan compiler accepts only capabilities in a fixed
catalog and evaluates every proposal against the engagement status, scope,
validity window, capability allowlist, approval rules, and action budget.

Planning uses consume=False, so generating or reviewing a plan cannot spend the
engagement action budget. Allowed steps still require a separate guarded
execution decision. Unknown, out-of-scope, expired, revoked, or unapproved steps
remain visible as blocked steps with deterministic reason codes.
