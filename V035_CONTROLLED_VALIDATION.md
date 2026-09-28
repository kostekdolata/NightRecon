# v0.35.0 Controlled Validation

Red Night v0.35 introduces a deterministic validation runtime for proving
security conditions without embedding exploit payloads.

A validation definition names the target, impact, and proof objective. The
shared engagement policy authorizes the target/capability, enforces the time
window and action budget, and requires approval for high-impact activity before
an adapter can run. Denied validations never call the adapter.

Adapters return secret-free structured observations. The runtime records one of
four states: denied, confirmed, not-confirmed, or error. Adapter exceptions are
sanitized and never become exploitability claims.

Concrete proof adapters can now be added behind this contract while preserving
the same authorization, approval, budget, and evidence rules.
