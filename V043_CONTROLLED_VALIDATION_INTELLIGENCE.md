# v0.43.0 Controlled Validation Intelligence

Red Night v0.43 starts from the verified v0.42.0 Cross-Domain Exposure
Intelligence release and develops reviewed controlled-validation coverage
without weakening the existing authorization boundary.

The milestone goal is to turn proposal-only attack-path candidates into
explicitly reviewed, bounded validation plans whose execution remains separate,
operator-authorized, approval-aware, auditable, and fail-closed.

## Batch 1 — Reviewed Technique Registry

Batch 1 adds a metadata-only controlled-validation technique registry.

The registry contains only symbolic review metadata:

- canonical technique ID
- title and short summary
- supported target kinds
- expected non-secret evidence keys
- impact classification
- approval requirement
- optional ATT&CK technique identifiers
- fixed adapter kind
- cleanup mode

It intentionally contains no:

- command text
- shell or script content
- exploit payloads
- credential material
- arbitrary request templates
- automatic execution hooks

The initial built-in entries are limited to read-only proof categories for TCP
service properties, TLS transport properties, and HTTP response-policy
metadata. No built-in ATT&CK mapping is asserted until each mapping is reviewed.

The registry can deterministically produce the existing
`ValidationDefinition` object for a selected technique and explicit target.
That bridge does not call an adapter or consume authorization state.

## Safety invariants

Batch 1 preserves the existing controlled-validation guarantees:

- authorization remains `validation.run`
- workspace scope, time window, action budget, revocation, and approval remain
  authoritative
- high-impact metadata cannot omit an approval requirement
- secret-like evidence keys are rejected
- unknown target kinds and unknown techniques fail closed
- only the symbolic `read-only-proof` adapter kind is accepted
- cleanup mode is fixed to `none` for the initial read-only catalog
- registry presence is not permission to execute

## Batch 2 — Exact candidate-to-technique eligibility planning

Batch 2 connects proposal-only v0.42 validation candidates to the reviewed
Batch 1 technique registry without choosing or executing a technique.

Each technique now separates:

- expected validation output evidence keys
- exact graph-property presence required for eligibility
- exact graph-property values required for eligibility

The planner verifies the candidate path, edge sequence, evidence IDs,
observed/inferred hop counts, proposal-only execution mode, review gates, and
`validation.run` capability against the current immutable graph before
considering any technique.

Target classification is exact and fail-closed:

- assets remain `asset` targets
- network services require canonical IP, canonical TCP port, and
  `protocol=tcp`
- web/API surfaces require canonical origin host/port, HTTP(S) scheme, and the
  explicit surface type
- unsupported surface types or malformed target evidence are not eligible

The planner emits every matching candidate/technique/target option in
deterministic order. It never ranks, recommends, or automatically selects one.
Missing exact target kinds and missing evidence prerequisites are returned as
explicit rejections.

## Batch 3 — Explicit adapter + precondition/postcondition contracts

Batch 3 adds immutable metadata-only adapter contracts for each reviewed
technique. The contract registry contains no adapter callables and exposes no
execution entry point.

Each contract binds:

- one reviewed technique ID
- the fixed `read-only-proof` adapter classification
- exact supported target kinds
- graph-property preconditions derived from reviewed eligibility metadata
- top-level evidence postconditions derived from reviewed expected evidence
- `side_effect_mode=none`
- `execution_mode=contract-only`

An eligibility option can be explicitly bound to its reviewed contract only
after the current graph target, target classification, provenance,
eligibility identifier, technique metadata, and preconditions are revalidated.
Contract drift or stale target evidence fails closed.

Postcondition checking is also pure and non-executing:

- confirmed observations must contain every contract evidence key
- unexpected top-level evidence keys are rejected
- not-confirmed observations may be partial, but may not introduce evidence
  outside the reviewed contract

Batch 3 does not register callable adapters, invoke the existing validation
runtime, consume authorization or action budgets, perform network activity,
resolve credentials, or introduce command/payload templates.

## Batch 4 — Isolated revocable worker execution boundary

Batch 4 is the first v0.43 layer that can perform a live validation action.
Execution is intentionally limited to the three already-reviewed
`read-only-proof` techniques:

- bounded TCP connection property proof
- bounded TLS transport/certificate-fingerprint proof
- bounded HTTP HEAD response-policy proof

The operator must explicitly select the exact Batch 3 binding ID. The parent
process revalidates the current graph binding and then performs the canonical
`validation.run` authorization with `consume=True`. Exactly one engagement
action is therefore reserved before any child worker starts.

Each action runs in a fresh spawned child process that receives only a minimal
typed request containing the reviewed technique ID and bounded target metadata.
The child receives no workspace handle, authorization store, credentials,
generic command text, script/payload surface, or arbitrary HTTP request
template.

While the child runs, the parent reloads the workspace policy from disk and
re-evaluates the already-reserved action without consuming another budget slot.
A revoked authorization, inactive engagement, expired/not-yet-valid window,
removed capability, scope change, approval loss, policy-budget inconsistency,
or lease recheck failure causes fail-closed worker termination.

Hard worker limits include:

- one reserved engagement action per invocation
- fresh spawned process per action
- maximum 15-second worker runtime
- maximum 5-second adapter I/O timeout
- bounded policy recheck interval
- maximum 64 KiB serialized result ceiling
- Batch 3 postcondition validation before evidence is accepted

The HTTP adapter is fixed to `HEAD /`, requests no response body, follows no
redirects, and reports only status code plus an allowlisted set of security
header names. The TLS adapter performs no authentication and confirms only an
exact pre-observed certificate SHA-256 fingerprint; certificate-chain trust is
not asserted by that proof.

Batch 4 still provides no arbitrary command execution, shell, PowerShell, SQL,
generic HTTP request builder, credential handling, exploit payload, persistence,
privilege change, automatic technique selection, or high-impact technique.

## Planned follow-on batches

1. Cleanup/evidence lifecycle and deterministic retest integration.
2. Reviewed ATT&CK mappings and controlled comparison labs.

Higher-impact techniques remain out of scope until the isolation, approval,
cleanup, and revocation boundaries are independently verified.
