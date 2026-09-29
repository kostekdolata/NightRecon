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

## Planned follow-on batches

1. Isolated worker and revocation boundary for approved validation execution.
2. Cleanup/evidence lifecycle and deterministic retest integration.
3. Reviewed ATT&CK mappings and controlled comparison labs.

Higher-impact techniques remain out of scope until the isolation, approval,
cleanup, and revocation boundaries are independently verified.
