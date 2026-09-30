# v0.43.0 Controlled Validation Intelligence

Status: released, tagged, and verified stable.

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

## Batch 5 — Cleanup / evidence lifecycle + deterministic retest integration

Batch 5 makes Batch 4 worker outcomes durable before they can affect
remediation state.

Every bounded worker result is normalized into a deterministic portable
`validation.worker-result` evidence record containing the exact reviewed
binding, candidate/path context, contract, target, terminal worker state,
reason, bounded evidence, and action-budget counters. Ephemeral worker process
IDs are intentionally not persisted.

Each validation record is paired with a deterministic `validation.cleanup`
record. The current reviewed techniques all declare `cleanup_mode=none` and
`side_effect_mode=none`, so the only accepted cleanup outcome in this batch is
`cleanup_state=not-required` with zero cleanup actions. A forged or future
side-effecting binding fails closed until a reviewed cleanup implementation
exists.

Validation and cleanup records are written together through the shared
engagement store. Replaying the same lifecycle at the same observation time is
idempotent: identical evidence IDs are recognized rather than duplicated, while
conflicting evidence fails closed.

Remediation/retest transitions now support exact persisted-evidence linkage:

- `not-confirmed` validation evidence + completed/no-op cleanup -> `verified`
- `confirmed` validation evidence + completed/no-op cleanup -> `regressed`
- denied, revoked, timed-out, contract-rejected, or error evidence -> inconclusive
  and remains `ready-for-retest`

The remediation record retains the exact validation evidence ID, cleanup
evidence ID, cleanup state, binding ID, and terminal validation state. Retest
integration refuses lifecycle objects that are not present byte-for-byte in the
engagement workspace.

Batch 5 introduces no additional live validation technique, no cleanup mutation,
no credential handling, and no expansion of the Batch 4 worker network surface.

## Batch 6 — Reviewed ATT&CK mappings + controlled comparison labs

Batch 6 reviews every current controlled-validation technique against MITRE
ATT&CK without turning ATT&CK IDs into an equivalence claim.

The bounded TCP service proof is recorded as **related** to Enterprise ATT&CK
T1046 Network Service Discovery. The review uses the official MITRE ATT&CK
T1046 reference (version 3.2, last modified 2026-05-12). The relationship is
deliberately narrow: NightRecon confirms one already-selected TCP service; it
does not enumerate a host/range or claim to implement the complete T1046
adversary technique.

The TLS transport/fingerprint proof and HTTP response-policy proof are explicitly
marked **reviewed-unmapped**. Their current behavior validates already-observed
transport/application evidence and is not force-fit to an ATT&CK adversary
technique.

A deterministic validation comparison lab now measures explicit fixture
expectations across durable Batch 5 lifecycle records:

- expected, matched, missed, and invented validation scenarios
- exact terminal state and evidence-key shape
- explicit cleanup completion state
- reviewed ATT&CK relationship disposition and IDs
- operator step count
- runtime reported separately
- deterministic SHA-256 comparison fingerprint excluding runtime

The lab validates the durable lifecycle records before measurement and refuses
duplicate actual scenarios. Its result explicitly states that fixture matching
does not establish parity or operational equivalence with ATT&CK, Caldera,
Metasploit, Cobalt Strike, or another specialist product.

Batch 6 adds no worker technique, network request, credential surface, payload,
cleanup mutation, automatic technique selection, or high-impact behavior.

## Release acceptance

The six-batch v0.43 train is release-complete. Stable release acceptance requires
coordinated 0.43.0 package metadata, the integrated deterministic v0.43 release
acceptance test, the full cross-platform CI/runtime/distribution matrix on the
exact finalization head, a verified merge commit on `master`, and guarded
annotated tag creation.

No additional execution power is introduced by release finalization. Live
authorized specialist-product comparisons remain broader Red acceptance work
where external evidence has not yet been collected. Higher-impact techniques
remain out of scope until the isolation, approval, cleanup, and revocation
boundaries are independently verified for those techniques.
