# v0.42.0 Unified Exposure Intelligence

Red Night v0.42 development begins the transition from parallel specialist
modules into one evidence-correlated red-team operating system.

The milestone goal is to connect network, web/API, identity, cloud/hybrid,
vulnerability, validation, critical-asset, remediation, and retest evidence in
one deterministic graph without turning graph reachability into an
exploitability verdict.

## Batch 1 — Exact cross-surface correlation

The first batch adds a deterministic network/identity correlation layer.

Current production-backed correlation evidence is:

- network asset hostnames observed in the asset inventory
- Active Directory computer `dNSHostName`
- host components extracted from observed Active Directory SPNs

Directory correlation properties are explicitly allowlisted to:

- `dns_hostname`
- `spn_hosts`

No generic provider-property channel is introduced.

## Correlation rule

A correlation edge is created only when one normalized identity hostname maps
to exactly one observed network asset hostname.

The resulting edge is:

- relationship: `correlates-to`
- evidence state: `inferred`
- claim: `exact-evidence-correlation-only`
- basis: `exact-hostname`

Human-readable labels are never used as join keys.

The correlator does not:

- perform DNS resolution
- use fuzzy matching
- use suffix similarity
- infer from display names
- infer from IP adjacency
- infer exploitability or compromise

## Ambiguity and incomplete evidence

If an exact identity hostname has no matching asset, Red Night returns an
explicit unresolved correlation with reason:

`no-exact-asset-hostname-match`

If more than one asset carries the same exact hostname, no graph edge is
created. Red Night returns:

`ambiguous-asset-hostname`

The unresolved result contains the opaque identity key, candidate count, and a
SHA-256 of the normalized correlation key. It does not expose the hostname
through the unresolved metadata.

## Determinism and budgets

Multiple exact hostname proofs between the same identity and asset collapse into
one deterministic correlation edge with a `matched_key_count`.

The correlator has hard ceilings for:

- generated correlation edges
- unresolved correlation records

Over-budget correlation fails closed.

Identical graph inputs produce identical correlation edges and unresolved results.

## Graph integration

The correlation layer is available through both graph assembly paths:

- `build_correlated_identity_graph(...)`
- `build_correlated_unified_attack_graph(...)`

The portable unified graph now preserves bounded node properties from engagement
evidence so exact correlation keys survive workspace storage and reload.

Existing non-correlated graph builders remain available and keep their previous
behavior.

## Safety and interpretation

Cross-surface correlation is evidence linkage only.

An inferred `correlates-to` edge means that two independently observed facts
share an exact normalized correlation key under the defined rule. It does not
mean the identity can authenticate to the asset, the asset is compromised, a
vulnerability is exploitable, lateral movement is possible, or a privilege
path is validated.

## Next v0.42 batches

1. exact web/API origin-to-network-service correlation
2. concrete cloud resource correlation keys and cloud-to-network/identity joins
3. critical-asset exposure paths spanning identity + network + web/API + cloud
4. evidence-chain explanations for every cross-surface path
5. descriptive choke-point and blast-radius analysis
6. operator-facing unified exposure review
7. remediation/retest impact on exposure paths
8. performance and specialist comparison labs
