# v0.42.0 Unified Exposure Intelligence

Red Night v0.42 is the transition from parallel specialist modules into one
evidence-correlated red-team operating system.

The milestone connects network, web/API, identity, cloud/hybrid, vulnerability,
validation, critical-asset, remediation, and retest evidence without turning
graph reachability into an exploitability or risk verdict.

## Batch 1 — Cross-Domain Attack Path Atlas

Batch 1 introduced bounded deterministic traversal over the unified engagement
graph. It preserves observed/inferred hop counts, supporting evidence IDs,
structural participation, global exploration budgets, and explicit truncation.

See [V042_ATTACK_PATH_ATLAS.md](V042_ATTACK_PATH_ATLAS.md).

## Batch 2 — Exact AD identity to network correlation

Batch 2 added deterministic identity/network correlation using:

- network asset hostnames observed in the asset inventory
- Active Directory computer `dNSHostName`
- host components extracted from observed Active Directory SPNs

Directory correlation properties are strictly allowlisted to:

- `dns_hostname`
- `spn_hosts`

One normalized identity hostname must map to exactly one observed network asset
hostname before Red Night creates an inferred `correlates-to` edge.

Zero matches and ambiguous matches remain explicit unresolved correlation
records. Human-readable labels are never join keys.

## Batch 3 — Exact web/API origin to network-service correlation

Batch 3 projects HTTP(S) surfaces as observation-scoped service nodes from:

- bounded web-crawl reports
- passive OpenAPI inventory reports
- GraphQL schema reports

Each web-surface observation carries only normalized correlation metadata:

- `surface_type` — `web`, `api`, or `graphql`
- `origin_scheme` — `http` or `https`
- `origin_host`
- `origin_port` — explicit port or normalized default 80/443

Surface natural keys contain opaque hashes of the origin and evidence source;
session/source identifiers are not exposed in the key.

### Origin correlation rule

A web/API surface is correlated only when:

1. the origin host is an exact match for one observed asset hostname, or the
   origin is an IP literal exactly matching one observed asset address;
2. that asset is unique for the origin host;
3. the asset has exactly one observed TCP service on the origin port.

The resulting inferred edge is directed:

`observed network service -> web/API surface`

with:

- relationship: `correlates-to`
- evidence state: `inferred`
- claim: `exact-evidence-correlation-only`
- basis: `exact-origin-host-port`

This direction lets the attack-path atlas traverse naturally from an exposed
asset/service into its observed application/API surface.

The scheme is preserved as evidence but is not used to invent a service
protocol. Red Night requires an observed TCP service on the exact port.

### Incomplete and ambiguous web correlation

Red Night creates no edge when evidence is incomplete or ambiguous. Reasons
include:

- `no-exact-origin-asset-match`
- `ambiguous-origin-asset`
- `no-exact-origin-service-match`
- `ambiguous-origin-service`

Unresolved correlation records retain an opaque source key, candidate count,
and SHA-256 of the correlation material. They do not expose the hostname.

## Shared correlation guarantees

The correlation engine never:

- performs DNS resolution
- performs network activity
- uses fuzzy matching
- uses suffix similarity
- joins on display labels
- infers from IP adjacency
- treats a service name as proof of HTTP(S)
- claims authentication access
- claims compromise, exploitability, or lateral movement

Multiple exact proofs for one source/target pair collapse deterministically.
Generated edges and unresolved records have hard ceilings; over-budget work
fails closed.

The correlation layer is available through both graph assembly paths:

- `build_correlated_identity_graph(...)`
- `build_correlated_unified_attack_graph(...)`

The portable unified graph preserves bounded node properties from engagement
evidence so correlation metadata survives workspace storage and reload.

## Deterministic runtime benchmark

`tests/cross_surface_correlation_runtime.py` proves the combined evidence chain
without network access:

`AD identity -> network asset -> observed TCP service -> web/API surfaces`

The benchmark runs on Python 3.11 and 3.14 and verifies:

- one exact AD identity-to-asset correlation
- exact network-service-to-web correlation
- exact network-service-to-API correlation
- observed vs inferred edge state
- zero unresolved correlations
- deterministic graph equality
- deterministic graph SHA-256 fingerprint

## Safety and interpretation

An inferred `correlates-to` edge means two independently observed facts share
the exact normalized evidence required by a documented correlation rule.

It does not establish exploitability, likelihood, impact, compromise,
authentication access, or a validated attack path. Those require separate
evidence or controlled validation.

## Next v0.42 batches

1. concrete AWS/Azure/Kubernetes correlation keys and cloud-to-network/identity joins
2. bounded controlled-validation candidates compiled from evidence-backed paths
3. evidence-chain explanations and unified operator exposure review
4. descriptive choke-point and blast-radius analysis
5. remediation/retest impact on exposure paths
6. reproducible specialist comparison labs
