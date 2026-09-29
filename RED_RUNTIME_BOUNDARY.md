# Red Night Runtime Boundary

This document records the stable v0.42.0 Red Night package boundary.

## Current package boundary

Red Night is independently installable through three coordinated distributions:

- `nightrecon-red-night==0.42.0` — application launcher and Red command surface
- `nightrecon-red-engine==0.42.0` — Red-owned assessment, evidence, graph,
  validation, planning, remediation, checks, identity, and cloud/hybrid logic
- `nightrecon-shared-core==0.42.0` — mandatory network-free authorization,
  edition policy, evidence contracts, engagement policy, storage, and workspace
  coordination

The standalone Red application does not require the legacy
`nightrecon==0.31.0` package. The legacy package remains an explicit
compatibility distribution and depends on the stable Red engine/shared core
during the migration window.

The standalone launcher path is:

`red-night-app -> red_night_app.main -> nightrecon_red_engine.red_cli.main`

The legacy compatibility launcher remains:

`red-night -> legacy compatibility CLI -> Red engine/shared-core boundaries`

Both paths preserve fail-closed command ownership, target scope, authorization
windows, action budgets, approval requirements, and non-secret audit evidence.

## Shared core ownership

The independently installable, network-free shared core is canonical for:

- Night identity and fail-closed command ownership policy
- target parsing and explicit scope authorization
- engagement status, validity windows, capability allowlists, approval rules,
  action budgets, revocation, and authorization audit
- versioned secret-free evidence records and engagement envelopes
- engagement coordination metadata
- backend-neutral engagement-store semantics
- deterministic local storage and workspace coordination
- portable import/export contracts

Evidence or metadata imported from another Night is coordination context only.
It never grants authorization for active activity.

## Red engine ownership

The Red engine owns the Red assessment/runtime surface used by the standalone
application, including the migrated discovery/service foundations plus the
v0.33-v0.42 engagement, live Active Directory and Microsoft Entra identity,
identity benchmark/operator, controlled-validation, graph, planning,
remediation/retest, check-ecosystem, and cloud/hybrid boundaries.

The stable v0.42 package boundary does not imply unrestricted offensive
execution. The current operator is plan-only, validation adapters are
capability-gated, and the release does not add exploit payloads, credential
harvesting, arbitrary command execution, cloud writes, persistence, privilege
changes, or autonomous execution.

## Standalone and compatibility verification

CI builds the Red application, Red engine, shared core, and legacy compatibility
wheel separately. It verifies:

1. isolated Red installation without the legacy `nightrecon` package
2. combined Red + legacy installation
3. uninstall separation between `red-night-app` and `red-night`
4. stable package metadata and dependency pins
5. cross-platform Python 3.11 and 3.14 Red distribution smoke tests
6. the full NightRecon test matrix and specialist runtime compatibility jobs

## Remaining boundary work

The compatibility window remains open while the legacy NightRecon distribution
continues to exist. Future package work should remove only proven compatibility
seams and must not rewrite stable Red engines merely for namespace purity.

Every later extraction or composition batch must preserve:

- shared-core authorization as authoritative
- fail-closed Red command ownership
- standalone Red installation
- no Night-to-Night runtime dependency
- deterministic versioned evidence/workspace contracts
- secret non-retention
- existing negative-authorization and distribution smoke coverage
