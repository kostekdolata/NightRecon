# White Night Package Boundary Plan

This plan creates White Night as a separately installable NightRecon application
without creating a USB-only fork or a mandatory dependency for the other Nights.

White Night is the second standalone NightRecon product track after Red Night.

## Target distributions

White Night should use the same separation pattern proven by Red Night:

- `nightrecon-white-night` — application launcher/presentation package;
- `nightrecon-white-engine` — White-owned engagement/exercise domain;
- `nightrecon-shared-core` — mandatory Night-neutral safety and contract layer.

Proposed dependency direction:

`white-night -> white-engine -> shared-core`

White Night must not depend on Red, Blue, Purple, or Black engine packages.

A composed full-stack installation installs multiple Night applications and
engines beside the same compatible shared core.

## One product, three required deployment profiles

White development must prove the same application/domain contracts in:

1. **Standalone installation**
   - White app + White engine + shared core;
   - no other Night required.

2. **Composed NightRecon stack**
   - White installed beside one or more other Nights;
   - shared engagement/workspace backend may be used;
   - removing White leaves other Night applications operational.

3. **White Night Live USB**
   - same White application and engine packages inside a bootable environment;
   - encrypted persistent workspace;
   - no Live-only fork of engagement, approval, evidence, or audit logic.

Later the same Live build system may produce White+Red or full-stack Live images
by changing included package sets, not by branching the White source.

## Proposed repository structure

```
packages/
  shared-core/
  red-engine/
  red-night/
  white-engine/
  white-night/

live/
  white-night/
    auto/
    config/
      package-lists/
      hooks/
      includes.chroot/
      bootloaders/
    branding/
    scripts/
    tests/
```

The exact Live directory shape may follow the selected Debian live-build
version, but Live configuration remains source-controlled and reproducible.

## Package responsibilities

### nightrecon-white-engine

Owns White Night business/domain behavior:

- engagement administration;
- ROE models and lifecycle;
- policy-management orchestration;
- approval workflows;
- evidence-custody workflows;
- audit-management workflows;
- exercise definitions and facilitator state;
- Mission Control projection/state;
- after-action and control-plane reporting;
- White-specific connector adapters.

It consumes shared-core enforcement/contracts instead of reimplementing them.

### nightrecon-white-night

Owns:

- CLI/application entry point;
- White user-facing presentation;
- deployment discovery;
- standalone versus composed workspace selection;
- White capability registration;
- configuration wiring.

It must not contain a second copy of the White domain engine.

### nightrecon-shared-core

Continues to own:

- scope and authorization enforcement;
- budgets;
- stop-state enforcement primitives;
- secret-safe shared types;
- evidence/engagement/event contracts;
- backend-neutral workspace interfaces;
- Night-neutral cryptographic verification primitives;
- edition/capability policy.

The shared core must remain usable by another Night without White installed.

## Storage abstraction

White application code must never assume a specific path such as a removable USB
mount.

White should depend on backend-neutral storage contracts.

Expected initial interfaces:

- `EngagementStore`
- `WorkspaceStore`
- `PolicyStore`
- `ApprovalStore`
- `EvidenceStore`
- `AuditStore`

The first implementation may extend the existing file-backed engagement/workspace
foundations where appropriate. Later backends may use SQLite, PostgreSQL, a
local service, or another implementation without changing White domain
semantics.

## Versioning

White app, White engine, and shared-core compatibility must be explicit.

The first White development release should not automatically force Red package
version numbers to move unless a shared-core contract actually changes.

If a shared-core contract changes, all consuming Night packages must declare
compatible ranges/versions and cross-package CI must prove the combination.

Cross-Night serialized contracts have independent schema versions and must not
use package version alone as their compatibility signal.

## Package-isolation acceptance

Before White is advertised as standalone:

- build White app, White engine, and shared-core wheels;
- install them in a clean environment with no legacy `nightrecon` monolith and
  no Red packages;
- run White CLI/application smoke tests;
- create and reopen an engagement;
- compile/validate a non-active policy example;
- write/read evidence and audit fixtures;
- uninstall White and prove shared core can remain where another consumer needs
  it.

## Composition acceptance

Before White is advertised as full-stack compatible:

- install White beside the stable Red application;
- prove both launch independently;
- prove both discover the same engagement only through shared contracts/backend;
- prove Red does not import White;
- prove White does not import Red engine modules;
- prove evidence imported from Red does not grant authorization;
- prove removing White does not break Red;
- prove removing Red does not break White;
- verify schema/version mismatch handling fails clearly and safely.

Future Blue/Purple/Black packages repeat the same contract tests.

## Live image packaging

The Live image consumes built White package artifacts.

The image build must not install White by copying arbitrary working-tree Python
source into the image. It should install the same versioned artifacts used by
normal installation wherever practical.

A full-stack Live image later installs:

```
nightrecon-shared-core
nightrecon-white-engine
nightrecon-white-night
nightrecon-red-engine
nightrecon-red-night
nightrecon-blue-engine
nightrecon-blue-night
nightrecon-purple-engine
nightrecon-purple-night
nightrecon-black-engine
nightrecon-black-night
```

Only packages that actually exist at that release are included.

## Development batches

### Batch A — documentation and contracts

- `WHITE_ACCEPTANCE.md`
- `WHITE_OWNERSHIP.md`
- `WHITE_PACKAGE_PLAN.md`
- `WHITE_LIVE_ARCHITECTURE.md`
- roadmap/edition updates.

No runtime behavior changes.

### Batch B — package skeleton

Status: implemented and PR-CI verified.

Delivered:

- White engine/application namespaces and version metadata;
- `white-night-app` informational entry point;
- explicit foundation capability/command registration;
- zero active commands;
- package-boundary unit tests;
- isolated wheel/install/uninstall distribution smoke;
- dedicated four-platform/runtime White distribution CI matrix.

### Batch C — engagement domain

Status: implemented and PR-CI verified.

Delivered immutable/versioned:

- engagement definitions and revisions;
- authorized contacts and bounded roles;
- normalized scope/exclusions with fail-closed CIDR overlap handling;
- timezone-aware testing/exercise windows;
- action classes, techniques, intrusiveness and action budgets;
- production/test/cyber-range environment classification;
- retention/data-handling policy;
- deterministic JSON and SHA-256 definition fingerprints;
- human-readable ROE rendered from the same source definition.

No other Night runtime is required, and the domain remains non-authoritative for
execution until Batch D compiles it through shared-core policy primitives.

### Batch D — policy compiler

Add deterministic ROE-to-policy compilation using shared-core policy primitives.

Negative tests must prove compilation cannot silently broaden scope.

### Batch E — approvals

Add approval requests, eligibility, dual/quorum rules, expiry, revocation,
delegation, and immutable decisions.

### Batch F — evidence and audit

Add evidence custody, integrity manifests, append-only logical audit, export, and
verification.

### Batch G — Live alpha

Produce the first bootable White Night image using the same package artifacts,
with encrypted persistent workspace and ephemeral mode.

### Batch H — exercise and Mission Control

Add scenario/inject/facilitator workflows and integrated engagement state.

### Batch I — Red composition

Wire versioned White/Red event and evidence exchange without cross-imports.

### Batch J — hardened release

Add professional reports, migration tests, Live recovery/update flows, Secure
Boot target validation, performance tests, and benchmark labs.

## Stop rules

Stop a package batch if it:

- creates a White-only copy of shared-core enforcement;
- adds a direct White-to-Red/Blue/Purple/Black engine import;
- adds a direct Red/Blue/Purple/Black-to-White runtime import;
- implements Live-specific forks of White domain behavior;
- changes another Night's default execution behavior merely because White is
  installed;
- introduces a cloud dependency for ordinary White operation.

Composition must add capability, not dependency.
