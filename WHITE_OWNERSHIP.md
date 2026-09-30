# White Night Capability Ownership

This document is the source of truth for White Night product ownership.

White Night owns the engagement and exercise **control plane**. It does not own
the network/application assessment engines, defensive telemetry engines,
correlation engines, or limited-knowledge external-assessment engines assigned
to the other Nights.

The mandatory shared core remains the enforcement boundary beneath every Night.

## Core rule

The required dependency direction is:

`Night application -> shared core`

Never:

`Red/Blue/Purple/Black -> White Night`

and never:

`White Night -> another Night's runtime`

Cross-Night composition uses versioned engagement, event, evidence, capability,
and control contracts.

## White-owned capabilities

### Engagement administration

White owns management workflows for:

- engagement creation, versioning, archival, and closure;
- engagement owner and operational roles;
- customer/entity and authorized contact metadata;
- testing/exercise windows;
- scope review and presentation;
- rules-of-engagement authoring;
- action/technique policy selection;
- data-handling and retention policy;
- engagement templates and cloning.

White does not bypass or replace shared-core scope enforcement.

### Rules of engagement and policy management

White owns:

- human-readable ROE authoring;
- version review;
- approval routing;
- deterministic compilation requests for machine policy bundles;
- policy fingerprints and presentation;
- policy publication/revocation lifecycle;
- deviation requests and approval records.

The canonical enforcement primitives and validation logic required by all Nights
belong in shared core. White may call them but must not fork them.

### Approval workflows

White owns the operator-facing approval domain:

- approval requests;
- eligible approver policy;
- single, dual-control, and quorum workflows;
- separation of duties;
- decision reasons;
- expiry;
- delegation;
- escalation;
- rejection;
- revocation;
- approval review/inbox presentation.

Another Night may request approval through a shared contract without importing
White. In a standalone deployment without White, shared-core policy must still
fail closed according to its configured approval requirements.

### Evidence custody

White owns evidence-management workflows:

- evidence intake;
- custody events;
- integrity verification;
- evidence manifests;
- classification;
- retention/disposition workflow;
- evidence review;
- portable export bundles;
- operator presentation and search.

Shared-core evidence contracts, provenance fields, schema rules, and
secret-handling protections remain Night-neutral.

### Audit management

White owns:

- engagement audit views;
- administrative/audit event ingestion;
- integrity verification;
- filtered operator review;
- export/report generation;
- retention policy workflow.

Any audit primitive required for safe operation without White belongs in shared
core.

### Exercise Director

White owns:

- exercise/scenario definitions;
- objectives;
- phases;
- injects;
- facilitator controls;
- participant/observer/reviewer roles;
- exercise clock;
- pause/resume/terminate orchestration;
- expected outcomes;
- observations;
- lessons learned;
- improvement actions;
- exercise scoring where scoring is explicitly defined by the exercise model.

White does not execute Red techniques or Blue defensive actions itself.

### Mission Control

White owns the integrated engagement-control surface:

- authorization/policy state;
- approval state;
- operation/event timeline;
- evidence intake state;
- connected Night capability/status presentation;
- action budget/time-window presentation;
- stop-request and acknowledgement presentation;
- operator notifications;
- exercise control.

Mission Control consumes versioned contracts and must not import other Night
engine modules.

### Emergency-stop management

White owns the operator workflow for:

- stop engagement;
- stop Night;
- stop operation;
- freeze new actions;
- revoke approval;
- revoke credential-use authorization where represented by shared policy;
- acknowledgement tracking.

The actual stop state, validation, and enforcement primitives required by active
workers belong in shared core so they remain effective when White is absent.

### Reporting

White owns generation of:

- engagement summary;
- scope/ROE report;
- approval/decision report;
- audit report;
- evidence manifest;
- exercise timeline;
- after-action report;
- lessons/improvement plan;
- combined control-plane export.

Specialist technical findings remain owned by their source Night; White may
reference, package, and present them with provenance.

## Shared-core responsibility

The shared core owns capabilities that must exist regardless of which Night
applications are installed:

- authorization and scope enforcement;
- target-validation primitives;
- action/intrusiveness budgets;
- stop-state contract and enforcement primitives;
- secret-handling primitives;
- edition/capability policy;
- engagement/evidence/event contract schemas;
- provenance requirements;
- backend-neutral engagement/workspace interfaces;
- cross-Night import/export invariants;
- cryptographic verification primitives used across Nights;
- policy validation required at active execution boundaries.

A feature belongs in shared core when another Night must remain safe without
White installed.

## Other Night responsibility

### Red Night

Red owns reconnaissance, exposure discovery, web/API/infrastructure assessment,
identity/attack-path analysis, bounded validation, controlled emulation, and
technical Red evidence.

### Blue Night

Blue owns defensive telemetry, control validation, detection engineering,
detection/prevention evidence, remediation verification, and defensive retests.

### Purple Night

Purple owns correlation of approved offensive actions with defensive telemetry,
prevention, alerts, detections, and control gaps.

### Black Night

Black owns explicitly authorized limited-knowledge/outside-in assessment and its
discovery evidence. Limited operator knowledge never weakens shared-core scope.

## Storage ownership

White code must depend on backend-neutral stores rather than USB-specific or
desktop-specific paths.

Expected contracts include:

- `EngagementStore`
- `WorkspaceStore`
- `EvidenceStore`
- `AuditStore`
- `PolicyStore`
- `ApprovalStore`

Deployment chooses the backend:

- standalone installation: local file/SQLite-style backend;
- composed full stack: shared NightRecon workspace service/database;
- Live USB: encrypted persistent local backend;
- portable exchange: signed/versioned export bundle.

The storage backend must not change evidence or authorization semantics.

## Live USB ownership boundary

The White Night Live image owns deployment integration such as:

- boot configuration;
- immutable operating-system image;
- encrypted persistence setup;
- application autostart;
- recovery/integrity mode;
- offline update staging;
- hardware compatibility testing.

Live-specific code must not duplicate White engagement/business logic.

## Connector ownership

White may provide connectors for external workflow, identity, ticketing, signing,
or evidence systems where they improve engagement control. Connector failures
must fail soft for evidence ingestion and fail closed where authorization would
otherwise be affected.

External products never become an implicit authorization source.

## Stop rule

If White development begins implementing Red scanning, exploit/validation
payloads, Blue telemetry/detection engines, Purple correlation logic, or Black
external discovery simply to make White appear self-contained, stop.

White is self-contained for its own control-plane responsibility. Full-stack
capability comes from composition through shared contracts, not duplicated
engines.
