# The NightRecon Nights

NightRecon is planned as five independently installable applications called the
Nights, built on one authorization-first core. A user should eventually be able
to install any one Night, any combination, or the complete suite without
maintaining five copies of the scanners, evidence models, or safety rules.
Their canonical names are White Night, Blue Night, Red Night, Purple Night, and
Black Night. The stable internal slugs remain `white`, `blue`, `red`, `purple`,
and `black` for CLI routing and future evidence contracts.

| Edition | Product responsibility | Current state |
| --- | --- | --- |
| White Night | Engagement scope, rules of engagement, approvals, audit, evidence custody, exercise control, emergency stop, and after-action reporting | Package boundary, immutable engagement/ROE domain, and deterministic local policy compiler implemented; functional standalone application not yet available |
| Blue Night | Defensive telemetry, control validation, detection coverage, and remediation retests | Planned; standalone application not available |
| Red Night | Authorized reconnaissance, exposure and attack-path analysis, bounded validation, and controlled emulation | Stable v0.41.0 standalone application available with mandatory shared safety core |
| Purple Night | Match approved Red Night actions to Blue Night prevention, alerts, telemetry, and detection gaps | Planned; standalone application not available |
| Black Night | Authorized outside-in assessment from a deliberately limited starting knowledge set | External reconnaissance foundations exist; standalone application not available |

`nightrecon editions` (or `nightrecon editions --json`) exposes the current
catalog. It is informational only: it does not select, install, enable, or
authorize an edition. The existing `nightrecon` CLI continues to work as before.
Installing the legacy NightRecon compatibility distribution creates a
`red-night` command. The stable Red Night v0.41.0 application is also
independently installable and exposes `red-night-app`. Both routes preserve the
same fail-closed Red command boundary and shared authorization policy. Existing
target scope and assessment policies still apply.

Red Night can review a local, normalized directory snapshot using
`red-night identity import snapshot.json --source-id approved-export-1` (also
available via `red-night-app`). The input schema is
`{"schema_version":1,"entries":[{"dn":"CN=Analyst,DC=example,DC=test","kind":"user","name":"Analyst"},{"dn":"CN=Reviewers,DC=example,DC=test","kind":"group","name":"Reviewers","members":["CN=Analyst,DC=example,DC=test"]}]}`.
The default JSON response contains counts, unresolved membership references,
and a reproducible graph fingerprint without listing people. Add
`--include-graph` only when you intend to export graph labels and provenance;
this can disclose identity data. The command reads at most 1 MB, makes no
directory connection, and never treats an absent member as an observed edge.

`packages/red-night/` is the separately built stable Red Night v0.41.0
application distribution. Installing its wheel with matching v0.41.0 Red-engine
and shared-core wheels supplies `red-night-app` without any other Night
application. The existing `red-night` entry point remains in the legacy package
for compatibility; the distinct script names prevent package installation or
removal from overwriting one another. Clean local-wheel installations of Red
alone and alongside the legacy launcher are smoke-tested across the supported
CI matrix. The catalog reports Red Night as standalone available. Combined
installation with the four future Nights cannot be verified before those
applications exist.

An internal `edition_gateway` now denies unowned commands before calling the
existing CLI. Red Night can route existing authorized assessment commands through this
boundary. White Night, Blue Night, Purple Night, and Black Night expose only the informational
catalog there for now. In particular, the generic CIDR discovery command is not
silently presented as a Black Night external-assessment workflow. The gateway is
not a substitute for the core scope checks.

Existing host discovery, TCP scanning, service detection, web/API assessment,
credentialed infrastructure assessment, vulnerability intelligence, checks,
inventory, reporting, and graph/path capabilities are assigned to Red Night.
The `red_host_discovery`, `red_tcp_scanner`, and `red_service_detection`
modules are thin ownership facades over the existing proven implementations;
they do not duplicate engine code. The detailed ownership map is maintained in
`RED_OWNERSHIP.md`. Existing authorization/scope behavior is unchanged.

## Stack composition contract

NightRecon is a software stack, not a collection of mutually exclusive editions.

Each Night must be able to run as a complete standalone application for its own
responsibility, with the mandatory shared safety core installed beneath it.
Installing another Night must never be required just to use that application's
normal workflows.

When two or more Nights are installed together, they form one composable
NightRecon stack. Composition must add interoperability, not create hidden
runtime dependencies between applications. The required dependency direction is:

`Night application -> shared core`

No Night application may become a mandatory dependency of another Night.

Cross-Night cooperation uses versioned, secret-free evidence and engagement
contracts. Standalone applications can export/import those contracts. A composed
installation may additionally use a shared engagement data layer so Red, Blue,
White, Purple, and Black can contribute to and consume the same authorized
engagement state without duplicating databases.

The shared engagement layer must preserve source Night, evidence provenance,
schema version, authorization context, timestamps, and confidence/limitations.
It must not turn data observed by one Night into automatic authorization for
another Night. Shared state is evidence and coordination context; each active
operation still passes the shared core's scope, approval, budget, and stop
controls.

Examples of intended composition:

- Red Night can publish assessment findings and action evidence.
- Blue Night can publish telemetry, prevention, alert, and remediation evidence.
- Purple Night can correlate Red and Blue evidence whether those Nights are
  installed locally or their versioned exports are imported.
- White Night can manage engagement authorization, approvals, evidence custody,
  and exercise control without becoming a required runtime for the safety core.
- Black Night can contribute outside-in discovery evidence while retaining its
  deliberately limited-knowledge operating model.

The full-suite installation should therefore feel like one integrated NightRecon
workspace while preserving the ability to install, upgrade, run, and remove each
Night independently.

### White Night deployment contract

White Night is the second standalone NightRecon product track after Red Night.
Its foundation is defined by [WHITE_ACCEPTANCE.md](WHITE_ACCEPTANCE.md),
[WHITE_OWNERSHIP.md](WHITE_OWNERSHIP.md),
[WHITE_PACKAGE_PLAN.md](WHITE_PACKAGE_PLAN.md), and
[WHITE_LIVE_ARCHITECTURE.md](WHITE_LIVE_ARCHITECTURE.md).

White Night remains one product across standalone installation, composed
full-stack installation, and White Night Live USB. The same White app/engine
packages and versioned contracts must be used in all three deployments.

White manages engagement authoring, approvals, evidence custody, exercise
control, emergency-stop workflows, and reporting. Shared core remains the
authoritative enforcement layer. White's deterministic compiler projects
immutable ROE intent into shared-core policy and must fail closed rather than
widen scope, capabilities, budgets, or impact.

Deployment-specific storage may differ, but engagement/evidence semantics must
not. Imported evidence never becomes authorization.

### Shared engagement storage

The shared core now defines a backend-neutral `EngagementStore` contract plus a
portable `FileEngagementStore` for standalone applications. The file store is
strictly versioned, deterministic, conflict-safe, and written by atomic replace.
A future full-stack workspace may use SQLite, PostgreSQL, a local service, or
another backend, but it must implement the same store semantics.

Red Night is the first producer wired into this layer. Its offline identity
import can persist evidence with `--store <path> --engagement-id <id>` and can
read it back with `identity store-list`. Engagement coordination metadata can be
created with `identity store-metadata`; its authorization reference is only a
pointer to separately enforced authorization state and never grants permission.
Standalone stores can export one engagement with `identity store-export` and
import it into another compatible store with `identity store-import`, preserving
source Night, provenance, limitations, metadata, and evidence IDs. These are
explicit local data operations; the default identity-import output remains unchanged.

Evidence imported from another Night is never authorization. Any later active
operation still requires the shared core's target scope, approvals, budgets,
and stop controls.

### Shared workspace coordination

The shared core also defines a `WorkspaceStore` boundary and a
`LocalWorkspace` implementation. A local workspace derives its engagement
index from one canonical `engagements.json` store rather than maintaining a
second database. Summaries expose engagement identity, name/status, source
Nights present, record counts, and evidence types; evidence breakdowns are
available by source Night and type.

Red Night owns the first top-level workspace adapter:
`workspace list`, `workspace show`, `workspace import`, and
`workspace export`. These commands are evidence/coordination operations only
and cannot scan or authorize targets.

The current file-backed workspace supports standalone use and serialized local
writers. A future composed service/database backend will provide concurrency
control while preserving the same store/workspace contracts. No Night is
permitted to import another Night's runtime just to participate in the shared
workspace.

## Separation contract

- The shared core owns existing scope and authorization checks, budgets, secret
  handling, evidence provenance, audit, and report schemas. A future emergency
  stop must also live in the shared core. These protections must be present even
  when the White Night application is not installed. White Night adds management and
  exercise-control workflows; it is not an optional safety bypass.
- Each edition will own its commands, optional dependencies, and presentation.
  An edition must not silently enable another edition's active capabilities.
- Cross-edition exchange uses versioned, secret-free evidence contracts. Purple Night
  can consume previously exported Red Night and Blue Night evidence without requiring both
  engines to run in the same process; integrated installations can connect them
  directly under one approved engagement.
- Black Night means limited operator knowledge, never weaker authorization.
  Discovered associations are evidence to review, not permission to probe newly
  found hosts or domains.
- Installing multiple Nights should compose capabilities, not duplicate
  databases or change defaults. Passive remains the default; active activity
  still requires the same explicit scope and policy gates.

## Delivery gates

1. Catalog and published boundaries (completed).
2. Command ownership and fail-closed routing boundary (completed for the legacy
   and standalone Red launchers).
3. Separate installable edition entry points with optional dependencies and
   tests proving one edition cannot invoke another edition's active commands.
   Completed for Red Night v0.41.0; arbitrary multi-Night/full-suite composition
   remains future work because the other standalone applications do not yet exist.
4. White Night is the second standalone product track after Red. Implement it
   in small CI-verified releases while preserving Red stability and the
   shared-core enforcement boundary.
5. Add the missing Blue Night/Purple Night capabilities and further
   Red Night/Black Night capabilities in small verified releases. Do not
   advertise any standalone edition as available until its isolation,
   deployment, and functional acceptance tests pass.
6. Full-stack composition and Live image profiles must reuse the same Night
   packages and versioned contracts; deployment must not introduce hidden
   Night-to-Night runtime dependencies.

The next Red Night product-development milestone should close measured
acceptance gaps rather than duplicate existing foundations: concrete authorized
provider adapters, repeatable comparison labs, controlled technique coverage,
and professional operator/reporting workflows.
