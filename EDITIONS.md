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
| White Night | Engagement scope, rules of engagement, approvals, audit, evidence custody, exercise control, and emergency stop | Shared scope/audit foundations exist; standalone application not available |
| Blue Night | Defensive telemetry, control validation, detection coverage, and remediation retests | Planned; standalone application not available |
| Red Night | Authorized reconnaissance, exposure and attack-path analysis, bounded validation, and controlled emulation | Reconnaissance/assessment/graph foundations exist; standalone application not available |
| Purple Night | Match approved Red Night actions to Blue Night prevention, alerts, telemetry, and detection gaps | Planned; standalone application not available |
| Black Night | Authorized outside-in assessment from a deliberately limited starting knowledge set | External reconnaissance foundations exist; standalone application not available |

`nightrecon editions` (or `nightrecon editions --json`) exposes the current
catalog. It is informational only: it does not select, install, enable, or
authorize an edition. The existing `nightrecon` CLI continues to work as before.
Installing the current NightRecon distribution also creates a `red-night`
command. For example, `red-night --help` lists its allowed commands and
`red-night scan --help` displays the existing scan options. This is a Red Night
entry point inside the shared distribution, not a separately installable Red
Night application. Existing target scope and assessment policies still apply.

Red Night can review a local, normalized directory snapshot using
`red-night identity import snapshot.json --source-id approved-export-1` (also
available via `red-night-app`). The input schema is
`{"schema_version":1,"entries":[{"dn":"CN=Analyst,DC=example,DC=test","kind":"user","name":"Analyst"},{"dn":"CN=Reviewers,DC=example,DC=test","kind":"group","name":"Reviewers","members":["CN=Analyst,DC=example,DC=test"]}]}`.
The default JSON response contains counts, unresolved membership references,
and a reproducible graph fingerprint without listing people. Add
`--include-graph` only when you intend to export graph labels and provenance;
this can disclose identity data. The command reads at most 1 MB, makes no
directory connection, and never treats an absent member as an observed edge.

`packages/red-night/` is a separately built **development-preview** Red Night
distribution. Installing its wheel with the matching NightRecon shared-runtime
wheel supplies `red-night-app` without any other Night application. The existing
`red-night` entry point remains in the shared package for compatibility; the
distinct script names prevent package installation or removal from overwriting
one another. Clean, local-wheel installations of the preview alone and alongside
the legacy launcher are smoke-tested. Its shared runtime still contains the
current integrated engines, and combined installation with the four future
Nights cannot be verified before they exist. The catalog therefore continues
to report `standalone_available: false` until isolation and functional release
gates pass.

An internal `edition_gateway` now denies unowned commands before calling the
existing CLI. Red Night can route existing authorized assessment commands through this
boundary. White Night, Blue Night, Purple Night, and Black Night expose only the informational
catalog there for now. In particular, the generic CIDR discovery command is not
silently presented as a Black Night external-assessment workflow. The gateway is
not a substitute for the core scope checks.

Bounded host discovery, TCP connect scanning, and service-detection orchestration now have canonical Red-owned
runtime modules (`red_host_discovery`, `red_tcp_scanner`, and `red_service_detection`). The legacy module
names remain compatibility re-exports, and the legacy CLI imports the Red-owned
implementations directly. This is an execution-ownership seam, not yet a fully
separate Red engine package; existing authorization/scope behavior is unchanged.

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
2. Command ownership and fail-closed routing boundary (the shared and separate
   Red Night launchers use the same gateway; complete engine isolation remains
   an open gate).
3. Separate installable edition entry points with optional dependencies and
   tests proving one edition cannot invoke another edition's active commands,
   including one edition, arbitrary combinations, and the full suite.
4. Add the missing Blue Night/White Night/Purple Night capabilities and further Red Night/Black Night
   capabilities in small CI-verified releases. Do not advertise a standalone
   edition as available until its isolation and functional acceptance tests pass.

The next Red Night domain-capability batch remains authorization-first Active
Directory identity collection on top of the v0.31 immutable graph contract.
