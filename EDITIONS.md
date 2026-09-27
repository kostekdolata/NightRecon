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
To review known group membership paths in that same snapshot, supply both
`--start-dn 'CN=Analyst,DC=example,DC=test'` and
`--target-dn 'CN=Reviewers,DC=example,DC=test'`. The target must be an
imported group. The summary reports the path count and whether the fixed
depth, path, or exploration budget left results incomplete. `--include-graph`
also includes path IDs and graph labels. These are membership relationships,
not proven access, privilege escalation, or exploitability.

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
