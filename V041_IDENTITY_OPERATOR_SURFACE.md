# v0.41.0 Live Identity Operator Surface

Red Night v0.41 exposes the authorization-first Active Directory and Microsoft
Entra collectors through one explicit operator command:

`red-night identity collect <provider>`

The live collection surface uses the existing Red workspace execution policy.
It does not create a second authorization system.

## Required engagement setup

Before live identity collection, the operator must have an existing active
workspace engagement with:

- an authorization reference
- the exact target or tenant in engagement scope
- a current validity window
- remaining action budget
- the `identity.collect` capability
- explicit approval when that capability is configured to require approval

Collection authorization is evaluated and consumed by `LocalWorkspace`
before the provider performs any network request. Denied requests therefore
make zero LDAP or Microsoft Graph provider calls.

The existing workspace CLI can create and authorize the engagement, for example:

`red-night workspace create <workspace> --engagement-id <id> ...`

`red-night workspace policy-set <workspace> --engagement-id <id> --scope <target> --valid-from <iso8601> --valid-until <iso8601> --max-actions <n> --capability identity.collect`

The engagement must be in the `active` lifecycle state.

## Active Directory

The live AD surface is:

`red-night identity collect ad`

Required operator inputs are:

- `--workspace`
- `--engagement-id`
- `--source-id`
- `--target`
- `--base-dn`
- `--bind-username`
- `--password-env`

The password is read from the named environment variable only if the
authorization gate has allowed the collection and the LDAP transport actually
opens. The password value is not printed or persisted.

Transport mode defaults to LDAPS. `--mode starttls` is available for the
existing certificate-validating StartTLS transport. Optional `--port` and
`--ca-certs-file` select transport metadata only; they do not weaken TLS
validation.

## Microsoft Entra

The live Entra surface is:

`red-night identity collect entra`

Required operator inputs are:

- `--workspace`
- `--engagement-id`
- `--source-id`
- `--target` (configured tenant identifier)
- `--token-env`

The Microsoft Graph bearer token is read from the named environment variable
only when an authorized Graph page request is executed. The token value and the
environment-variable name are not included in ordinary output or persisted
evidence.

## Default output

Default stdout is an identity-safe JSON summary. It contains:

- provider and authorized target
- identity/group/role counts
- observed membership/relationship counts
- unresolved-reference count
- truncation state and provider limitations
- provider request count and runtime
- deterministic graph SHA-256
- graph node/edge counts
- workspace records added
- an explicit no-exploitability interpretation

Default stdout does **not** contain identity labels, raw Active Directory DNs,
Entra object IDs, passwords, access tokens, or credential environment-variable
names.

`--report-output <path>` writes the same identity-safe summary as canonical
sorted JSON.

## Explicit detailed graph export

`--export-graph <path>` is the explicit opt-in boundary for a detailed graph
export. That file can contain identity/group/application/role labels needed for
authorized review.

Detailed graph labels are never printed merely because collection succeeded.
The exported graph still uses opaque normalized natural keys instead of raw AD
DNs or Entra object IDs.

## Workspace evidence

A successful collection records normalized evidence into the selected
engagement workspace:

- identity observations
- group observations
- permission/role observations
- membership relationships
- ownership and scoped role relationships where observed
- one non-secret collection-summary record

The workspace authorization action is consumed exactly once per allowed live
collection attempt. Denied attempts are audited but do not consume an action.

## Safety and non-goals

This surface is read-only. It does not add:

- arbitrary LDAP or Microsoft Graph queries
- password spraying or guessing
- credential harvesting
- directory writes
- ownership changes
- role assignment/removal
- OAuth consent or permission modification
- persistence
- lateral movement
- autonomous exploitation
