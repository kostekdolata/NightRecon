# Red Night application distribution

`nightrecon-red-night` is the independently installable Red Night application.

The stable v0.43.0 package supplies the `red-night-app` command and depends on
the matching `nightrecon-red-engine==0.43.0` and
`nightrecon-shared-core==0.43.0` distributions. It does not require the
legacy `nightrecon==0.31.0` package and it does not install future White,
Blue, Purple, or Black Night applications.

The application entry point calls `nightrecon_red_engine.red_cli` directly.
The CI distribution matrix verifies:

- isolated Red Night installation with no legacy NightRecon package
- combined Red Night + legacy compatibility installation
- independent `red-night-app` / `red-night` scripts
- Python 3.11 and 3.14 on Ubuntu and Windows

Optional extras expose the existing bounded integrations:

- `browser`
- `api`
- `ad`
- `ssh`
- `smb`
- `winrm`
- `postgres`
- `mysql`
- `all`

v0.41 includes authorization-first live Active Directory and Microsoft Entra
identity collection through `red-night-app identity collect ad` and
`red-night-app identity collect entra`. Default live identity output is
label/secret-safe; detailed graph labels require an explicit graph export.

All active operations remain subject to shared-core scope, authorization
windows, action budgets, approval requirements, revocation, and audit controls.

Red Night v0.43 adds explicitly selected Controlled Validation Intelligence for the reviewed bounded read-only proof techniques. Execution remains subject to the shared-core authorization boundary and the isolated revocable worker, durable evidence, cleanup, and retest contracts documented in `V043_CONTROLLED_VALIDATION_INTELLIGENCE.md`.


## v0.44 deployment foundation

Red Night is being completed as one product across three deployment profiles:

- standalone installation;
- composed NightRecon stack;
- Red Night Live USB.

All three profiles retain the dependency direction
`red-night-app -> nightrecon-red-engine -> nightrecon-shared-core`.
Peer Nights remain optional and independently removable.

Current v0.44 deployment work includes:

- package-parity and no-cross-Night-runtime contracts;
- normal-install Red+White composition and shared-workspace exchange;
- explicit fail-closed Red package/shared-schema compatibility;
- Debian-based amd64 Live image construction and UEFI VM boot proof;
- privileged Live appliance modes with `authorization_effect: none`;
- LUKS2 encrypted Secure Workspace provisioning, reopen, safe close, recovery,
  and read-only integrity evidence;
- deterministic release manifests and secret-free SBOM metadata;
- immutable Live retention and boot-time verification of exact Red wheels;
- Ed25519-signed offline update verification;
- bounded update/rollback planning that preserves the encrypted workspace;
- explicit deployment-readiness records that keep Secure Boot, hardware, and
  media endurance unverified until real qualification evidence exists.

The Live layer does not grant target authorization and does not weaken Red
scope, approval, action-budget, revocation, evidence, cleanup, audit, or
isolated-worker controls.

See `RED_LIVE_ARCHITECTURE.md` and `RED_ACCEPTANCE.md` for the authoritative
deployment and acceptance boundaries.
