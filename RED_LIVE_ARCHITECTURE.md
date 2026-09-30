# Red Night Live USB Architecture

Red Night Live is a deployment of the same Red Night product, not a separate
codebase or a USB-specific fork.

The locked product rule is:

- normal standalone Red installation;
- Red inside a composed NightRecon full-stack installation; and
- Red Night Live USB

must all run the same versioned `nightrecon-red-night`,
`nightrecon-red-engine`, and `nightrecon-shared-core` packages.

Live-specific code may own boot, media provisioning, persistence, hardware
integration, recovery, and update mechanics. It must not fork scanners,
collectors, validation logic, authorization, evidence, graph, reporting, or
cleanup semantics.

## Dependency boundary

The Red runtime dependency direction remains:

`red-night-app -> nightrecon-red-engine -> nightrecon-shared-core`

Red must never require White, Blue, Purple, or Black Night merely to perform
Red-owned workflows.

A composed installation may install peer Nights beside Red and may use the same
compatible shared engagement/workspace backend. Interoperability occurs through
versioned shared-core contracts and evidence, never by Red importing another
Night's engine.

Removing another Night from a composed installation must not make Red unable to
start or use its own capabilities.

## Required deployment profiles

### Standalone installation

Required Python distributions:

- `nightrecon-shared-core`
- `nightrecon-red-engine`
- `nightrecon-red-night`

No legacy monolith or other Night is required.

The current v0.43 distribution smoke already proves the independently installed
Red application and engine boundary. v0.44 extends that proof into deployment
parity rather than creating a new Red implementation.

### Composed NightRecon stack

Red may be installed beside any available White, Blue, Purple, or Black Night
packages.

Composition may provide:

- one shared engagement/workspace service;
- shared evidence and audit contracts;
- coordinated authorization/stop state;
- shared update and platform services;
- cross-Night reporting and correlation where explicitly designed.

Composition must not provide implicit authorization or silently activate Red
capabilities.

### Red Night Live USB

Red Night Live is a bootable appliance profile built from the same Red package
artifacts as the normal installation.

The first platform target is:

- x86-64;
- UEFI PCs;
- USB 3.x storage;
- minimal Debian-based Live environment generated from source-controlled
  `live-build` configuration.

ARM64 is a later platform and must not complicate the initial implementation.

## Live storage model

Conceptual media layout:

```
RED NIGHT LIVE MEDIA
|
+-- EFI / boot
|   +-- bootloader
|   +-- kernel
|   +-- initramfs
|   `-- integrity metadata
|
+-- immutable/read-only system image
|   +-- Debian base
|   +-- nightrecon-shared-core
|   +-- nightrecon-red-engine
|   +-- nightrecon-red-night
|   +-- approved Red optional runtime dependencies
|   `-- deployment/integrity metadata
|
`-- encrypted persistent workspace
    +-- engagements
    +-- authorization/policy state
    +-- evidence
    +-- validation lifecycle
    +-- reports
    +-- audit
    +-- configuration
    `-- controlled update state
```

Production persistent workspaces should use LUKS2 encryption.

The operating-system/application image should remain immutable during normal
operation wherever practical. Customer evidence and engagement state must not
be written into the immutable system image.

## Live boot modes

### Secure Workspace

Normal field mode.

- encrypted persistence required;
- Red workspace survives reboot;
- Red application launches after workspace unlock;
- all active Red operations still pass shared-core authorization and stop
  controls.

### Ephemeral Session

Temporary mode.

- no engagement persistence survives shutdown;
- useful for demonstrations, temporary authorized assessment, or recovery
  triage;
- explicit export is required to retain evidence.

### Recovery & Integrity Check

Maintenance mode.

- verify image/package manifest;
- inspect persistence availability;
- perform supported workspace recovery;
- stage rollback/update recovery;
- do not start an active assessment automatically.

## Networking

Red Night Live must remain usable without Internet access.

Network interfaces are available only because Red assessment workflows may
require authorized target connectivity. Their presence does not create target
authorization.

Defaults:

- no cloud login required;
- no telemetry required;
- no SaaS dependency;
- no automatic evidence upload;
- no automatic external synchronization;
- update checks/imports are explicit operator actions.

## Host-disk behavior

Red Night Live must not automatically mount or modify internal host disks.

Any future host-storage access must be an explicit authorized workflow with
clear operator visibility and must not be required simply to run Red.

## Live package composition

The Live builder must consume built, versioned package artifacts rather than
copying arbitrary working-tree Python source into the image.

Expected package profiles over time:

- Red Night Live;
- Red + White Live;
- Red + selected Nights Live;
- Full NightRecon Live.

Those are composition profiles, not source forks. A Red+White image installs the
same Red packages and the same White packages that their standalone products
use.

## Optional Red runtime dependencies

The Live profile may include selected existing Red extras such as browser, API,
AD, SSH, SMB, WinRM, PostgreSQL, or MySQL support.

Which extras are installed is a build/profile decision. Their presence must not
change authorization or make optional capability silently active.

## Image artifacts

Target production artifacts:

```
RedNight-Live-<version>-amd64.iso
RedNight-Live-<version>-amd64.iso.sha256
RedNight-Live-<version>-amd64.iso.sig
RedNight-Live-<version>-SBOM.json
RedNight-Live-<version>-manifest.json
```

The manifest should record Red/shared-core package versions, base OS snapshot
information, included package/extras, image fingerprint, build source revision,
and build/schema format versions.

Manual post-build customization is not an acceptable production release path.

## Secure Boot and integrity

Secure Boot is a production target, not a claim for Batch 1.

Development order:

1. bootable development image;
2. deterministic package/image manifest;
3. signed image/update metadata;
4. verified Secure Boot flow;
5. hardware compatibility matrix.

Integrity failures must be visible and fail closed. A development image booting
on one machine does not establish Secure Boot or hardware compatibility.

## Updates and recovery

Updates must preserve the workspace independently from the immutable system
image.

Target update flow:

1. explicit operator check/import;
2. verify update metadata/signature;
3. verify compatible Red/shared-core/schema versions;
4. stage image/package update;
5. preserve encrypted workspace;
6. reboot;
7. verify migration/integrity;
8. keep a bounded rollback path.

Offline update bundles are required for field use.

Recovery design must cover power loss, unsafe media removal, persistence
filesystem damage, schema mismatch, failed updates, failed boot, and replacement
media restored from an approved encrypted backup.

## v0.44 Live development gates

### Batch 1 — deployment architecture contracts

- declarative Red deployment profiles in the Red application package;
- standalone/composed/Live package parity contract;
- explicit no-cross-Night-runtime dependency rule;
- Red Live architecture and acceptance documentation;
- installed-wheel smoke verifies the deployment contract.

### Batch 2 — Live build skeleton

Status: completed and merged.

- source-controlled Debian `live-build` configuration under `live/red-night/`;
- Debian 13 (trixie) amd64 hybrid ISO with GRUB EFI;
- install built shared-core/Red engine/Red app wheel artifacts into an isolated venv;
- headless QEMU/OVMF UEFI boot smoke with VM networking disabled;
- boot marker validates the installed Red Live deployment contract;
- exact-head PR CI and 40/40 post-merge master CI verified;
- no persistent engagement state yet.

### Batch 3 — application appliance session

Status: active development.

- automatic non-root appliance controller on tty1;
- explicit Secure Workspace / Ephemeral Session / Recovery & Integrity selection;
- no workspace mode is selected automatically;
- Ephemeral Session launches only the existing Red application command boundary
  from temporary runtime storage;
- Recovery & Integrity validates local deployment contracts and does not launch
  assessment commands;
- Secure Workspace is visible but fails closed until Batch 4 supplies LUKS2
  persistence;
- appliance selection has `authorization_effect: none`; all active Red
  operations retain normal shared-core authorization requirements;
- networking may be visible to the operator but no target is automatically
  authorized.

### Batch 4 — encrypted persistence

- LUKS2 persistent workspace;
- create/reopen a Red engagement across reboot;
- prove ephemeral mode leaves no engagement state;
- safe shutdown/removal flow.

### Batch 5 — composition

- Red+White image profile once White's compatible standalone boundary is ready;
- shared engagement contracts/backend only;
- no Red->White or White->Red runtime imports;
- package removal/isolation tests in normal composed installs;
- prepare selected-Night and eventual full-stack image profiles.

### Batch 6 — production hardening

- signed update/offline bundle flow;
- image/package integrity manifest;
- SBOM;
- recovery validation;
- Secure Boot target;
- hardware compatibility and USB endurance testing.

## Release rule

A Red capability is not Live-compatible merely because its CLI starts from the
Live image.

Deployment parity requires its authorization, workspace, evidence, validation
worker, cleanup/retest, reporting, update, and recovery behavior to be verified
through the Live deployment path as well as the normal standalone installation.
