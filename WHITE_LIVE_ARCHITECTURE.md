# White Night Live USB Architecture

White Night Live is a first-class deployment of the same White Night product.
It is not a separate codebase and does not replace the normal standalone or
full-stack installation model.

The goal is a self-contained, air-gap-capable engagement and exercise-control
environment that can boot from approved removable media and run without trusting
or modifying the host Windows installation.

## Locked deployment principle

The same White Night application and engine packages must work in:

- normal standalone installation;
- composed NightRecon full-stack installation;
- White Night Live USB.

Live-specific components own boot, persistence, update, and hardware integration
only. They must not fork engagement, ROE, approval, audit, evidence, exercise,
or reporting logic.

## Host behavior

White Night Live is boot media.

It does **not** attempt to bypass modern operating-system removable-media
AutoRun restrictions or silently execute when inserted into a running host.

Normal operator flow:

```
insert approved White Night USB
        ->
select USB/UEFI boot
        ->
White Night Live boots
        ->
verify system/integrity state
        ->
unlock encrypted workspace when persistent mode is selected
        ->
White Night starts automatically
```

## Initial platform target

First supported hardware target:

- x86-64;
- UEFI PCs;
- modern business/workstation hardware;
- USB 3.x storage.

Initial media guidance:

- 64 GB minimum development/field size;
- 128 GB recommended for production engagements;
- high-endurance USB 3.2 media or compact external SSD preferred for heavy
  evidence workloads.

ARM64 is a later platform and must not complicate the first release.

## Base operating system

Initial architecture target:

- minimal Debian-based Live environment;
- reproducible configuration using Debian `live-build`;
- no Kali dependency required for White control-plane operation;
- only required runtime/system packages installed;
- no unnecessary general-purpose services enabled by default.

The base environment is treated as an appliance platform rather than a general
desktop distribution.

## Storage layout

Conceptual media layout:

```
WHITE NIGHT LIVE MEDIA
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
|   +-- nightrecon-white-engine
|   +-- nightrecon-white-night
|   +-- approved dependencies
|   `-- optional installed Night packages for composed images
|
`-- encrypted persistent workspace
    +-- engagements
    +-- policies
    +-- approvals
    +-- evidence
    +-- audit
    +-- reports
    +-- configuration
    `-- controlled update state
```

Production persistent workspace uses LUKS2 encryption.

The operating-system image should remain read-only/immutable during ordinary
operation wherever practical. Only explicitly selected application state is
persistent.

## Boot modes

White Night Live should provide three explicit modes.

### Secure Workspace

Normal field operation.

- encrypted persistence required;
- engagement state survives reboot;
- White launches automatically after workspace unlock;
- active Night operations remain subject to shared-core policy.

### Ephemeral Session

Temporary/non-persistent operation.

- no engagement workspace persistence;
- suitable for demonstrations, temporary exercises, recovery triage, or
  situations where no state should survive shutdown;
- must clearly warn that results will be lost unless explicitly exported to an
  approved destination.

### Recovery & Integrity Check

Maintenance mode.

- verify system image/package manifest;
- inspect encrypted workspace availability;
- perform supported filesystem/recovery checks;
- stage rollback or approved recovery;
- do not start an active engagement automatically.

## Startup sequence

Target startup flow:

1. boot approved image;
2. verify expected image/package integrity metadata;
3. initialize minimal local services;
4. detect selected boot mode;
5. for Secure Workspace, unlock LUKS2 persistence;
6. validate workspace schema/version;
7. load operator/engagement context;
8. verify signed/approved policy state where present;
9. read shared emergency-stop/freeze state;
10. launch White Night full-screen/operator UI.

Integrity failure must be visible and must not silently become trusted state.

## Networking

White Night Live must remain fully useful without Internet access.

Defaults:

- no required cloud login;
- no required telemetry;
- no required SaaS backend;
- no automatic external synchronization;
- no automatic evidence upload.

Local Ethernet/Wi-Fi support may be available for authorized engagement use, but
network-dependent actions still pass shared-core policy.

Update checks are explicit operator actions, not a condition for using the
product.

## Full-stack Live composition

The Live builder must support package profiles rather than separate code forks.

Expected future profiles:

- White Night Live;
- White + Red Live;
- White + selected Nights Live;
- Full NightRecon Live.

All profiles use:

- the same shared-core package;
- the same White app/engine packages;
- the same versioned engagement/evidence contracts;
- the same storage interfaces.

A full-stack Live environment should expose one integrated NightRecon workspace
while preserving independent Night package boundaries.

## Encrypted persistence

Production requirements:

- LUKS2 encrypted persistence;
- no unencrypted customer evidence by default;
- failed unlock does not expose workspace content;
- engagement/evidence/report directories live only in the encrypted workspace
  unless the operator explicitly exports them;
- keys/passphrases are never written into ordinary audit/report content;
- recovery-key handling is documented separately and does not create a universal
  vendor backdoor.

Optional hardware-token-assisted unlock may be added later but must not be
required for the first usable release.

## Secure Boot

Secure Boot is a production target, not a claim for the first alpha.

Development sequence:

1. development images may require Secure Boot to be disabled;
2. beta establishes signed boot-chain compatibility;
3. production acceptance requires documented supported Secure Boot flow and
   compatibility testing across the hardware matrix;
4. unsigned custom kernel modules are not silently loaded in production mode.

Secure Boot support must be verified empirically; booting one development laptop
is not sufficient evidence.

## Image build and release artifacts

Live images must be built from source-controlled configuration.

Target release artifacts:

```
WhiteNight-Live-<version>-amd64.iso
WhiteNight-Live-<version>-amd64.iso.sha256
WhiteNight-Live-<version>-amd64.iso.sig
WhiteNight-Live-<version>-SBOM.json
WhiteNight-Live-<version>-manifest.json
```

The manifest should record at minimum:

- NightRecon package versions;
- base OS/repository snapshot information;
- included packages;
- image fingerprint;
- build source revision;
- schema/build format version.

Manual post-build customization is not an acceptable production release process.

## Reproducibility

The repository must contain the complete intended Live build configuration.

Build inputs should be pinned or recorded sufficiently to recreate and audit a
release. Where byte-for-byte reproducibility is prevented by upstream repository
behavior, the release must still provide deterministic configuration and a
complete package/source manifest.

CI should eventually build the image or a representative deterministic image
fixture and boot it in a VM.

## Updates

Updates must not mutate a field USB unpredictably.

Planned update model:

1. explicit operator check/import;
2. verify signed update metadata;
3. verify compatible White/shared-core/schema versions;
4. stage update;
5. preserve encrypted workspace independently from immutable system image;
6. reboot into new system version;
7. verify migration;
8. retain a bounded rollback path.

Offline update bundles must be supported.

## Recovery

Recovery design must cover:

- interrupted write/power loss;
- unclean USB removal;
- damaged persistent filesystem;
- incompatible workspace schema;
- failed application update;
- failed boot update;
- lost or damaged primary media where an approved encrypted backup exists.

Recovery must preserve evidence provenance and audit history where recoverable.

## Threat model

The Live design explicitly considers:

- lost/stolen USB media;
- unauthorized reading of engagement evidence;
- tampered system image;
- tampered package/update bundle;
- malicious or compromised network;
- malicious USB replacement;
- abrupt power loss/removal;
- hostile or untrusted host disk contents;
- compromised firmware/hardware outside White Night's control;
- rollback to stale authorization;
- copied engagement state;
- expired/revoked approval used offline.

The Live environment cannot guarantee trust in compromised firmware, malicious
hardware, DMA-capable devices, or physical attacks outside the documented
platform assumptions. Such limitations must be stated rather than hidden.

## Host-disk interaction

White Night Live should avoid mounting or modifying internal host disks by
default.

Access to host storage, when ever required for an explicitly authorized workflow,
must be a deliberate action with clear operator visibility.

White evidence storage remains on the encrypted Live workspace or another
explicitly selected approved destination.

## White application presentation

Normal boot should feel like a security appliance, not a generic Linux desktop.

Expected initial presentation:

- integrity status;
- workspace lock/unlock;
- current engagement;
- authorization validity;
- installed Night capabilities;
- evidence/audit state;
- resume/create/import engagement actions.

A maintenance/admin shell may exist for authorized operators but should not be
the default user experience.

## USB creation utility

A later White Night USB Creator should safely provision approved media from a
signed release image.

It should:

- force explicit device selection;
- display destructive-write confirmation;
- verify release signature/hash;
- write the image;
- create/configure encrypted workspace where supported by the provisioning
  model;
- verify the resulting media;
- report success/failure clearly.

The application must be conservative about disk selection to reduce the risk of
destroying the wrong device.

## Initial Live development gates

### Live Batch 1 — build skeleton

Status: completed and CI-verified on `v0.1.0-white-live-batch1-dev`.

Verified acceptance evidence:

- exact White/shared-core wheels built from repository package sources;
- Debian trixie amd64 hybrid ISO built successfully;
- generated ISO SHA-256 sidecar verified;
- image retained as a CI artifact for inspection;
- OVMF/QEMU UEFI boot reaches the deterministic
  `WHITE_NIGHT_LIVE_BOOT_OK` userspace marker with `-nic none`;
- complete NightRecon CI remains green on the Batch 1 head.

Acceptance slice:

- source-controlled Debian trixie `live-build` configuration;
- minimal x86-64 UEFI bootable image using GRUB EFI;
- exact built shared-core + White engine/app wheel artifacts staged into the
  immutable image, without installing or auto-launching White yet;
- explicit non-authoritative, nonpersistent Batch 1 Live profile metadata;
- offline QEMU/OVMF VM boot smoke using `-nic none`;
- deterministic serial readiness marker proving the expected package artifacts
  are present in the booted image.

LUKS2 persistence, application auto-launch, Secure Workspace/Ephemeral/Recovery
runtime behavior, Secure Boot support, host-storage workflows, and composition
remain later Live batches and are not claimed by Batch 1.

### Live Batch 2 — application launch

Status: next active Live increment.

Initial verified slice:

- install the exact staged shared-core, White engine, and White app wheels into
  an isolated runtime inside the immutable image;
- expose the packaged `white-night-app` entry point;
- prove the booted image can execute the White application boundary and load the
  expected package versions with networking disabled;
- keep persistence disabled and host disks untouched.

Follow-on slice:

- automatic White application start;
- appliance-style session;
- no persistent engagement state yet.

### Live Batch 3 — encrypted persistence

- LUKS2 workspace;
- create/reopen engagement across reboot;
- prove ephemeral mode leaves no engagement state behind;
- safe shutdown/removal workflow.

### Live Batch 4 — integrity/recovery

- image/package manifest;
- recovery boot mode;
- persistence integrity checks;
- interrupted-update/recovery tests.

### Live Batch 5 — composition

- White+Red image profile;
- same shared engagement contracts as normal installation;
- no cross-engine imports;
- package removal/isolation tests outside the immutable production image.

### Live Batch 6 — production hardening

- Secure Boot target;
- hardware compatibility matrix;
- signed update/offline bundle flow;
- SBOM;
- performance/endurance testing;
- full-stack profile when the remaining Nights exist.

## Release rule

A feature is not considered Live-compatible merely because its UI opens in the
Live environment.

For White Night deployment parity, its storage, authorization, approval,
evidence, audit, export, migration, and recovery behavior must be verified in
the Live deployment as well as the normal install path.
