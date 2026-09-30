# White Night Live — Encrypted Workspace Contract

This document defines the acceptance contract for White Night Live Secure
Workspace persistence before any LUKS2 provisioning or unlock code is added.

It is intentionally stricter than a generic Linux persistence setup. White Night
must never gain convenience at the cost of mounting, formatting, or trusting an
unexpected host disk.

## Scope

This contract covers the first encrypted-persistence implementation for White
Night Live.

It does not define a USB Creator UI, production key escrow, Secure Boot,
hardware-token unlock, remote recovery, or full-stack Night composition.

## Locked storage model

Secure Workspace uses a dedicated LUKS2 container owned by the White Night Live
deployment layer.

The unlocked filesystem is mounted only at:

`/var/lib/nightrecon-workspace`

The decrypted mapper name is fixed and non-user-derived:

`nightrecon-white-workspace`

Application state stored there includes:

- engagements;
- compiled policy state;
- approvals;
- evidence;
- custody/audit state;
- reports;
- operator-safe configuration;
- controlled migration metadata.

The immutable operating-system image and the encrypted workspace remain separate
failure domains.

## Provisioning boundary

Provisioning and runtime unlock are separate capabilities.

Runtime boot must never create or format a LUKS container.

The first implementation must refuse to format arbitrary discovered block
devices. Provisioning requires an explicitly supplied, operator-selected target
and an explicit destructive action outside normal boot.

Automated CI provisioning may use only disposable test-backed storage created by
the test itself.

## Runtime discovery and fail-closed behavior

Secure Workspace boot must not scan and mount general host filesystems.

It may inspect only the specifically configured White workspace target.

If the expected encrypted workspace is absent, malformed, has an unexpected
type, cannot be unlocked, or fails schema/integrity checks:

- Secure Workspace does not launch the White operator application;
- no fallback to unencrypted persistence occurs;
- no host filesystem is mounted as a substitute;
- the failure is explicit and auditable;
- Recovery remains available as a separate maintenance path.

Imported evidence or workspace data never grants authorization.

## Encryption requirements

The production storage format is LUKS2.

Initial requirements:

- LUKS2 only; legacy LUKS1 is not accepted for new provisioning;
- no plaintext customer workspace by default;
- passphrases/keys are never written to command history, application logs,
  reports, audit payloads, environment variables, or kernel command-line
  parameters;
- there is no universal vendor recovery key;
- unlock secrets are passed through a non-logging secret input path;
- mapper and mount state are closed cleanly during shutdown where possible.

Hardware-token-assisted unlock is optional later and must not weaken this
baseline.

## Workspace identity

Each initialized encrypted workspace contains a private metadata file inside the
encrypted filesystem.

Minimum metadata:

- schema version;
- workspace UUID;
- product: White Night;
- creation format version;
- compatible White/shared-core schema range;
- no authorization effect.

The metadata is not considered proof of authorization or operator identity.

## Mode behavior

### Secure Workspace

- requires successful LUKS2 unlock;
- mounts the workspace at the fixed mount point;
- validates workspace metadata before application launch;
- persists engagement state across reboot;
- launches White only after all checks succeed.

### Ephemeral Session

- does not unlock or mount the encrypted workspace automatically;
- does not write engagement state into the persistent workspace;
- shutdown/reboot must remove all temporary engagement state created by the
  Ephemeral session unless the operator explicitly exports it.

### Recovery & Integrity Check

- may inspect encrypted-workspace availability;
- must not silently convert a failed Secure Workspace boot into a writable
  recovery mount;
- writable repair actions require an explicit recovery workflow;
- normal engagement auto-start remains disabled.

## Filesystem and permissions

The first implementation should use a Linux filesystem suitable for removable
encrypted media and crash recovery.

Regardless of filesystem choice:

- the mount root is not world-readable;
- application-owned directories are least-privilege;
- customer evidence is never duplicated into an unencrypted convenience path;
- temporary secret material is not persisted.

The exact filesystem choice is an implementation decision and must be recorded
in the release manifest.

## Shutdown and removal

Normal Secure Workspace shutdown should:

1. stop White application writes;
2. flush pending application state;
3. unmount the encrypted filesystem;
4. close the LUKS mapper;
5. report whether the workspace closed cleanly.

Unexpected power loss/removal must be covered by later recovery tests.

## First CI acceptance fixture

The first verified LUKS2 implementation must use disposable storage created
inside CI. It must not depend on a real host disk.

Required test sequence:

1. create disposable backing storage;
2. provision it as LUKS2 using a test-only secret;
3. create the workspace filesystem and metadata;
4. unlock and mount it;
5. write a deterministic engagement-state fixture;
6. close the mapper cleanly;
7. reopen the same encrypted workspace in a second boot/test phase;
8. prove the deterministic state survived;
9. run an Ephemeral phase and prove it did not modify persistent engagement
   state;
10. prove a wrong secret fails closed;
11. prove a malformed/non-LUKS target fails closed;
12. prove no unrelated host filesystem is mounted or modified.

Test secrets must be synthetic and must never appear in retained artifacts.

## Safety assertions required in tests

Automated tests must prove at minimum:

- no call to `luksFormat` occurs during normal Secure Workspace boot;
- no automatic formatting of `/dev/sd*` or `/dev/nvme*`;
- no generic `mount /dev/...` fallback;
- Secure Workspace requires verified encrypted state before app startup;
- Ephemeral does not mount the persistent workspace;
- Recovery does not auto-start an engagement;
- workspace metadata has `authorization_effect: none`;
- unlock failure cannot silently downgrade into unencrypted operation;
- secrets are absent from generated reports, logs, and retained CI artifacts.

## Initial implementation order

1. storage-domain contract and tests;
2. disposable LUKS2 CI fixture;
3. explicit provisioning helper for disposable/approved targets only;
4. Secure Workspace unlock + mount service;
5. workspace metadata validation;
6. second-boot persistence verification;
7. Ephemeral non-persistence verification;
8. clean shutdown/unmount/mapper-close path;
9. recovery inspection path;
10. field-media provisioning design.

Production USB partitioning/provisioning comes after the above behavior is
verified against disposable storage.

## Acceptance rule

White Night Live may not report `secure_workspace_ready: true` until the
encrypted workspace has been unlocked, mounted, validated, and proven usable by
the current boot.

Recognizing the Secure Workspace menu entry is not sufficient.

A failed encrypted-workspace check always leaves Secure Workspace unavailable.
