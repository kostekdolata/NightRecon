# Red Night Windows installer acceptance

## Scope

This document defines the first native Windows installation surface for Red Night v0.46.6. It is intentionally separate from Live USB hardware qualification.

The Windows installer packages the existing Red application, Red engine, and shared core as one coordinated PyInstaller onedir bundle and installs it with Inno Setup 6.

## Privilege boundary

The installer is per-user and uses `PrivilegesRequired=lowest`. Installing, repairing, or uninstalling Red Night therefore does not require administrator rights merely to copy application files.

Operational Red Night execution retains the `required-platform-privileged` contract. A deliberate launch requests the platform-native elevation boundary once (Windows UAC; Linux/Live root elevation through the platform launcher). After elevation succeeds, that privileged Red Night session is the operator approval boundary: normal commands run directly without a separate workspace/engagement guard ceremony. Command-level `--scope`, bounded execution, credential handling, evidence, result logging, and audit controls remain in force.

`RedNight.exe --deployment-info` is the only non-elevated launcher path. It is non-operational, performs no target action, and reports only package/build compatibility metadata with `authorization_effect=none`.

## Installation locations

Application binaries:

`%LOCALAPPDATA%\Programs\Red Night`

Preserved application-data root:

`%LOCALAPPDATA%\NightRecon\RedNight`

The installer creates preserved `workspaces`, `backups`, and `logs` subdirectories. They inherit the current Windows user's profile ACL boundary. The installer does not claim stronger Windows ACL guarantees than those actually supplied by the user's profile and Windows filesystem policy.

Uninstall removes the application bundle and shortcuts but deliberately preserves the Red Night data root.

## Build integrity

The CI build emits:

- the Windows x64 installer;
- the exact three Red wheel artifacts used by the bundle;
- `build-info.json` beside the executable;
- a CycloneDX environment SBOM;
- a JSON release manifest with SHA-256 hashes;
- `SHA256SUMS.txt`.

The manifest records the source commit and installer version.

## Current capability boundary

The installer bundles the Python dependencies for the existing optional Red integrations. It does not bundle a Playwright Chromium browser binary in this initial Windows installer. Browser-driven assessment therefore remains a separately provisioned optional integration and is not part of the first offline Windows acceptance gate.

The operator-session model removes only the repeated workspace/engagement guard ceremony after platform elevation. Target scope, bounded execution, credential handling, evidence, cleanup, result logging, and audit controls remain in place.

## CI acceptance

The Windows installer workflow must prove:

1. exact package bundle construction;
2. PyInstaller launch of the non-operational deployment-info path;
3. silent per-user install;
4. installed deployment-info compatibility;
5. an installed local-only deployment self-test covering workspace reopen, engagement export, professional report construction, encrypted backup verification, and encrypted restore;
6. creation and preservation of the user data root;
7. silent uninstall removes application binaries;
8. user data survives uninstall;
9. reinstall succeeds with the preserved data and repeats the local-only self-test;
10. integrity manifest and SHA-256 outputs are generated.

A real UAC operational launch, Microsoft Defender/SmartScreen observations, and laptop-specific path/firewall behaviour remain physical Windows acceptance items and must not be claimed from CI.
