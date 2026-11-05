# Red Night managed security tools — deployment contract (draft)

## Goal
Provide Nmap, TShark and other specialist engines through the Red Night installer
without making the operator install each tool manually. This design does not
authorise network scanning, elevate privileges or modify existing installation
behaviour.

## Existing foundation
- `managed_components.py` reads an administrator-supplied manifest and verifies the SHA-256 of an exact allowlisted Nmap, Nuclei, or TShark executable (depending on the release branch).
- The bounded Nmap coordinator is disabled by default.
- External scanning still requires a transactional engagement, scoped target
  and approved `external.nmap.discovery` capability.

## Packaging gates before shipping binaries
1. Confirm the installed Red Night packaging targets and staged artefact layout.
2. Review Nmap redistribution obligations and the licenses of accompanying
   components, including version-specific notices and source provision.
3. For Windows, determine whether Npcap is needed for each enabled capability;
   do not silently install a driver or assume its redistribution is permitted.
4. Use a build-time generated manifest signed or pinned by trusted release
   metadata stored outside the writable components directory. **A manifest
   located alongside the executable is not an independent trust anchor.**
5. Stage managed binaries to an installation directory not writable by ordinary
   assessment users. No automatic download, upgrade, or replacement during scans.
6. Verify executable provenance and integrity at staging time and immediately
   before launch; remove time-of-check/time-of-use risks with OS-specific
   process-launch containment and immutable staged artefacts.
7. Add Windows and Linux installer tests for missing binary, checksum mismatch,
   ACL violations, uninstall, upgrade, preservation and rollback.
8. Run disposable authorized lab tests of scan -> bounded output -> scoped
   evidence -> findings. No live target is configured in CI by default.

## Explicit non-goals for the current batch
No shipping or fetching third-party executables; no bundled Npcap installer;
no assumed commercial redistribution rights; no general shell execution.

## Verified legal distribution decision (2026-10-09)
Nmap's official public licensing pages distinguish end-user installation from
redistribution bundled into third-party software:
- https://nmap.org/npsl/
- https://nmap.org/oem/
- https://nmap.org/book/man-legal.html
- https://github.com/nmap/npcap/blob/master/LICENSE

**Release gate:** Do not distribute the stock Windows Nmap installer, ZIP or
Npcap inside Red Night without documented rights. Official Nmap OEM licensing
is a supported path for embedded redistribution and covers Npcap OEM when used
for Nmap. Otherwise provide a user-directed installation flow and detect an
existing user-installed Nmap; do not silently repackage it. Open-source project
status does not by itself establish rights to redistribute Npcap. Legal review
of applicable exact versions and distributions is required before enabling
`ManagedNmapDir` in a release pipeline.

The current bounded TCP-connect preset uses `-sT` and does not require
the raw-packet scan options that typically depend on Npcap, but Windows
distribution and optional advanced modes still require independent review.

## Current managed executable provenance (beta8)

The resolver's tool allowlist is limited to `nmap[/ .exe]`, `nuclei[/ .exe]`,
and `tshark[/ .exe]` filenames (without the spaces in executable names).
Each tool must have its own manifest entry with a confined relative path and
SHA-256 of its exact installed binary. A discovered PATH executable cannot
replace the independently selected managed component. This only validates
file identity; it **never** authorizes network activity or capture inspection.

**Unresolved production gate:** The manifest is currently read from inside the
managed component directory. It must not be represented as a cryptographically
independent trust anchor until an independently signed/pinned release record
and protected installation ACLs are verified. Do not bundle third-party
executables without the applicable license and redistributability review.
