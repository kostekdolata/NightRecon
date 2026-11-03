# Nmap Phase 1 — Weekend acceptance and release gates

This checklist is for user-owned or explicitly authorised disposable test VMs.
Do not perform scans of public IPs or unrelated networks.

## Cloud evidence already obtained
- Genuine Ubuntu Nmap TCP-connect run to a test HTTP server on 127.0.0.1
  passed in the Red Night Real Nmap Loopback Lab GitHub workflow.
- That test exercises a genuine installed Nmap executable and the passive
  XML parser. It does NOT exercise transactional engagement enforcement.
- CI workflow results can change with later commits. Verify the branch HEAD
  has passing full NightRecon, importer, Windows installer, and loopback jobs.

## Windows 11 acceptance (local VM or laptop)
- [ ] Download the release candidate from the intended GitHub workflow only.
- [ ] Check publisher, artifact hash and scan the installer; retain evidence.
- [ ] Install as non-admin. Verify launch, user data path, shortcuts and uninstall.
- [ ] Verify Nmap availability through the explicit supported installation
      option. If absent, UI must report unavailable, not silently fall back.
- [ ] Do not install Npcap without separate approval and licensing review.
- [ ] Check any available Nmap binary hash against independently approved metadata.
- [ ] Register an ACTIVE test engagement with a single local VM target and
      the exact external.nmap.discovery capability and limited action budget.
- [ ] Confirm a bounded TCP-connect scan succeeds and imports its XML output.
- [ ] Inspect findings: observations must not be labelled proven CVEs.
- [ ] Test an out-of-scope target: deny before spawning Nmap.
- [ ] Test exhausted budget and duplicate action ID: deny.
- [ ] Pause/revoke an active engagement: verify process termination and audit.
- [ ] Cancel a scan: verify prompt termination, no orphan Nmap descendants,
      and accurate cancellation log.
- [ ] Force timeout and malformed/truncated XML: fail closed and preserve audit.
- [ ] Uninstall and reinstall; inspect retained user files and installed tools.
- [ ] Inspect logs for sensitive data and ensure target scope is explicit.

## Ubuntu VM acceptance
- [ ] Install the supported Nmap package independently on disposable Ubuntu VM.
- [ ] Verify `nmap --version`, installed executable provenance and hash.
- [ ] Repeat authorised, low-rate discovery against a VM-owned lab target.
- [ ] Verify XML import, scope, audit, cancellation, revocation, report and retest.

## Stop/go criteria
- **Do not declare Nmap Phase 1 complete** until the installed Red Night
  application has been verified on Windows and Ubuntu with the governed
  execution path and findings/report pipeline, all release CI is green,
  and the distribution rights for any bundled third-party executables are
  documented.
- Bundle Nmap/Npcap only after version-specific rights are established.
- Keep scans low-impact, explicitly targeted, and human-authorised.
