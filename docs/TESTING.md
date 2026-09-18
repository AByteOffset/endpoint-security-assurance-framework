# Testing

The test suite validates the current engine 0.3.0, schema 1.0, Corporate-W11 1.1.0 and support transport 0.1 runtime contracts. Documentation may describe controls as local verification probes and the baseline concept as a future verification profile, but those terms do not change runtime fields or PASS/FAIL behavior. Tests do not establish Microsoft policy assignment, policy delivery, native compliance, cloud telemetry receipt or cryptographic attestation.

`tools/Test-ESAF.ps1` parses every PowerShell source file, parses every repository JSON file, semantically validates the shipped baseline/controls, imports ESAF and runs Pester 5.6.1+. Dependency, output and Git directories are excluded. The Windows Actions job runs these same commands in Windows PowerShell 5.1. No live Defender integration tests run in CI.

```powershell
Install-Module Pester -RequiredVersion 5.6.1 -Scope CurrentUser -Force -SkipPublisherCheck
.\tools\Test-ESAF.ps1
```

`PolicyAssurance.Tests.ps1` exercises the Milestone 4 central reconciliation with synthetic Graph responses and evidence files. It covers both MATCH directions, both MISMATCH directions, unsupported or non-applicable assignments, schema and identity errors, non-collected evidence, sanitized Graph failure, output-path restrictions, least-privilege scope checks, GET-only production code and absence of tenant identifiers or common credential patterns. Pester and CI never call a live Microsoft tenant; live validation follows the separate procedure in [MILESTONE4_POLICY_INTENT_POC.md](MILESTONE4_POLICY_INTENT_POC.md).

`SupportExport.Tests.ps1` exercises Milestone 5 entirely with synthetic TestDrive evidence and transport paths. It covers schema/input validation, exact-source SHA-256, field allowlists, exclusion of raw/error/identity/credential data, canonical immutability, atomic creation and replacement, byte-equivalent adapter output, missing IME behavior, existing ACL utility use, publication ordering, verdict preservation, and the absence of network/Graph/registry/security-control mutation. It also invokes the production security scan. No test uses a live endpoint identifier, tenant or Intune service. The separate generic live procedure is in [MILESTONE5_SUPPORT_EVIDENCE.md](MILESTONE5_SUPPORT_EVIDENCE.md).

Tests mock Windows security providers and privileged write boundaries. Coverage includes provider registry extensibility and command rejection, Boolean/enum normalization, ACL/owner construction, repeated payload copying and obsolete-file removal, baseline validation, applicability, verdicts, errors, Run IDs, history, registry, separate freshness and PENDING semantics. Copy tests use actual temporary filesystem operations; ACL tests build real Windows descriptors but mock Set-Acl. TestDrive outputs are cleaned by Pester. No tests require a live Defender/MDE endpoint.

The historical first-live-test checklist is [LIVE_LAB_CHECKLIST.md](LIVE_LAB_CHECKLIST.md), covering raw Windows/MDE state and ACL comparisons. It is retained as a reference, not a requirement to redo the verified foundation.
The owner subsequently reported successful foundation live validation. Milestone 2 SYSTEM/IME installation and portal compliance were owner-verified. Milestone 3 local endpoint recertification and the optional Intune Custom Compliance path were also completed successfully; see [MILESTONE3_LIVE_VALIDATION.md](MILESTONE3_LIVE_VALIDATION.md) and [VALIDATION_REPORT.md](VALIDATION_REPORT.md). Pilot.Tests.ps1 extends the retained foundation tests with staging/hash validation, actual temporary-file rollback, mutex contention, atomic-publication failure handling, strict result contracts and read-only tooling. All security state and machine deletion/registry boundaries are mocked or redirected into TestDrive.

For later assessment and the separate installer lifecycle milestone, elevate 64-bit Windows PowerShell and run:

```powershell
Import-Module .\src\ESAF.psd1 -Force
$r = Invoke-ESAFValidation
$r.controls | Format-Table id,expected,observed,status
$r | Select-Object runId,status,summary
Get-Content C:\ProgramData\ESAF\result.json -Raw | ConvertFrom-Json
Get-Content C:\ProgramData\ESAF\evidence.json -Raw | ConvertFrom-Json
Get-ItemProperty HKLM:\SOFTWARE\ESAF
.\intune\compliance\Compliance-Discovery.ps1
# Test the installation lifecycle in separate processes (scripts use exit):
$build=.\packaging\Build-ESAFPackage.ps1 -OutputRoot C:\ESAFBuild
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ESAFBuild\ESAF-Package\Install-ESAF.ps1
$LASTEXITCODE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\intune\package\Detect-ESAF.ps1
$LASTEXITCODE
```

Compare local reported states with approved Microsoft read-only diagnostics and the intended Intune baseline. Confirm ACLs, matching Run IDs, history and JSON ingestion. Test a naturally noncompliant lab snapshot or mocks; never disable protection to manufacture failures. Do not run the installer on a developer workstation merely to exercise tests. Provider unit tests do not prove tenant integration, functional enforcement, protected ACL behavior or cloud telemetry delivery.

Future Standard active tests require independent safety review and cleanup tests. Deep tests will be separately authorized and isolated; none are implemented. Next milestone is a documented lab matrix including passive antivirus, provisioning latency, unavailable permissions, legacy baseline applicability and Intune recertification timing.

Expanded.Tests.ps1 covers new provider positive/negative/unknown/error paths, baseline-driven signature age, firewall ActiveStore profiles, OS-drive BitLocker, TPM/Secure Boot availability, sanitized exclusion/ASR inventories, optional assessment verdicts, fourteen-control contracts, staged inventory, version upgrade rejection and passive compliance. Existing installer diagnostics, script-body root resolution, process-only policy, mutex, ACL, hash and publication tests are retained. No test runs live Windows security providers; shims and mocks isolate them. Automated success is not live validation of 0.3.0.

Required-only certification regressions exercise complete fourteen-control results and the independent contract, including optional findings with overall PASS and unchanged counts. Passive discovery is checked for PASS with optional REVIEW/ERROR while retaining the stored findings. Required failure/pending/review precedence and the empty-assessment guard remain tested.
