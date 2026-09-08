# Testing

`tools/Test-ESAF.ps1` parses every PowerShell source file, parses every repository JSON file, semantically validates the shipped baseline/controls, imports ESAF and runs Pester 5.6.1+. Dependency, output and Git directories are excluded. The Windows Actions job runs these same commands in Windows PowerShell 5.1. No live Defender integration tests run in CI.

```powershell
Install-Module Pester -RequiredVersion 5.6.1 -Scope CurrentUser -Force -SkipPublisherCheck
.\tools\Test-ESAF.ps1
```

Tests mock Windows security providers and privileged write boundaries. Coverage includes provider registry extensibility and command rejection, Boolean/enum normalization, ACL/owner construction, repeated payload copying and obsolete-file removal, baseline validation, applicability, verdicts, errors, Run IDs, history, registry, separate freshness and PENDING semantics. Copy tests use actual temporary filesystem operations; ACL tests build real Windows descriptors but mock Set-Acl. TestDrive outputs are cleaned by Pester. No tests require a live Defender/MDE endpoint.

The historical first-live-test checklist is [LIVE_LAB_CHECKLIST.md](LIVE_LAB_CHECKLIST.md), covering raw Windows/MDE state and ACL comparisons. It is retained as a reference, not a requirement to redo the verified foundation.
The owner subsequently reported successful foundation live validation. For Milestone 2 use INTUNE_PILOT_GUIDE.md instead; real Intune SYSTEM/IME execution and portal results remain pending. Pilot.Tests.ps1 extends the retained foundation tests with staging/hash validation, actual temporary-file rollback, mutex contention, atomic-publication failure handling, strict result contracts and read-only tooling. All security state and machine deletion/registry boundaries are mocked or redirected into TestDrive.

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
powershell.exe -NoProfile -File C:\ESAFBuild\ESAF-Package\Install-ESAF.ps1
$LASTEXITCODE
powershell.exe -NoProfile -File .\intune\package\Detect-ESAF.ps1
$LASTEXITCODE
```

Compare local reported states with approved Microsoft read-only diagnostics and the intended Intune baseline. Confirm ACLs, matching Run IDs, history and JSON ingestion. Test a naturally noncompliant lab snapshot or mocks; never disable protection to manufacture failures. Do not run the installer on a developer workstation merely to exercise tests. Provider unit tests do not prove tenant integration, functional enforcement, protected ACL behavior or cloud telemetry delivery.

Future Standard active tests require independent safety review and cleanup tests. Deep tests will be separately authorized and isolated; none are implemented. Next milestone is a documented lab matrix including passive antivirus, provisioning latency, unavailable permissions, legacy baseline applicability and Intune recertification timing.
