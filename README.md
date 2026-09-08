# ESAF - Endpoint Security Assurance Framework

Policy deployment is not proof of endpoint protection. Intune can report a policy delivered and MDE can report onboarding without proving the finished device matches its intended security state. ESAF performs a versioned, repeatable assessment and reports assurance through Intune.

ESAF 0.1.1 is a Windows PowerShell 5.1 module with five read-only controls. It writes local evidence, results, history, an operational log, and a small registry summary. Milestone 2 adds deterministic Win32 staging, coordinated deployment, strict result consumption and rollback for one approved Intune pilot device. It is not a security product replacement or a permanent agent.

| Layer | Purpose | Foundation support |
| --- | --- | --- |
| Desired state | Versioned organization baseline | Corporate-W11 1.0.0 |
| Effective local state | What Windows/Defender currently reports | Five providers |
| Functional validation | Prove a control operates using an approved test | Future; never implied by PASS |
| MDE cloud observation | Correlate local execution with observed telemetry | Future central verifier |

Certification records the device, baseline, engine, time, Run ID and evidence. Existing fleet assessment uses the same runner as new-device certification. Recertification follows baseline/engine version changes or an explicit validation request; age alone never fails Win32 detection. Compliance reports CertificationFreshness separately without enforcing an age rule by default. Corporate-W11 applies to Windows client build 22000 or later. Approved legacy clients require a separately reviewed baseline with appropriate constraints; older devices are not silently certified against this baseline.

```text
Intune required Win32 package -> ESAF Runner
  -> baseline and controls -> read-only evidence -> deterministic verdict
  -> ProgramData results/history + HKLM summary
  -> Intune Custom Compliance discovery -> compliance rules
```

| Control | Expected state | Severity |
| --- | --- | --- |
| ESAF-MDE-001: MDE onboarding | Onboarded | Critical |
| ESAF-MDE-002: SENSE service | Running | Critical |
| ESAF-AV-001: Defender Antivirus | Active | Critical |
| ESAF-AV-002: Real-time protection | Enabled | Critical |
| ESAF-NET-001: Network Protection | Block | High |

Required Critical/High FAIL or ERROR produces overall FAIL. Unknown evidence is REVIEW, or PENDING when explicitly running with `-Provisioning`. A known failure is never hidden by provisioning or a score. Required inapplicable controls produce REVIEW rather than certifying an unsupported device.

Run from an elevated **64-bit Windows PowerShell 5.1** prompt on an approved Windows 11 MDE lab device:

```powershell
Import-Module .\src\ESAF.psd1 -Force
$result = Invoke-ESAFValidation
$result | Select-Object runId,status,summary
# Alternatively, concise console output and execution exit code:
powershell.exe -NoProfile -File .\tools\Invoke-ESAF.ps1
Get-Content C:\ProgramData\ESAF\result.json -Raw | ConvertFrom-Json
```

Use your organization's script signing and execution policy. Do not change machine execution policy to deploy ESAF. The wrapper and installer return 0 when execution and publication succeed, including security FAIL. Security verdicts are reported separately through discovery; execution failures return 1.

Run mocked tests (no live security checks):

```powershell
Install-Module Pester -RequiredVersion 5.6.1 -Scope CurrentUser -Force -SkipPublisherCheck
.\tools\Test-ESAF.ps1
```

Safety: no Defender changes, exclusions, ASR changes, firewall changes, remediation, malware, EICAR, Atomic Red Team, arbitrary data-driven commands, endpoint Graph credentials, web server, database or service. Standard mode has no active test execution. Only ESAF files, protected storage and its registry summary are written.

Intune deployment uses a required Win32 package in SYSTEM context and lightweight Custom Compliance. Review [deployment and recertification](docs/INTUNE_DEPLOYMENT.md), [control semantics](docs/CONTROL_MODEL.md), [security model](docs/SECURITY_MODEL.md) and [testing](docs/TESTING.md) before a pilot. Intune compliance is binary: only ESAF PASS meets the included rules; REVIEW, FAIL and PENDING remain distinguishable in discovery data but do not satisfy compliance.

The owner reports successful one-device Intune installation and ESAFStatus = Compliant for engine 0.1.1; see the [validation report](docs/VALIDATION_REPORT.md) for automated checks and live evidence. Follow the [ONE-device Intune pilot guide](docs/INTUNE_PILOT_GUIDE.md). Build staging with `packaging/Build-ESAFPackage.ps1 -OutputRoot C:\ESAFBuild`, then use an approved external Content Prep Tool. This validates the one-device pilot only; broader rollout is not approved. PENDING is never security PASS and needs an explicit later run. No automatic retry service is installed. Desired baseline remains Corporate-W11 1.0.0; engine 0.1.1 changes deployment behavior only.
