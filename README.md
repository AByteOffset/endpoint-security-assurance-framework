# ESAF - Endpoint Security Assurance Framework

ESAF is an Endpoint Security Policy Assurance Framework around native Microsoft security controls. Microsoft Defender and Microsoft Intune remain the native Microsoft management, configuration and reporting planes for applicable endpoint security controls. Microsoft Entra remains the identity and access control plane. ESAF independently observes selected effective Windows and platform state.

ESAF 0.2.0 independently observes effective Windows endpoint state through fourteen read-only local verification probes. It compares those observations with reviewed ESAF verification criteria and retains protected point-in-time evidence and history for post-deployment assurance and configuration mismatch or drift investigation. ESAF does not replace Microsoft management, compliance, health, attestation or reporting, and it is not a permanent agent.

| Layer | Purpose | Current support |
| --- | --- | --- |
| Approved organizational policy | Defines the security outcome the organization intends | External to ESAF 0.2.0 |
| Microsoft control plane | Manages, configures and reports applicable native endpoint security controls | Microsoft Defender and Intune |
| Effective local state | What Windows and Defender report on the endpoint | Fourteen ESAF verification probes |
| ESAF comparison criteria | Reviewed local criteria used by schema 1.0 | Corporate-W11 1.1.0 |
| Protected evidence | Point-in-time results and mismatch history | ProgramData history and registry summary |
| Downstream integration | Optionally consumes an ESAF result | Intune Custom Compliance pilot POC |

Corporate-W11 1.1.0 remains the schema 1.0 `baseline` runtime concept for compatibility. Forward-looking architecture may describe its role as a verification profile, but this milestone does not rename files, fields or schemas. ESAF does not currently ingest authoritative policy intent from Intune, Defender, Microsoft Graph, Entra or Microsoft security baselines.

The existing schema 1.0 term “certification” means a completed ESAF assessment that records the device, baseline, engine, time, Run ID and evidence. ESAF is a privileged local assessor; it does not provide independent cryptographic certification or attestation. Existing fleet assessment and new-device verification use the same runner. Reassessment follows baseline/engine version changes or an explicit validation request; age alone never fails Win32 detection.

```text
Approved organizational security policy
  -> Microsoft Defender / Intune configuration and deployment
  -> effective Windows endpoint state
  -> independent ESAF local verification probes
  -> comparison with reviewed ESAF schema 1.0 criteria
  -> protected evidence / assessment history
  -> optional downstream integrations
```

| Control | Expected state | Severity |
| --- | --- | --- |
| ESAF-MDE-001: MDE onboarding | Onboarded | Critical |
| ESAF-MDE-002: SENSE service | Running | Critical |
| ESAF-AV-001: Defender Antivirus | Active | Critical |
| ESAF-AV-002: Real-time protection | Enabled | Critical |
| ESAF-NET-001: Network Protection | Block | High |
| ESAF-AV-003: Cloud/MAPS participation | Enabled | High |
| ESAF-AV-004: Security intelligence | Fresh, at most 72 hours | High |
| ESAF-AV-005: Tamper Protection | Enabled | Critical |
| ESAF-AV-006: Visible exclusions | Clear; presence yields REVIEW | Informational, optional |
| ESAF-NET-002: Firewall profiles | Domain, Private, Public enabled | High |
| ESAF-DISK-001: OS BitLocker | Fully encrypted, protection on | High |
| ESAF-HW-001: TPM | Present and ready | High |
| ESAF-HW-002: Secure Boot | Enabled | High |
| ESAF-ASR-001: ASR inventory | Assessed; no required rule set | Informational, optional |

The fourteen controls listed above are local verification probes for Microsoft-managed endpoint security capabilities. They observe; they do not configure Defender, Intune, Windows or Entra. Their presence does not imply that Microsoft lacks native management, compliance, health, attestation or reporting for the same capabilities.

Required Critical/High FAIL or ERROR produces overall FAIL. Unknown evidence is REVIEW, or PENDING when explicitly running with `-Provisioning`. A known failure is never hidden by provisioning or a score. Required inapplicable controls produce REVIEW rather than certifying an unsupported device.

PASS means that the locally observed state satisfied the current ESAF verification criterion. PASS does not prove policy assignment, successful Microsoft policy delivery, functional blocking, cloud telemetry receipt, cryptographic attestation, absence of hidden configuration or native Microsoft compliance.

Run from an elevated **64-bit Windows PowerShell 5.1** prompt on an approved Windows 11 MDE lab device:

```powershell
Import-Module .\src\ESAF.psd1 -Force
$result = Invoke-ESAFValidation
$result | Select-Object runId,status,summary
# Alternatively, concise console output and execution exit code:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Invoke-ESAF.ps1
Get-Content C:\ProgramData\ESAF\result.json -Raw | ConvertFrom-Json
```

Use your organization's script signing and execution policy. Do not change machine execution policy to deploy ESAF. The wrapper and installer return 0 when execution and publication succeed, including security FAIL. Security verdicts are reported separately through discovery; execution failures return 1.

Run mocked tests (no live security checks):

```powershell
Install-Module Pester -RequiredVersion 5.6.1 -Scope CurrentUser -Force -SkipPublisherCheck
.\tools\Test-ESAF.ps1
```

Safety: no Defender changes, exclusions, ASR changes, firewall changes, remediation, malware, EICAR, Atomic Red Team, arbitrary data-driven commands, endpoint Graph credentials, web server, database or service. Standard mode has no active test execution. Only ESAF files, protected storage and its registry summary are written.

Intune Win32 deployment is one delivery option for running ESAF in SYSTEM context. The included Intune Custom Compliance integration is an optional downstream adapter and a successful one-device proof of concept. Organizations should continue using native Intune compliance when a native Microsoft compliance control directly represents the requirement. The ESAF adapter may be appropriate for an explicitly approved assurance requirement that native compliance does not adequately represent. Review [deployment and recertification](docs/INTUNE_DEPLOYMENT.md), [control semantics](docs/CONTROL_MODEL.md), [security model](docs/SECURITY_MODEL.md) and [testing](docs/TESTING.md) before using it. The unchanged pilot rule is binary: only ESAF PASS satisfies it.

ESAF does not send a direct trust signal to Entra and is not a Conditional Access replacement or policy-decision engine. Entra Conditional Access may consume the resulting Intune compliance state for access decisions when an organization explicitly configures that relationship.

The owner has now validated engine 0.2.0 / Corporate-W11 1.1.0 through the complete one-device chain on `DESKTOP-GFRP15O`. Version-aware detection rejected the old 0.1.1 / 1.0.0 certification, Intune installed the update, ESAF accurately returned FAIL for BitLocker off and Secure Boot disabled, and the unchanged Custom Compliance rule reported the device Not compliant in Intune and Company Portal. See the [validation report](docs/VALIDATION_REPORT.md) for the separation between automated, endpoint, and portal evidence. This validates the Milestone 3 one-device scope only; broader rollout is not approved. No automatic retry service is installed.

ASR PASS means the local inventory was successfully assessed, not that a universal ASR protection baseline was met. Visible exclusions remain individual REVIEW; unknown/error/pending assessment findings remain visible. Optional findings and their summary counts do not downgrade overall certification when required controls are satisfied. Overall Custom Compliance still enforces only ESAFStatus=PASS. Details and source references are in [the expanded control model](docs/CONTROL_MODEL.md).
