# Controls, baselines and verdicts

The existing fourteen controls are local verification probes for Microsoft-managed endpoint security capabilities. Each probe independently observes effective endpoint state; it does not configure the capability or imply that Microsoft lacks native policy, compliance, health, attestation or reporting.

Corporate-W11 1.1.0 remains the schema 1.0 `baseline` runtime concept for compatibility. Forward-looking architecture may call this role a verification profile, but no file, field or schema is renamed in this milestone. The baseline and control definitions are locally authored and reviewed; ESAF does not currently import authoritative Microsoft policy intent.

`expected.state` is a reviewed ESAF schema 1.0 comparison criterion. It is not an expectation retrieved from Intune, Defender, Microsoft Graph, Entra or a Microsoft security baseline. PASS means only that the locally observed state satisfied that criterion. It does not prove policy assignment, Microsoft policy delivery, functional blocking, cloud telemetry receipt, cryptographic attestation, absence of hidden configuration or native Microsoft compliance.

“Certification” remains the schema 1.0 runtime term for a completed ESAF assessment. ESAF is a privileged local assessor, not an independent certification or attestation authority.

Schema version 1.0 is enforced by explicit PowerShell 5.1 validators, not PowerShell 7-only Test-Json. Baseline fields are schemaVersion, name, version, engineCompatibility, platform, minimumBuild and a nonempty unique controls array. Versions use three numeric components. The only engine expression supported is `>= x.y.z`; the current baseline requires `>= 0.1.0`. Unknown fields, malformed JSON, duplicate IDs, unsupported providers, traversal IDs and missing files are rejected before collection.

Controls require id, title, description, category, severity, profiles, required (Boolean), expected.state, evidenceProvider, functionalTest.supported (false in foundation), remediationGuidance and references. ID prefixes select category directories; there is no individual-control-ID dispatch table. Get-ESAFProviderRegistry maps approved provider names to internal functions, categories and allowed normalized expected-state domains. JSON selects an exact provider key and supplies expected.state. A new ESAF-NET-099 control can reuse NetworkProtection and expect Audit without changing dispatch code. Unknown fields, executable-looking provider names, invalid categories and expected states outside the provider domain are rejected. Unknown/Error cannot be desired states. Corporate-W11 1.1.0 retains its original five expectations and adds nine controls. Less restrictive expectations in other baselines require explicit governance review; ESAF does not alter endpoint policy.

| Provider | Evidence | Normalized observations |
| --- | --- | --- |
| MDEOnboardingState | HKLM Windows Advanced Threat Protection/Status OnboardingState | 1 Onboarded; 0 NotOnboarded; absent/other Unknown |
| MDESensorService | Win32_Service filtered to Sense | Running, Stopped, Paused, Missing; transitional/other states Unknown; raw State and StartMode |
| DefenderAntivirus | Get-MpComputerStatus AMRunningMode, AMServiceEnabled, AntivirusEnabled | Normal plus both enabled: Active; Passive/EDR Block: Passive; disabled flags: Disabled; otherwise Unknown |
| RealTimeProtection | Get-MpComputerStatus RealTimeProtectionEnabled | Enabled, Disabled, Unknown |
| NetworkProtection | Get-MpPreference EnableNetworkProtection | 1 / Enabled -> Block; 2 / AuditMode -> Audit; 0 / Disabled -> Disabled; numeric strings accepted; other Unknown |

Missing onboarding keys or OnboardingState properties return Unknown; access/collection failures return ERROR. Normalization functions preserve original Windows property names/values in evidence.raw and place the canonical value in evidence.observed and result.controls.observed. Boolean properties must actually be Boolean; missing/string values do not become True through coercion. Antivirus recognizes Normal, Passive, Passive Mode, SxS Passive Mode and EDR Block Mode explicitly; only Normal plus both true operational flags is Active. Unknown mode text is not matched by a broad substring. The reported Network Protection preference does not prove traffic blocking, and onboarding does not prove cloud receipt. Functional status is explicitly NOT_IMPLEMENTED.

Control comparisons are exact against normalized canonical values. Inapplicable controls are NOT_APPLICABLE and are not collected. Unknown is REVIEW, except explicit caller `-Provisioning` converts Unknown to PENDING. This switch makes no claim to detect provisioning automatically and does not soften mismatches or errors. There is no indefinite automatic retry; orchestration decides when to recertify.

Overall precedence:

1. Required Critical/High FAIL or ERROR -> FAIL.
2. Required PENDING -> PENDING.
3. Other failures/errors/warnings, optional pending, required NOT_APPLICABLE, or empty results -> REVIEW.
4. Otherwise -> PASS (all required controls pass).

Critical/high counters include required collection errors; the failed counter counts FAIL, while errors has its own counter. Medium/informational required failures and optional failures result in REVIEW. No percentage score can override a failure; foundation does not calculate one.

References: [MDE onboarding troubleshooting](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-onboarding), [Defender status](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus), [Defender running modes](https://learn.microsoft.com/en-us/defender-endpoint/edr-block-mode-faqs), [Network Protection configuration](https://learn.microsoft.com/en-us/defender-endpoint/enable-network-protection). These sources inform normalization; Milestone 2 live comparison covered the original five; new providers require Milestone 3 live comparison.

## Expanded providers (engine 0.2.0 / Corporate-W11 1.1.0)

| Control | Provider / local source | Normalization and evidence |
| --- | --- | --- |
| AV-003 | CloudProtection / Get-MpPreference MAPSReporting | 0/Disabled -> Disabled; 1/Basic or 2/Advanced -> Enabled; absent/other -> Unknown. Local participation only. |
| AV-004 | SecurityIntelligence / Get-MpComputerStatus AntivirusSignatureLastUpdated | UTC age <= baseline securityIntelligenceMaxAgeHours (72) -> Fresh; greater -> Stale; missing/sentinel -> Missing; future -> Unknown; malformed -> ERROR. Age/UTC timestamp/assessment time/threshold in evidence. |
| AV-005 | TamperProtection / Get-MpComputerStatus IsTamperProtected | Strict Boolean Enabled/Disabled; unavailable -> Unknown. Critical and required. |
| AV-006 | DefenderExclusions / Get-MpPreference | Counts for Path/Process/Extension/IpAddress only. Present -> REVIEW; no visible entries -> Clear/PASS; unavailable categories -> Unknown. Optional informational, not proof of absence of hidden exclusions. |
| NET-002 | WindowsFirewall / Get-NetFirewallProfile ActiveStore | Require exactly one Domain, Private and Public profile, all Enabled; any Disabled -> Disabled/FAIL; missing/ambiguous -> Unknown unless a known disabled profile exists. All three profiles apply to this baseline, including inactive profiles. |
| DISK-001 | BitLockerOS / Get-BitLockerVolume | OS drive from Win32_OperatingSystem.SystemDrive. FullyEncrypted+On -> Protected; FullyEncrypted+Off -> Suspended; decrypted/decrypting -> Off; encrypting/paused -> InProgress; unrecognized/unavailable -> Unknown. No recovery data retained. |
| HW-001 | TPMReadiness / Get-Tpm | Present+ready -> Ready; absent -> Missing; present/not ready -> NotReady; unavailable -> Unknown. Only presence/readiness retained. |
| HW-002 | SecureBoot / Confirm-SecureBootUEFI | Boolean Enabled/Disabled; typed unsupported -> Unsupported/FAIL; other exceptions -> provider ERROR. Non-UEFI/localized errors may be ERROR rather than Unsupported, never PASS. |
| ASR-001 | ASRAssessment / Get-MpPreference | Pair GUIDs/actions, sort IDs, summarize Disabled=0, Block=1, Audit=2, Warn=6 and named equivalents. Unknown action -> Unknown/REVIEW. Invalid/mismatched/duplicate IDs -> ERROR. Assessed/PASS means inventory collection only, including an empty inventory; no universal rule set is enforced. Optional informational. |

Required new controls are high except Tamper Protection (critical). Known adverse states produce FAIL, including suspended/in-progress BitLocker. Provider ERROR fails required high/critical controls under the unchanged aggregate model. Unknown is REVIEW or PENDING only under explicit provisioning. Unsupported does not silently exempt a Corporate-W11 requirement. Optional errors, unknown states, pending assessments and visible exclusions remain in individual statuses and summary counts but do not downgrade overall certification. Required critical/high FAIL or ERROR yields FAIL; required PENDING takes next precedence; unresolved required REVIEW/NOT_APPLICABLE or other required failure/error yields REVIEW. If required controls are satisfied, overall PASS is retained despite optional findings. An empty assessment remains REVIEW. Intune still enforces only ESAFStatus=PASS. Advice remains administrator review, never automatic remediation.


The included Custom Compliance rule is an optional downstream adapter retained from the successful one-device pilot. Native Intune compliance should remain the preferred mechanism when a native Microsoft compliance setting directly represents the requirement. ESAF Custom Compliance is intended for an explicitly approved assurance requirement that native compliance does not adequately represent; the adapter does not make ESAF the management or access-control plane.

Sources: [Defender status](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus), [Defender preferences and enum domains](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference), [BitLocker status](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide), [TPM status](https://learn.microsoft.com/en-us/powershell/module/trustedplatformmodule/get-tpm), [Secure Boot status and unsupported platforms](https://learn.microsoft.com/en-us/powershell/module/secureboot/confirm-securebootuefi), [Firewall ActiveStore](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile). Configuration documentation is used only to interpret states; ESAF never calls setters.
