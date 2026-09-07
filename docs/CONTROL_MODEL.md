# Controls, baselines and verdicts

Schema version 1.0 is enforced by explicit PowerShell 5.1 validators, not PowerShell 7-only Test-Json. Baseline fields are schemaVersion, name, version, engineCompatibility, platform, minimumBuild and a nonempty unique controls array. Versions use three numeric components. The only engine expression supported is `>= x.y.z`; the current baseline requires `>= 0.1.0`. Unknown fields, malformed JSON, duplicate IDs, unsupported providers, traversal IDs and missing files are rejected before collection.

Controls require id, title, description, category, severity, profiles, required (Boolean), expected.state, evidenceProvider, functionalTest.supported (false in foundation), remediationGuidance and references. IDs map through code to exact category paths and providers. Current expected values are deliberately fixed to the five implemented assurance states; new expected states require reviewed code and tests. JSON describes intent and cannot provide scripts, command strings or executable paths. Editing required/severity/profile or baseline versions remains a privileged governance decision.

| Provider | Evidence | Normalized observations |
| --- | --- | --- |
| MDEOnboardingState | HKLM Windows Advanced Threat Protection/Status OnboardingState | 1 Onboarded; 0 NotOnboarded; absent/other Unknown |
| MDESensorService | Win32_Service filtered to Sense | Running, Stopped, Missing; raw startup mode |
| DefenderAntivirus | Get-MpComputerStatus AMRunningMode, AMServiceEnabled, AntivirusEnabled | Normal plus both enabled: Active; Passive/EDR Block: Passive; disabled flags: Disabled; otherwise Unknown |
| RealTimeProtection | Get-MpComputerStatus RealTimeProtectionEnabled | Enabled, Disabled, Unknown |
| NetworkProtection | Get-MpPreference EnableNetworkProtection | 1 Block; 2 Audit; 0 Disabled; other Unknown |

Missing registry values that raise exceptions return ERROR; missing registry keys return Unknown. Read failures return ERROR with a safe category/message. The reported Network Protection preference does not prove traffic blocking, and onboarding does not prove cloud receipt. Functional status is explicitly NOT_IMPLEMENTED.

Control comparisons are exact against normalized canonical values. Inapplicable controls are NOT_APPLICABLE and are not collected. Unknown is REVIEW, except explicit caller `-Provisioning` converts Unknown to PENDING. This switch makes no claim to detect provisioning automatically and does not soften mismatches or errors. There is no indefinite automatic retry; orchestration decides when to recertify.

Overall precedence:

1. Required Critical/High FAIL or ERROR -> FAIL.
2. Required PENDING -> PENDING.
3. Other failures/errors/warnings, optional pending, required NOT_APPLICABLE, or empty results -> REVIEW.
4. Otherwise -> PASS (all required controls pass).

Critical/high counters include required collection errors; the failed counter counts FAIL, while errors has its own counter. Medium/informational required failures and optional failures result in REVIEW. No percentage score can override a failure; foundation does not calculate one.

References: [MDE onboarding troubleshooting](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-onboarding), [Defender status](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus), [Network Protection configuration](https://learn.microsoft.com/en-us/defender-endpoint/enable-network-protection).
