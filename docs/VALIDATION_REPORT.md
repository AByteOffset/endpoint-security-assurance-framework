# Milestone 3 validation report

## Automated coverage

The full Windows PowerShell 5.1 Pester suite currently passes 153 tests, with 0 failures, skips or inconclusive results. All 75 Milestone 2 tests remain, with version/count fixtures updated for the expanded baseline. The production security scan passes. Expanded coverage includes every new provider's positive/negative/unavailable/error behavior, timestamp freshness policy, ASR action normalization, redacted exclusions, required versus optional verdicts, complete fourteen-control contracts, physical old-version detection, passive compliance and deterministic staging.

Tests use mocked Windows security providers and isolated filesystem/registry boundaries. They do not execute live security collection on this development machine or establish Intune recertification success. New ACL persistence checks retain the documented privileged-boundary mocks. The repository workflow runs the same full suite and scan; consult the Milestone 3 PR checks for actual CI status.

## Local lab validation — pending

Abhijeet has not yet live-validated engine 0.2.0 / Corporate-W11 1.1.0 on DESKTOP-GFRP15O. No new control is claimed as live PASS. Compare normalized states and protected evidence with actual local Windows output using [MILESTONE3_LIVE_VALIDATION.md](MILESTONE3_LIVE_VALIDATION.md). PASS, REVIEW, FAIL or explicit provider ERROR must reflect the VM, not a desired demo outcome.

The owner previously proved the five-control engine 0.1.1 / baseline 1.0.0 pipeline: Installed, all verifier checks PASS, restricted ACLs and Intune ESAFStatus Compliant on DESKTOP-GFRP15O, Run ID ESAF-20260908-4180E576390BD031F3893333FE968A80. That historical evidence is preserved in [MILESTONE2_VALIDATION_REPORT.md](MILESTONE2_VALIDATION_REPORT.md). It does not certify new controls.

## Real Intune recertification — pending

The approved next validation is the existing one-device Win32 app upgrade from 0.1.1 / 1.0.0 to 0.2.0 / 1.1.0, including old-version detection failure, new SYSTEM run ID/timestamp, all fourteen controls, installed verifier/ACLs and portal compliance. No app, group, assignment or compliance policy was changed by this implementation. No .intunewin or live run is claimed; use the approved external Content Prep Tool after staging. Milestone 3 remains open for review and live validation; do not merge automatically.

## Design decisions and limitations

- Signature freshness is baseline-driven: securityIntelligenceMaxAgeHours=72, validated integer range 1-720. Changing requirements requires another baseline-version decision. Future timestamps are Unknown; absent timestamps are Missing; malformed/provider errors never PASS.
- All Domain/Private/Public firewall profiles are required, even when currently inactive. BitLocker encryption in progress or suspended protection fails this protection requirement; no state changes are performed.
- Secure Boot unsupported/non-UEFI can appear as Unsupported or ERROR depending on Windows exception type. Missing modules/permissions are explicit errors, never PASS. TPM readiness is local only.
- ASR Assessed/PASS means inventory collected, including an empty inventory; no universal ASR rule set is certified. Visible exclusions yield optional REVIEW. Optional findings never downgrade overall certification by themselves. Individual REVIEW/ERROR/PENDING and all summary counts remain visible; if all required controls pass, overall PASS meets the unchanged Intune PASS rule.
- Local preference visibility is not online effectiveness testing. Hidden exclusions cannot be ruled out. Recovery keys, TPM owner authorization and raw exclusion values are omitted. No Graph identity, cloud verification, EICAR, Atomic tests, attack simulation, remediation or permanent agent was added.
- Engine/baseline detection is 0.2.0 / 1.1.0; result schema remains 1.0. The original five protective expectations, required failure precedence, process-only Bypass, script-body root resolution, protected diagnostics, mutex, ACLs, hashes, atomic files and registry commit marker remain. No periodic reinstall/recertification service is added.

## Required-only aggregate correction before live validation

Fourteen new regression cases cover optional exclusions/ASR REVIEW, optional ERROR/PENDING/NOT_APPLICABLE, simultaneous visible summary counts, required FAIL/ERROR/REVIEW/PENDING/NOT_APPLICABLE precedence, lower-severity required failures and passive compliance output. Get-ESAFVerdict and the independent ResultContract aggregate validation now apply the same required-only selection. No individual provider/control finding is coerced to PASS. Schema, versions (0.2.0 / 1.1.0), detection script, installer, providers and the ESAFStatus=PASS JSON rule are unchanged. No live VM or Intune validation was performed.
