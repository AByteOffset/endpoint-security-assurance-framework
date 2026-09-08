# Milestone 3 validation report

## Automated validation

The complete Windows PowerShell 5.1 Pester suite passes 153 tests, with 0 failures, skips, or inconclusive results. The production security scan passes, and the repository secret scan finds no matches. These development checks are distinct from the owner-confirmed live evidence below. Tests use mocked Windows security providers and isolated filesystem and registry boundaries; they do not replace endpoint or Intune validation.

Coverage includes all fourteen controls, provider positive/negative/unavailable/error states, baseline-driven signature freshness, sanitized exclusion and ASR evidence, required-only aggregate verdicts, the fourteen-control result contract, deterministic packaging, version-aware detection, passive Custom Compliance, and all retained Milestone 2 installation hardening. The repository workflow runs the same suite and security scan; consult PR #3 checks for its remote result.

## Owner-confirmed live endpoint validation — 2026-09-08

The project owner completed Milestone 3 validation on `DESKTOP-GFRP15O`. This evidence was supplied by the owner; the development agent did not independently operate or inspect the VM or tenant.

The installed engine upgraded from 0.1.1 to 0.2.0, and Corporate-W11 upgraded from baseline 1.0.0 to 1.1.0. Before upgrade, the Milestone 3 detection script returned exit code 1 against the old installation, proving that 0.1.1 / 1.0.0 was no longer current and recertification was required.

| Evidence | Confirmed value |
| --- | --- |
| Old Run ID | `ESAF-20260908-4180E576390BD031F3893333FE968A80` |
| Old result SHA-256 | `C89D79664A8E38711397C8A0BBCD2A2EAB29EB5A36897C26D094D1D852DFAE21` |
| New Run ID | `ESAF-20260908-0DED50AE5202FD2855607798E05B80E4` |
| New completion time | `2026-09-08T21:42:18.9242558Z` |
| Overall status | `FAIL` |
| Summary | 12 passed, 2 failed, 0 review, 0 pending, 0 errors |
| Failure counts | 0 critical, 2 high |

The two failures are accurate endpoint security-assurance findings, not framework defects:

- `ESAF-DISK-001` expected `Protected` and observed `Off`. Independent `Get-BitLockerVolume` output showed `C:` as `FullyDecrypted`, protection `Off`, and encryption percentage 0.
- `ESAF-HW-002` expected `Enabled` and observed `Disabled`. Independent `Confirm-SecureBootUEFI` returned `False`.

The other new controls matched independent local Windows state:

- MAPSReporting 2 normalized to CloudProtection `Enabled / PASS`.
- The Defender antivirus signature timestamp was present and within the 72-hour baseline, producing `Fresh / PASS`.
- IsTamperProtected was True, producing `Enabled / PASS`.
- Visible Defender exclusion counts were Path 0, Process 0, Extension 0, and IP 0, producing `Clear / PASS`.
- Domain, Private, and Public firewall profiles were all True, producing `Enabled / PASS`.
- TPM was present and ready, producing `Ready / PASS`.
- ASR inventory was collected successfully, producing `Assessed / PASS`.

The installed verifier returned Engine PASS, Baseline PASS, ResultIntegrity PASS, RegistryConsistency PASS, StorageAcl PASS, LatestRunId `ESAF-20260908-0DED50AE5202FD2855607798E05B80E4`, and Certification FAIL. `Certification FAIL` is the expected, correct assurance outcome for two required high-severity mismatches. Installation and publication succeeded; an ESAF security verdict of FAIL is not an installer failure.

Protected history was preserved at `C:\ProgramData\ESAF\history` for these runs:

- `ESAF-20260907-F4233EC9C04220E8AA463F641F3DD644`
- `ESAF-20260908-4180E576390BD031F3893333FE968A80`
- `ESAF-20260908-0DED50AE5202FD2855607798E05B80E4`

Historical Milestone 2 evidence remains in [MILESTONE2_VALIDATION_REPORT.md](MILESTONE2_VALIDATION_REPORT.md).

## Owner-confirmed Intune portal validation

The existing Win32 app was updated in place to `ESAF - Endpoint Security Assurance Framework 0.2.0 - Pilot`. Intune reported Device install status `Installed`; the assignment remained limited to `MDE-LAB-DEVICES`. Custom Compliance discovery required engine 0.2.0 and baseline 1.1.0, while the rule remained `ESAFStatus = PASS`.

Company Portal displayed `Can't access company resources` and `Endpoint assurance requires attention`. The Intune compliance policy ultimately showed Compliant 0, Noncompliant 1, and `DESKTOP-GFRP15O = Not compliant`. The latest observed Intune compliance contact was approximately `09/08/2026 5:50 PM`.

This validates the full Milestone 3 chain:

```text
Intune Win32 deployment -> ESAF certification -> local evidence -> ESAF FAIL
-> Custom Compliance -> Intune Noncompliant -> Company Portal enforcement
```

The two endpoint gaps correctly drove the overall FAIL and the unchanged Intune rule correctly produced Noncompliant. No remediation was performed or implied.

## Scope and limitations

Milestone 3 automated validation, one-device endpoint validation, version-aware recertification, installation integrity, evidence history, Custom Compliance ingestion, Intune noncompliance, and Company Portal enforcement are now owner-confirmed. PR #3 is ready for merge review within this milestone's one-device pilot scope; it remains open and must not be merged automatically.

This evidence is not production rollout approval, broad hardware compatibility, ARM64 validation, functional attack-blocking proof, or cryptographic attestation. MAPS remains a local participation setting rather than proof of cloud connectivity. Empty visible exclusions cannot disprove hidden exclusions, and ASR `Assessed` confirms inventory collection rather than a universal ASR policy. Local administrators remain outside the attestation boundary. Engine 0.2.0, Corporate-W11 1.1.0, providers, verdicts, installer, detection, and compliance behavior are unchanged by this documentation update.
