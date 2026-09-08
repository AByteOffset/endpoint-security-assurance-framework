Historical Milestone 2 evidence snapshot, retained for provenance. PR-state statements below describe that milestone at validation time, not the current Milestone 3 PR.

# Milestone 2 validation report

## Automated validation

The complete Windows PowerShell 5.1 Pester suite passes 75 tests, with 0 failures, skips or inconclusive results. Production security scanning passes and the tracked-file secret scan finds no matches. These are development checks, distinct from the owner-reported live Intune evidence below. CI runs the same suite and security scan; consult PR #2 checks for each remote run result.

Coverage includes baseline/control validation, evidence normalization, verdict logic, result/registry consistency, protected ACL intent, deterministic staging and SHA-256 integrity rejection, installation success/failure separation, module reload, execution-lock contention/release, atomic publication, detection and compliance semantics, isolated uninstall, sanitized diagnostics, and package-root resolution. Privileged filesystem/registry boundaries are substituted in relevant tests. Mocked tests do not establish actual SYSTEM deployment or portal compliance.

## Successful live one-device Intune pilot — 2026-09-08

Source: final live validation evidence supplied by the project owner from the Windows 11 MDE lab VM. The development agent did not independently operate the tenant or inspect the VM. This records a completed pilot, separate from the automated suite.

| Evidence | Live result |
| --- | --- |
| Device | DESKTOP-GFRP15O |
| Win32 app | ESAF - Endpoint Security Assurance Framework 0.1.1 - Pilot |
| Intune app state | Installed |
| Installation directory | C:\Program Files\ESAF exists |
| Deployment context | Intune machine/SYSTEM, native 64-bit Windows PowerShell |
| Engine | 0.1.1 |
| Baseline | Corporate-W11 1.0.0 |
| Final Run ID | ESAF-20260908-4180E576390BD031F3893333FE968A80 |
| Overall ESAF verdict | PASS |
| Controls | 5 passed; 0 failed, review, pending or errors |
| Installation verifier | Engine, Baseline, ResultIntegrity, RegistryConsistency, StorageAcl and Certification all PASS |
| Program Files ACL | C:\Program Files\ESAF: SYSTEM + BUILTIN\Administrators FullControl only |
| ProgramData ACL | C:\ProgramData\ESAF: SYSTEM + BUILTIN\Administrators FullControl only |
| Intune compliance policy | ESAF Endpoint Security Compliance - Pilot |
| Final portal custom setting | ESAFStatus = Compliant |

Local Custom Compliance discovery returned ESAFStatus PASS, MDEAssurance PASS, DefenderAssurance PASS, NetworkAssurance PASS, BaselineVersion 1.0.0, EngineVersion 0.1.1 and CertificationFreshness Fresh. The portal setting is recorded separately: the local discovery result alone was not used to claim Intune compliance.

## Pilot defects fixed and retained hardening

1. The unsigned installer initially exited 1 before creating Program Files/ESAF. The earlier detailed evidence reported persistent execution-policy scopes Undefined and effective Windows PowerShell policy Restricted. The launch needed process-only `-ExecutionPolicy Bypass`; the install command and native uninstall wrapper now include it. No Set-ExecutionPolicy call, persistent LocalMachine/CurrentUser change, execution-policy registry value or GPO weakening was added. Production should prefer signed release scripts and normal organizational script-control policy.
2. After that correction, package version 2 still failed under SYSTEM. Manifest validation, module import, paths, payload directories, temporary payload copy/ACLs and execution-lock acquisition passed isolated live checks. Protected diagnostics identified `package support load`, `System.Management.Automation.ParameterBindingValidationException`, line 77, offset 18, stack line 77 and exit 1 at the Join-Path call. Windows PowerShell 5.1 evaluated the optional PackageRoot default before PSScriptRoot was available. PackageRoot now has no parameter default; the script body resolves an omitted value from PSScriptRoot after binding, rejects explicit empty/whitespace values and normalizes the path. The `package root resolution` diagnostic stage and reviewed safe message remain covered by regression tests.

Protected installer diagnostics remain part of the release: `C:\ProgramData\ESAF\installer-diagnostics\installer-<guid>.json`. Records preserve stage, UTC time, exception type, recognized error ID, reviewed safe messages and numeric line information. Unknown text/IDs, source paths, credentials and environment dumps are omitted. SYSTEM/Administrators-only storage, reparse rejection and unique CreateNew files protect the records. Logging failure preserves the original exit 1 and generic stdout. Successful live deployment resolves the earlier failure reports; diagnostics are retained for future failures.

## Scope and merge readiness

Automated checks and the successful one-device Intune installation and portal compliance evidence satisfy Milestone 2 validation. PR #2 is ready for maintainer merge review within this pilot scope; it remains open and must not be merged automatically.

This is not production rollout approval or evidence of broad endpoint/ARM64 compatibility, functional attack blocking, cryptographic attestation or cloud telemetry receipt. Live uninstall/rollback and repeat-install behavior are not claimed by the final evidence; isolated automated tests cover those paths. Local administrators remain outside the attestation boundary. Hash inventories are not signatures. Production signing, wider deployment and additional live scenarios require separate review.

This final update changes documentation only. Engine 0.1.1, Corporate-W11 1.0.0, verdict logic, detection semantics, deployment behavior and execution-policy handling are unchanged. No tenant changes were performed by this documentation update.
