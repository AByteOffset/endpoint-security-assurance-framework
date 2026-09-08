# Milestone 3: DESKTOP-GFRP15O live validation and Intune recertification

Status: completed successfully on 2026-09-08 using real endpoint state. “Successfully” means the deployment, certification, evidence, and Intune reporting chain behaved correctly. The endpoint certification result was `FAIL` because two required high-severity protections did not meet Corporate-W11 1.1.0.

## Completed recertification

The existing one-device Win32 application was updated in place from engine 0.1.1 / Corporate-W11 1.0.0 to engine 0.2.0 / Corporate-W11 1.1.0. Assignment remained limited to `MDE-LAB-DEVICES`. Before upgrade, current detection returned exit 1 against the old installed versions, proving version-aware recertification was required. No periodic reinstall mechanism was added.

The previous result was Run ID `ESAF-20260908-4180E576390BD031F3893333FE968A80`, SHA-256 `C89D79664A8E38711397C8A0BBCD2A2EAB29EB5A36897C26D094D1D852DFAE21`. Intune deployed the update as installed and ESAF published Run ID `ESAF-20260908-0DED50AE5202FD2855607798E05B80E4` at `2026-09-08T21:42:18.9242558Z`.

## Endpoint result

ESAF returned overall `FAIL`: 12 PASS, 2 FAIL, 0 REVIEW, 0 PENDING, 0 ERROR, 0 critical failures, and 2 high failures.

| Control | Expected | Observed | Status | Independent validation |
| --- | --- | --- | --- | --- |
| ESAF-DISK-001 | Protected | Off | FAIL | `Get-BitLockerVolume`: C: FullyDecrypted, protection Off, encryption 0% |
| ESAF-HW-002 | Enabled | Disabled | FAIL | `Confirm-SecureBootUEFI`: False |

These are security gaps on the lab VM, not framework defects. Accuracy of observed state was the acceptance criterion; no endpoint setting was weakened or changed to manufacture a result.

Independent checks also confirmed MAPSReporting 2 -> CloudProtection Enabled/PASS; signature timestamp within 72 hours -> Fresh/PASS; IsTamperProtected True -> Enabled/PASS; visible exclusion counts all zero -> Clear/PASS; all firewall profiles True -> Enabled/PASS; TPM present and ready -> Ready/PASS; and ASR inventory collected -> Assessed/PASS.

The installed verifier returned PASS for Engine, Baseline, ResultIntegrity, RegistryConsistency, and StorageAcl. LatestRunId matched the new run and Certification was FAIL. Certification FAIL is a completed security-assurance result and is distinct from installation failure. The Win32 app correctly remained Installed.

History preservation was confirmed for:

- `ESAF-20260907-F4233EC9C04220E8AA463F641F3DD644`
- `ESAF-20260908-4180E576390BD031F3893333FE968A80`
- `ESAF-20260908-0DED50AE5202FD2855607798E05B80E4`

## Intune and Company Portal result

Custom Compliance discovery was updated to require engine 0.2.0 / baseline 1.1.0. The rule remained `ESAFStatus = PASS`. Company Portal displayed `Can't access company resources` and `Endpoint assurance requires attention`. Intune ultimately reported Compliant 0, Noncompliant 1, and `DESKTOP-GFRP15O = Not compliant`; the latest observed compliance contact was approximately `09/08/2026 5:50 PM`.

The complete chain is therefore validated:

```text
Intune Win32 deployment -> ESAF certification -> local evidence -> ESAF FAIL
-> Custom Compliance -> Intune Noncompliant -> Company Portal enforcement
```

## Reusable evidence procedure

For later authorized recertification, preserve the prior result/hash, prove old-version detection before replacement, deploy through the same one-device SYSTEM/x64 path, compare all controls with independent read-only Windows commands, run the installed verifier, validate ACLs/history, and wait for portal compliance. Keep automated tests, endpoint evidence, and portal evidence separate. Do not change protection to force PASS and do not publish raw exclusion values, BitLocker protectors, TPM OwnerAuth, credentials, or environment data.

Protected installer diagnostics remain available at `C:\ProgramData\ESAF\installer-diagnostics\installer-<guid>.json` for execution failures. They were not needed to reinterpret this completed certification FAIL as an installation failure.

Production rollout, ARM64, broad device coverage, hidden exclusion discovery, online MAPS effectiveness, universal ASR policy adequacy, and functional attack blocking remain outside this validation. PR #3 may proceed to merge review within the Milestone 3 one-device scope, but must not be merged automatically.
