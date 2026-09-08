# Milestone 3: DESKTOP-GFRP15O live validation and Intune recertification

Status: prepared only. Abhijeet must execute and record results. The nine new controls have no live validation yet. Keep the existing ESAF one-device pilot app and group; never assign All Users/All Devices. Keep Windows 11 x64/SYSTEM behavior and the exact install command from INTUNE_PILOT_GUIDE.md. Coordinate any compliance grace/Conditional Access implications with the owner. Do not weaken controls to force a PASS or manufacture negative cases.

1. Preserve the existing protected 0.1.1 / Corporate-W11 1.0.0 result, registry summary, old Run ID and timestamp on DESKTOP-GFRP15O. Do not overwrite it with a manual 0.2.0 run before proving old-version detection.
2. Check out feature/expanded-security-controls and run the full test suite. Build reviewed deterministic staging on a non-synced path with `packaging/Build-ESAFPackage.ps1 -OutputRoot C:\ESAFBuild`. Verify manifest engine 0.2.0, baseline 1.1.0 and fourteen control files. Use the approved process-only unsigned pilot shell; no persistent execution-policy changes. Sign before hashing if using signed release scripts.
3. Use the approved external Microsoft Content Prep Tool to produce .intunewin. Update the existing pilot Win32 app content and its custom detection script together. Keep install behavior System, x64, signature policy for this approved unsigned pilot, and assignments limited to the same single device.
4. Before deployment, run the new detection script in a separate native PowerShell process against the old installation. Expect exit 1 and no installed stdout. Retain this evidence, then verify IME also reports the old 0.1.1 / 1.0.0 versions as not current. Do not alter installed files merely to obtain this result.
5. Let Intune perform the required 0.2.0 / 1.1.0 upgrade. Confirm app installation status, native SYSTEM invocation, installation exit code and IME logs. An overall security FAIL/REVIEW is still completed installation if publication succeeded; do not confuse app success with security PASS.
6. Capture the new result's engine, baseline, startedAt/completedAt and Run ID. Prove they differ from the old run and that registry, result and evidence refer to the same new run. Verify old history remains. If installation fails, inspect the protected `C:\ProgramData\ESAF\installer-diagnostics\installer-<guid>.json` locally as administrator; never copy secrets or full environment dumps into PR comments.
7. Compare every new control with the actual local evidence using the read-only selections below. Preserve safe summaries and explain any mismatch; do not change endpoint protection to make the result green. Existing five controls must still agree with the previously used read-only comparison procedure.
8. Run installed `Test-ESAFInstallation.ps1` and, in the approved SYSTEM context, `Test-ESAFSystemContext.ps1`. Check all verifier fields, new Run ID, Program Files/ESAF and ProgramData/ESAF owner/ACLs (SYSTEM + Administrators FullControl only). No new privilege launcher is bundled.
9. Upload current Custom Compliance discovery to the existing pilot policy, with logged-on credentials No and native 64-bit host. Discovery must read the new result, not trigger a new validation. Locally compare ESAFStatus, versions, Run ID and freshness with result.json. Review the unchanged single ESAFStatus=PASS rule.
10. Wait for normal Intune evaluation and record the portal setting from the existing policy. PASS should satisfy the rule; REVIEW/FAIL/PENDING must not. Retain the local-to-portal comparison and elapsed timing. Report evidence to update VALIDATION_REPORT.md; do not claim completion in advance or merge automatically.

Use an approved elevated 64-bit Windows PowerShell 5.1 shell. For unsigned pilot scripts, launch it with `powershell.exe -NoProfile -ExecutionPolicy Bypass`. Read-only comparisons (do not run setters):

```powershell
Get-MpPreference | Select-Object MAPSReporting
Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated,IsTamperProtected
Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled
$osDrive=(Get-CimInstance Win32_OperatingSystem).SystemDrive
Get-BitLockerVolume -MountPoint $osDrive | Select-Object VolumeStatus,ProtectionStatus
Get-Tpm | Select-Object TpmPresent,TpmReady
Confirm-SecureBootUEFI
# Never output all MpPreference fields, BitLocker key protectors or TPM OwnerAuth.
$p=Get-MpPreference
foreach($name in 'ExclusionPath','ExclusionProcess','ExclusionExtension','ExclusionIpAddress') {
    [pscustomobject]@{Category=$name;VisibleCount=@($p.$name | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) }).Count}
}
$p | Select-Object AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\Program Files\ESAF\tools\Test-ESAFInstallation.ps1'
$r=Get-Content C:\ProgramData\ESAF\result.json -Raw | ConvertFrom-Json
$r | Select-Object engineVersion,baseline,runId,startedAt,completedAt,status,summary
$r.controls | Select-Object id,expected,observed,status,reason,errorCategory
```

For freshness, compare the signature timestamp converted to UTC with the evidence assessment timestamp and shipped 72-hour threshold; do not compare a much later wall clock with the old evidence age. ASR GUID/action mapping and exclusion visibility limitations are documented in CONTROL_MODEL.md. Empty/hidden exclusions and a successful ASR inventory are not proof of policy adequacy. Unsupported hardware/provider errors must be retained and investigated, never coerced to PASS.

Record separately: automated test totals/commit, manual local comparisons, and actual Intune recertification/portal results. Production rollout, ARM64 and attack blocking are outside this pilot. Existing rollback procedures preserve history; any purge remains explicitly authorized only.
