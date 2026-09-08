# Milestone 3 live validation status

New 0.2.0 / 1.1.0 controls are NOT live-validated. Abhijeet must use [MILESTONE3_LIVE_VALIDATION.md](MILESTONE3_LIVE_VALIDATION.md) on DESKTOP-GFRP15O for the complete fourteen-control comparison and real Intune recertification. The checklist below is historical foundation procedure; its successful results are not evidence for new controls.

# First safe live lab test - before Intune packaging

The project owner reports successful foundation 0.1.0 live five-control PASS, restricted ACLs and compressed compliance JSON on a Windows 11 MDE lab device. This checklist is retained as the historical manual-assessment procedure; Milestone 2 does not redo that foundation. Use INTUNE_PILOT_GUIDE.md for the new 0.1.1 deployment. The owner has now reported successful 0.1.1 Intune SYSTEM/IME installation and portal custom compliance; see [VALIDATION_REPORT.md](VALIDATION_REPORT.md) for the final evidence, separate from this historical procedure. No security settings, EICAR or active demonstrations are part of either milestone.

1. Get the reviewed feature branch and run the mocked tests:

```powershell
git clone --branch feature/esaf-foundation https://github.com/AByteOffset/endpoint-security-assurance-framework.git
Set-Location endpoint-security-assurance-framework
git status --short
git log -1 --oneline
Install-Module Pester -RequiredVersion 5.6.1 -Scope CurrentUser -Force -SkipPublisherCheck
.\tools\Test-ESAF.ps1
Import-Module .\src\ESAF.psd1 -Force
```

2. Capture raw Windows state BEFORE validation. This helper records unavailable observations without preventing the other checks. Raw objects stay in memory until saved inside protected history. They may contain sensitive configuration; do not publish them to GitHub.

```powershell
function Get-LabObservation {
    param([scriptblock]$Read)
    try { [pscustomobject]@{Data=(& $Read);ErrorType=$null;At=[DateTime]::UtcNow.ToString('o')} }
    catch { [pscustomobject]@{Data=$null;ErrorType=$_.Exception.GetType().FullName;At=[DateTime]::UtcNow.ToString('o')} }
}
$raw=[ordered]@{
    ComputerStatus=Get-LabObservation { Get-MpComputerStatus -ErrorAction Stop }
    Preferences=Get-LabObservation { Get-MpPreference -ErrorAction Stop }
    Sense=Get-LabObservation { Get-Service Sense -ErrorAction Stop }
    Onboarding=Get-LabObservation { Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction Stop }
}
$result=Invoke-ESAFValidation
$history=Join-Path $env:ProgramData ('ESAF\history\'+$result.runId)
$raw | Export-Clixml -LiteralPath (Join-Path $history 'lab-raw.xml')
$evidence=Get-Content (Join-Path $history 'evidence.json') -Raw | ConvertFrom-Json
if ($evidence.runId -ne $result.runId) { throw 'Run ID mismatch.' }
$comparison=foreach ($control in $result.controls) {
    $entry=$evidence.controls | Where-Object id -eq $control.id
    [pscustomobject]@{
        Control=$control.id
        RawWindowsValue=($entry.evidence.raw | ConvertTo-Json -Compress -Depth 6)
        Normalized=$entry.evidence.observed
        Expected=$control.expected
        Verdict=$control.status
    }
}
$comparison | Format-Table -Wrap
$comparison | Export-Csv -LiteralPath (Join-Path $history 'lab-comparison.csv') -NoTypeInformation
$raw.ComputerStatus.Data | Select-Object AMRunningMode,AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled
$raw.Preferences.Data | Select-Object EnableNetworkProtection
$raw.Sense.Data | Select-Object Name,Status
$raw.Onboarding.Data | Select-Object OnboardingState
$result | Select-Object runId,status,summary
.\intune\compliance\Compliance-Discovery.ps1
```

Compare the separately captured raw outputs with same-run raw evidence in the table. Provisioning can change values between observations; record differences without changing policy. ESAF obtains service State and StartMode via Win32_Service. Integer/enum 1 or Enabled maps to Block, 2 or AuditMode to Audit, 0 or Disabled to Disabled. Normal plus true AMServiceEnabled/AntivirusEnabled maps to Active. Boolean RealTimeProtectionEnabled maps to Enabled/Disabled. OnboardingState DWORD 1 maps to Onboarded, 0 to NotOnboarded. Missing/unrecognized values are Unknown; collection/access failures are ERROR.

3. Check actual ACLs and ownership:

```powershell
$storage=Join-Path $env:ProgramData 'ESAF'
@($storage,(Join-Path $storage 'result.json'),(Join-Path $storage 'evidence.json'),(Join-Path $storage 'history'),$history) | ForEach-Object {
    $acl=Get-Acl -LiteralPath $_
    [pscustomobject]@{Path=$_;Owner=$acl.Owner;Protected=$acl.AreAccessRulesProtected;SDDL=$acl.Sddl}
}
icacls.exe "$storage"
icacls.exe "$storage\result.json"
icacls.exe "$storage\evidence.json"
icacls.exe "$storage\history"
```

Expected: SYSTEM and built-in Administrators FullControl; no standard-user Write/Modify/WriteDac/WriteOwner grants. Existing objects receive Administrators ownership. New children can inherit these protected parent rules and be owned by the elevated creator/SYSTEM. SYSTEM must retain read access. This administrator-session test does not verify actual SYSTEM execution; that is a later Intune lab step.

From a separate **standard-user account**, not an administrator's filtered token, attempt to obtain write access without writing bytes:

```powershell
$handle=$null
try {
    $handle=[IO.File]::Open('C:\ProgramData\ESAF\result.json',[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
    Write-Output 'UNEXPECTED: standard user obtained write access; stop rollout.'
} catch [UnauthorizedAccessException] { Write-Output 'Expected: write access denied.' }
finally { if ($handle) { $handle.Dispose() } }
```

4. Retain commit, Run ID, timestamps, Windows build, raw comparison, ACL output and discovery result in protected storage. PASS proves reported local state only, not functional blocking or cloud receipt. Local administrators remain outside the tamper-resistance boundary; no signing of results is claimed.

5. During actual provisioning, an explicitly chosen `Invoke-ESAFValidation -Provisioning` can classify unknown evidence as PENDING. Confirmed failures remain failures. PENDING neither passes compliance nor schedules retries. Explicitly rerun ordinary validation after convergence and compare history. Resolve unexplained normalization/ACL discrepancies before packaging. Repeated installation and SYSTEM Intune execution are subsequent lab steps.
