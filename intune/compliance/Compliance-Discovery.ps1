#Requires -Version 5.1
[CmdletBinding()]
param([string]$ResultPath=(Join-Path $env:ProgramData 'ESAF/result.json'),[int]$MaximumAgeHours=168,[string]$InstallPath=(Join-Path $env:ProgramFiles 'ESAF'))
$ErrorActionPreference='Stop'
$output=[ordered]@{ESAFStatus='PENDING';MDEAssurance='PENDING';DefenderAssurance='PENDING';NetworkAssurance='PENDING';BaselineVersion='Unknown';EngineVersion='Unknown';CertificationFreshness='Unknown';CertificationRunId='Unknown'}
try {
    . (Join-Path $InstallPath 'src/Utility/ResultContract.ps1')
    if ($MaximumAgeHours -lt 1) { throw 'Invalid age policy.' }
    $r=Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    Assert-ESAFResultContract $r -EngineVersion '0.2.0' -BaselineVersion '1.1.0'
    Assert-ESAFRegistryConsistency $r (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\ESAF')
    if (-not (Test-ESAFStorageAcl (Split-Path $ResultPath -Parent)) -or -not (Test-ESAFStorageAcl $ResultPath)) { throw 'Untrusted result permissions.' }
    $output.ESAFStatus=$r.status; $output.BaselineVersion=$r.baseline.version; $output.EngineVersion=$r.engineVersion; $output.CertificationRunId=$r.runId
    foreach ($pair in @(@('MDEAssurance','mde'),@('DefenderAssurance','defender'),@('NetworkAssurance','network'))) {
        $group=@($r.controls | Where-Object { $_.category -eq $pair[1] })
        $output[$pair[0]]=if (@($group | Where-Object { $_.status -ne 'PASS' }).Count -eq 0) {'PASS'} else {'REVIEW'}
    }
    $output.CertificationFreshness=if ([DateTimeOffset]::Parse($r.completedAt) -lt [DateTimeOffset]::UtcNow.AddHours(-$MaximumAgeHours)) {'Stale'} else {'Fresh'}
} catch {
    foreach ($key in @('ESAFStatus','MDEAssurance','DefenderAssurance','NetworkAssurance')) { $output[$key]='PENDING' }
}
$output | ConvertTo-Json -Compress
