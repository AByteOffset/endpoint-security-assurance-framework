#Requires -Version 5.1
[CmdletBinding()]
param([string]$InstallPath=(Join-Path $env:ProgramFiles 'ESAF'),[string]$ResultPath=(Join-Path $env:ProgramData 'ESAF/result.json'))
$ErrorActionPreference='Stop'
$check=[ordered]@{Engine='FAIL';Baseline='FAIL';ResultIntegrity='FAIL';RegistryConsistency='FAIL';StorageAcl='FAIL';LatestRunId='Unknown';Certification='Unknown'}
try {
    . (Join-Path $InstallPath 'src/Utility/ResultContract.ps1')
    $manifest=Import-PowerShellDataFile (Join-Path $InstallPath 'src/ESAF.psd1')
    if ($manifest.ModuleVersion -eq '0.2.0' -and (Test-Path (Join-Path $InstallPath 'src/ESAF.psm1'))) { $check.Engine='PASS' }
    $baseline=Get-Content (Join-Path $InstallPath 'baselines/Corporate-W11.json') -Raw | ConvertFrom-Json
    if ($baseline.name -ceq 'Corporate-W11' -and $baseline.version -ceq '1.1.0') { $check.Baseline='PASS' }
    $r=Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    Assert-ESAFResultContract $r -EngineVersion '0.2.0' -BaselineVersion '1.1.0'
    $check.ResultIntegrity='PASS'; $check.LatestRunId=$r.runId; $check.Certification=$r.status
    try { Assert-ESAFRegistryConsistency $r (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\ESAF'); $check.RegistryConsistency='PASS' } catch {}
    $storage=Split-Path $ResultPath -Parent
    $paths=@($InstallPath,$storage,$ResultPath,(Join-Path $storage 'evidence.json'),(Join-Path $storage 'history'))
    $good=$true
    foreach ($path in $paths) { if (-not (Test-ESAFStorageAcl $path)) { $good=$false } }
    if ($good) { $check.StorageAcl='PASS' }
} catch { }
[pscustomobject]$check
