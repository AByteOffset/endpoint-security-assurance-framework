#Requires -Version 5.1
[CmdletBinding()]
param([string]$RequiredEngineVersion='0.3.0',[string]$RequiredBaselineVersion='1.1.0',[string]$InstallPath=(Join-Path $env:ProgramFiles 'ESAF'),[string]$ResultPath=(Join-Path $env:ProgramData 'ESAF/result.json'))
$ErrorActionPreference='Stop'
try {
    if (-not [Environment]::Is64BitProcess -or -not (Test-Path -LiteralPath $InstallPath -PathType Container)) { exit 1 }
    . (Join-Path $InstallPath 'src/Utility/ResultContract.ps1')
    $manifest=Import-PowerShellDataFile (Join-Path $InstallPath 'src/ESAF.psd1')
    $baseline=Get-Content (Join-Path $InstallPath 'baselines/Corporate-W11.json') -Raw | ConvertFrom-Json
    if ($manifest.ModuleVersion -ne $RequiredEngineVersion -or $baseline.name -cne 'Corporate-W11' -or $baseline.version -ne $RequiredBaselineVersion -or -not (Test-Path (Join-Path $InstallPath 'src/ESAF.psm1'))) { exit 1 }
    $r=Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    Assert-ESAFResultContract $r $RequiredEngineVersion $RequiredBaselineVersion
    Assert-ESAFRegistryConsistency $r (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\ESAF')
    Write-Output 'ESAF installed and certification versions current.'
    exit 0
} catch { exit 1 }
