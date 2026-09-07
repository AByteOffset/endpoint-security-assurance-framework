#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$SourceRoot=(Split-Path (Split-Path $PSScriptRoot -Parent) -Parent))
$ErrorActionPreference='Stop'
try {
    if (-not [Environment]::Is64BitProcess) { throw '64-bit PowerShell required.' }
    $destination = Join-Path $env:ProgramFiles 'ESAF'
    Import-Module (Join-Path $SourceRoot 'src/ESAF.psd1') -Force
    $module = Get-Module ESAF
    & $module { param($path) Assert-ESAFStoragePath $path } $destination
    $null = New-Item -ItemType Directory -Path $destination -Force
    & $module { param($path) Set-ESAFStoragePermissions $path } $destination
    foreach ($folder in @('src','controls','baselines','tools')) {
        Copy-Item -LiteralPath (Join-Path $SourceRoot $folder) -Destination $destination -Recurse -Force
    }
    Import-Module (Join-Path $destination 'src/ESAF.psd1') -Force
    $r = Invoke-ESAFValidation
    Write-Output "ESAF executed. Run=$($r.runId); security verdict=$($r.status)"
    exit 0
} catch { Write-Output 'ESAF installation or report publication failed.'; exit 1 }
