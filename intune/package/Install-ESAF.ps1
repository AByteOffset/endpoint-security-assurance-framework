#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$SourceRoot=(Split-Path (Split-Path $PSScriptRoot -Parent) -Parent))
$ErrorActionPreference='Stop'
try {
    if (-not [Environment]::Is64BitProcess) { throw '64-bit PowerShell required.' }
    $destination = Join-Path $env:ProgramFiles 'ESAF'
    Remove-Module ESAF -Force -ErrorAction SilentlyContinue
    $module = Import-Module (Join-Path $SourceRoot 'src/ESAF.psd1') -Force -PassThru
    & $module { param($source,$target) Copy-ESAFPayload $source $target } $SourceRoot $destination
    Remove-Module ESAF -Force
    $installed = Import-Module (Join-Path $destination 'src/ESAF.psd1') -Force -PassThru
    if ([IO.Path]::GetFullPath($installed.ModuleBase) -ne [IO.Path]::GetFullPath((Join-Path $destination 'src'))) { throw 'Unexpected installed module location.' }
    $r = & $installed { Invoke-ESAFValidation }
    Write-Output "ESAF executed. Run=$($r.runId); security verdict=$($r.status)"
    exit 0
} catch { Write-Output 'ESAF installation or report publication failed.'; exit 1 }
