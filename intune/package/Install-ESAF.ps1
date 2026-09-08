#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$PackageRoot=$PSScriptRoot,[ValidateRange(0,600)][int]$LockTimeoutSeconds=30)
$ErrorActionPreference='Stop'
$executionLock=$null
try {
    if (-not [Environment]::Is64BitProcess) { throw '64-bit Windows PowerShell required.' }
    . (Join-Path $PackageRoot 'PackageSupport.ps1')
    $manifest=Assert-ESAFPackage $PackageRoot
    . (Join-Path $PackageRoot 'ExecutionLock.ps1')
    $executionLock=Enter-ESAFExecutionLock -TimeoutSeconds $LockTimeoutSeconds
    $destination=Join-Path $env:ProgramFiles 'ESAF'
    Remove-Module ESAF -Force -ErrorAction SilentlyContinue
    $source=Join-Path $PackageRoot 'payload'
    $module=Import-Module (Join-Path $source 'src/ESAF.psd1') -Force -PassThru
    & $module { param($source,$target) Copy-ESAFPayload $source $target } $source $destination
    Copy-Item -LiteralPath (Join-Path $PackageRoot 'Uninstall-ESAF.ps1') -Destination (Join-Path $destination 'tools/Uninstall-ESAF.ps1') -Force
    Remove-Module ESAF -Force
    $installed=Import-Module (Join-Path $destination 'src/ESAF.psd1') -Force -PassThru
    if ([IO.Path]::GetFullPath($installed.ModuleBase) -ne [IO.Path]::GetFullPath((Join-Path $destination 'src'))) { throw 'Unexpected installed module.' }
    $r=& $installed { Invoke-ESAFValidation }
    if ($r.status -cnotin @('PASS','REVIEW','FAIL','PENDING')) { throw 'Invalid execution result.' }
    Write-Output "ESAF $($manifest.engineVersion) executed. Run=$($r.runId); security verdict=$($r.status); installation=success"
    $code=0
} catch { Write-Output 'ESAF installation, validation or publication failed.'; $code=1 }
finally { if ($null -ne $executionLock) { Exit-ESAFExecutionLock $executionLock } }
exit $code
