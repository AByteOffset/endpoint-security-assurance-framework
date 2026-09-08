#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$Purge,[ValidateRange(0,600)][int]$LockTimeoutSeconds=30)
$ErrorActionPreference='Stop'
$executionLock=$null
try {
    if (-not [Environment]::Is64BitProcess) { throw '64-bit Windows PowerShell required.' }
    $programRoot=[Environment]::GetFolderPath('ProgramFiles')
    $dataRoot=[Environment]::GetFolderPath('CommonApplicationData')
    $install=Join-Path $programRoot 'ESAF'; $data=Join-Path $dataRoot 'ESAF'
    # Resolve only fixed ESAF child paths; no arbitrary deletion path parameter.
    $lockFile=Join-Path $PSScriptRoot 'ExecutionLock.ps1'
    if (-not (Test-Path $lockFile)) { $lockFile=Join-Path $install 'src/Utility/ExecutionLock.ps1' }
    . $lockFile
    $executionLock=Enter-ESAFExecutionLock -TimeoutSeconds $LockTimeoutSeconds
    foreach ($path in @($install,$data)) {
        if (Test-Path -LiteralPath $path) {
            foreach ($item in @((Get-Item $path -Force))+@(Get-ChildItem $path -Force -Recurse)) {
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing reparse-point uninstall target.' }
            }
        }
    }
    if ([IO.Path]::GetFullPath($install) -ne (Join-Path $programRoot 'ESAF') -or [IO.Path]::GetFullPath($data) -ne (Join-Path $dataRoot 'ESAF')) { throw 'Unsafe uninstall path.' }
    # Remove trust publication before removing program files; preserve all evidence by default.
    if (Test-Path 'HKLM:\SOFTWARE\ESAF') { Remove-Item -LiteralPath 'HKLM:\SOFTWARE\ESAF' -Recurse -Force }
    Remove-Module ESAF -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $install) { Remove-Item -LiteralPath $install -Recurse -Force }
    if ($Purge -and (Test-Path -LiteralPath $data)) { Remove-Item -LiteralPath $data -Recurse -Force }
    Write-Output 'ESAF uninstalled. Evidence is preserved unless explicit purge was requested.'
    $code=0
} catch { Write-Output 'ESAF uninstall failed safely.'; $code=1 }
finally { if ($null -ne $executionLock) { Exit-ESAFExecutionLock $executionLock } }
exit $code
