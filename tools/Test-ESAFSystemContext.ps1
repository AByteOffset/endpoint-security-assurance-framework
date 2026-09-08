#Requires -Version 5.1
[CmdletBinding()]
param([string]$InstallPath=(Join-Path $env:ProgramFiles 'ESAF'))
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try { $system=$identity.User.Value -eq 'S-1-5-18' } finally { $identity.Dispose() }
if (-not $system -or -not [Environment]::Is64BitProcess) {
    [pscustomobject]@{SystemContext=$system;Is64Bit=[Environment]::Is64BitProcess;Verification='Not verified: use Intune SYSTEM execution or an already approved lab tool.'}
    exit 1
}
$result=& (Join-Path $InstallPath 'tools/Test-ESAFInstallation.ps1') -InstallPath $InstallPath
[pscustomobject]@{SystemContext=$true;Is64Bit=$true;Installation=$result}
if (@('Engine','Baseline','ResultIntegrity','RegistryConsistency','StorageAcl') | Where-Object { $result.$_ -ne 'PASS' }) { exit 1 }
exit 0
