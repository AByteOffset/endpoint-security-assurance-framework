#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$PackageRoot,[ValidateRange(0,600)][int]$LockTimeoutSeconds=30)
$ErrorActionPreference='Stop'
# These bootstrap helpers must work even when package support/module loading fails.
function New-ESAFInstallerDiagnostic {
    param([Management.Automation.ErrorRecord]$Failure,[string]$Stage)
    # Error text can contain arbitrary credentials or command arguments. Retain only
    # reviewed literal messages; preserve type, known error ID and numeric locations.
    $safeMessages=@('Unable to resolve ESAF package root.','64-bit Windows PowerShell required.','Unexpected installed module.','Invalid execution result.','ESAF execution lock timed out.','Incomplete ESAF payload.','Source and installation paths must be separate.')
    $message='[Redacted untrusted exception text]'
    if ($Failure.Exception.Message -cin $safeMessages) { $message=$Failure.Exception.Message }
    $id='[Redacted untrusted error ID]'
    $knownIds=@('UnauthorizedAccess','PermissionDenied','PathNotFound','FileNotFound','CommandNotFoundException','Modules_ModuleNotFound','AmbiguousParameterSet','ParameterBindingFailed','ParameterArgumentValidationError','NamedParameterNotFound','PositionalParameterNotFound','ParameterArgumentTransformationError','InvalidOperation','System.Management.Automation.RuntimeException')
    $first=($Failure.FullyQualifiedErrorId -split ',')[0]
    if ($first -cin $knownIds) { $id=$first }
    if ([string]::IsNullOrEmpty($Failure.FullyQualifiedErrorId)) { $id=$null }
    $type=$Failure.Exception.GetType().FullName
    if ($type -notmatch '^System\.[A-Za-z0-9_.]+$') { $type='[Redacted custom exception type]' }
    $lines=@([regex]::Matches([string]$Failure.ScriptStackTrace,': line (\d+)') | Select-Object -First 16 | ForEach-Object { [int]$_.Groups[1].Value })
    [ordered]@{timestampUtc=[DateTime]::UtcNow.ToString('o');stage=$Stage;exceptionType=$type;fullyQualifiedErrorId=$id;message=$message;scriptLineNumber=$Failure.InvocationInfo.ScriptLineNumber;offsetInLine=$Failure.InvocationInfo.OffsetInLine;stackLineNumbers=$lines;exitCode=1}
}

function New-ESAFInstallerLogAcl {
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity=New-Object Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    $acl
}

function Write-ESAFInstallerDiagnostic {
    param($Record)
    $base=[Environment]::GetFolderPath('CommonApplicationData')
    $root=Join-Path $base 'ESAF'
    $directory=Join-Path $root 'installer-diagnostics'
    # Do not follow pre-existing junctions/symlinks, including parent directories.
    $cursor=$directory
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unsafe diagnostic path.' }
        }
        $cursor=Split-Path $cursor -Parent
    }
    foreach ($path in @($root,$directory)) {
        if (-not (Test-Path -LiteralPath $path)) {
            $null=[IO.Directory]::CreateDirectory($path,(New-ESAFInstallerLogAcl))
        }
        $acl=Get-Acl -LiteralPath $path
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Unsafe diagnostic owner.' }
        $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        if ($rules.Count -ne 2) { throw 'Unsafe diagnostic permissions.' }
        foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
            $match=@($rules | Where-Object { $_.IdentityReference.Value -eq $sid -and $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights -eq 'FullControl' -and $_.InheritanceFlags -eq 'ContainerInherit, ObjectInherit' -and $_.PropagationFlags -eq 'None' })
            if ($match.Count -ne 1) { throw 'Unsafe diagnostic permissions.' }
        }
    }
    # Unique CreateNew files avoid overwriting/following a pre-existing log file.
    $path=Join-Path $directory ('installer-'+[guid]::NewGuid().ToString('N')+'.json')
    $stream=$null
    try {
        $stream=New-Object IO.FileStream($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $bytes=[Text.Encoding]::UTF8.GetBytes(($Record | ConvertTo-Json -Depth 4 -Compress))
        $stream.Write($bytes,0,$bytes.Length)
    } finally { if ($null -ne $stream) { $stream.Dispose() } }
}

$executionLock=$null
try {
    $stage='package root resolution'
    if (-not $PSBoundParameters.ContainsKey('PackageRoot')) {
        $PackageRoot=$PSScriptRoot
    }
    if ([string]::IsNullOrWhiteSpace($PackageRoot)) {
        throw 'Unable to resolve ESAF package root.'
    }
    $PackageRoot=[IO.Path]::GetFullPath($PackageRoot)
    $stage='architecture check'
    if (-not [Environment]::Is64BitProcess) { throw '64-bit Windows PowerShell required.' }
    $stage='package support load'
    . (Join-Path $PackageRoot 'PackageSupport.ps1')
    $stage='package validation'
    $manifest=Assert-ESAFPackage $PackageRoot
    $stage='execution-lock load'
    . (Join-Path $PackageRoot 'ExecutionLock.ps1')
    $stage='execution-lock acquire'
    $executionLock=Enter-ESAFExecutionLock -TimeoutSeconds $LockTimeoutSeconds
    $destination=Join-Path $env:ProgramFiles 'ESAF'
    $stage='payload module import'
    Remove-Module ESAF -Force -ErrorAction SilentlyContinue
    $source=Join-Path $PackageRoot 'payload'
    $stage='payload module import'
    $module=Import-Module (Join-Path $source 'src/ESAF.psd1') -Force -PassThru
    $stage='payload copy'
    & $module { param($source,$target) Copy-ESAFPayload $source $target } $source $destination
    $stage='uninstall script copy'
    Copy-Item -LiteralPath (Join-Path $PackageRoot 'Uninstall-ESAF.ps1') -Destination (Join-Path $destination 'tools/Uninstall-ESAF.ps1') -Force
    $stage='payload module import'
    Remove-Module ESAF -Force
    $stage='installed module import'
    $installed=Import-Module (Join-Path $destination 'src/ESAF.psd1') -Force -PassThru
    $stage='installed module path verification'
    if ([IO.Path]::GetFullPath($installed.ModuleBase) -ne [IO.Path]::GetFullPath((Join-Path $destination 'src'))) { throw 'Unexpected installed module.' }
    $stage='ESAF validation'
    $r=& $installed { Invoke-ESAFValidation }
    $stage='result validation'
    if ($r.status -cnotin @('PASS','REVIEW','FAIL','PENDING')) { throw 'Invalid execution result.' }
    Write-Output "ESAF $($manifest.engineVersion) executed. Run=$($r.runId); security verdict=$($r.status); installation=success"
    $code=0
} catch {
    $failure=$_
    $code=1
    Write-Output 'ESAF installation, validation or publication failed.'
    try { $null=Write-ESAFInstallerDiagnostic (New-ESAFInstallerDiagnostic $failure $stage) } catch { }
}
finally {
    if ($null -ne $executionLock) {
        try { Exit-ESAFExecutionLock $executionLock }
        catch {
            if ($code -ne 1) {
                $code=1
                Write-Output 'ESAF installation, validation or publication failed.'
                try { $null=Write-ESAFInstallerDiagnostic (New-ESAFInstallerDiagnostic $_ 'execution-lock release') } catch { }
            }
        }
    }
}
exit $code
