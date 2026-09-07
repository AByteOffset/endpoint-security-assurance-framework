function Write-ESAFJson {
    param($Value, [string]$Path)
    $json = $Value | ConvertTo-Json -Depth 20
    $null = $json | ConvertFrom-Json -ErrorAction Stop
    $temporary = $Path + '.tmp'
    try {
        [IO.File]::WriteAllText($temporary, $json, (New-Object Text.UTF8Encoding($false)))
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary,$Path,[NullString]::Value) }
        else { [IO.File]::Move($temporary,$Path) }
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
}

function New-ESAFStorageAcl {
    param([switch]$File)
    $acl = if ($File) { New-Object Security.AccessControl.FileSecurity } else { New-Object Security.AccessControl.DirectorySecurity }
    $acl.SetAccessRuleProtection($true,$false)
    # A previous standard-user owner could otherwise rewrite the DACL.
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = if ($File) { New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','Allow') }
        else { New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow') }
        $acl.AddAccessRule($rule)
    }
    $acl
}

function Set-ESAFStoragePermissions {
    param([string]$Path)
    $acl=New-ESAFStorageAcl
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    # Remove preexisting explicit child grants as well as inherited ones.
    foreach ($item in Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction Stop) {
        if ($item.PSIsContainer) { Set-Acl -LiteralPath $item.FullName -AclObject $acl -ErrorAction Stop }
        else {
            $fileAcl = New-ESAFStorageAcl -File
            Set-Acl -LiteralPath $item.FullName -AclObject $fileAcl -ErrorAction Stop
        }
    }
}

function Assert-ESAFStoragePath {
    param([string]$Path)
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse-point storage paths are not allowed.' }
        }
        $parent = Split-Path $current -Parent
        if ($parent -eq $current) { break }
        $current = $parent
    }
    if (Test-Path -LiteralPath $Path) {
        foreach ($item in Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction Stop) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse-point output artifacts are not allowed.' }
        }
    }
}

function Set-ESAFRegistrySummary {
    param($Result)
    $path = 'HKLM:\SOFTWARE\ESAF'
    $null = New-Item -Path $path -Force -ErrorAction Stop
    $values = [ordered]@{ EngineVersion=$Result.engineVersion; BaselineName=$Result.baseline.name; BaselineVersion=$Result.baseline.version; LastRun=$Result.completedAt; LastRunId=$Result.runId; Status=$Result.status; CriticalFailures=$Result.summary.criticalFailures; HighFailures=$Result.summary.highFailures }
    foreach ($name in $values.Keys) {
        $type = if ($name -in @('CriticalFailures','HighFailures')) { 'DWord' } else { 'String' }
        $null = New-ItemProperty -Path $path -Name $name -Value $values[$name] -PropertyType $type -Force -ErrorAction Stop
    }
}

function Write-ESAFReport {
    param($Result, $Evidence, [string]$OutputPath)
    $history = Join-Path $OutputPath ('history/' + $Result.runId)
    $null = New-Item -ItemType Directory -Path $history -ErrorAction Stop
    Write-ESAFJson $Evidence (Join-Path $history 'evidence.json')
    Write-ESAFJson $Result (Join-Path $history 'result.json')
    Write-ESAFJson $Evidence (Join-Path $OutputPath 'evidence.json')
    # result.json is the latest-run commit marker; consumers verify matching registry run IDs.
    Write-ESAFJson $Result (Join-Path $OutputPath 'result.json')
    $line = '{0} Run={1} Baseline={2}/{3} Status={4}' -f $Result.completedAt,$Result.runId,$Result.baseline.name,$Result.baseline.version,$Result.status
    Add-Content -LiteralPath (Join-Path $OutputPath 'ESAF.log') -Value $line -Encoding UTF8 -ErrorAction Stop
    Set-ESAFRegistrySummary $Result
}
