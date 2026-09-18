function Write-ESAFJson {
    param($Value, [string]$Path)
    $json = $Value | ConvertTo-Json -Depth 20
    $null = $json | ConvertFrom-Json -ErrorAction Stop
    $temporary = $Path + '.tmp'
    try {
        [IO.File]::WriteAllText($temporary, $json, (New-Object Text.UTF8Encoding($false)))
        $null=Get-Content -LiteralPath $temporary -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary,$Path,[NullString]::Value) }
        else { [IO.File]::Move($temporary,$Path) }
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
}

function Write-ESAFTextAtomic {
    param([Parameter(Mandatory=$true)][string]$Content,[Parameter(Mandatory=$true)][string]$Path)
    $null=$Content | ConvertFrom-Json -ErrorAction Stop
    $temporary=$Path+'.tmp'
    try {
        [IO.File]::WriteAllText($temporary,$Content,(New-Object Text.UTF8Encoding($false)))
        $written=[IO.File]::ReadAllText($temporary,(New-Object Text.UTF8Encoding($false)))
        if ($written -cne $Content) { throw 'Support evidence temporary-file verification failed.' }
        $null=$written | ConvertFrom-Json -ErrorAction Stop
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary,$Path,[NullString]::Value) }
        else { [IO.File]::Move($temporary,$Path) }
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Export-ESAFSupportEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$EvidencePath,
        [Parameter(Mandatory=$true)][string]$SupportPath,
        [string]$IntuneLogDirectory
    )
    $ErrorActionPreference='Stop'
    if (-not $PSBoundParameters.ContainsKey('IntuneLogDirectory')) {
        $IntuneLogDirectory=Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs'
    }
    if (-not (Test-Path -LiteralPath $EvidencePath -PathType Leaf)) { throw 'Canonical ESAF evidence file is unavailable.' }
    Assert-ESAFStoragePath $EvidencePath
    $sourceBytes=[IO.File]::ReadAllBytes($EvidencePath)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $sourceHash=([BitConverter]::ToString($sha.ComputeHash($sourceBytes))).Replace('-','') }
    finally { $sha.Dispose() }
    try { $source=[Text.Encoding]::UTF8.GetString($sourceBytes) | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Canonical ESAF evidence is not valid JSON.' }
    if ([string](Get-ESAFProperty $source 'schemaVersion') -cne '1.0') { throw 'Canonical ESAF evidence schema is unsupported.' }
    $runId=Get-ESAFProperty $source 'runId';$device=Get-ESAFProperty $source 'device';$sourceControls=Get-ESAFProperty $source 'controls'
    Assert-ESAFString $runId;Assert-ESAFString $device
    if ($sourceControls -isnot [array]) { throw 'Canonical ESAF controls must be an array.' }
    $seen=@{};$controls=@()
    foreach ($control in $sourceControls) {
        $id=Get-ESAFProperty $control 'id';$evidence=Get-ESAFProperty $control 'evidence'
        Assert-ESAFString $id
        if ($seen.ContainsKey($id) -or $null -eq $evidence) { throw 'Canonical ESAF control evidence is invalid.' }
        $seen[$id]=$true
        $provider=Get-ESAFProperty $evidence 'evidenceProvider';$observed=Get-ESAFProperty $evidence 'observed'
        $collectedAt=Get-ESAFProperty $evidence 'collectedAt';$status=Get-ESAFProperty $evidence 'status'
        Assert-ESAFString $provider;Assert-ESAFString $observed;Assert-ESAFString $status
        if ($null -ne $collectedAt -and $collectedAt -isnot [string]) { throw 'Canonical ESAF collection timestamp is invalid.' }
        $controls+=[pscustomobject][ordered]@{id=$id;evidenceProvider=$provider;observed=$observed;collectedAt=$collectedAt;status=$status}
    }
    $transport=[pscustomobject][ordered]@{
        transportVersion='0.1';evidenceSchemaVersion='1.0';device=$device;runId=$runId
        exportedAtUtc=[DateTime]::UtcNow.ToString('o');sourceEvidenceSha256=$sourceHash;controls=$controls
    }
    $serialized=$transport | ConvertTo-Json -Depth 8
    $supportDirectory=Split-Path ([IO.Path]::GetFullPath($SupportPath)) -Parent
    Assert-ESAFStoragePath $supportDirectory
    $null=New-Item -ItemType Directory -Path $supportDirectory -Force -ErrorAction Stop
    Set-ESAFStoragePermissions $supportDirectory
    $SupportPath=[IO.Path]::GetFullPath($SupportPath)
    Write-ESAFTextAtomic -Content $serialized -Path $SupportPath
    Set-ESAFStoragePermissions $supportDirectory

    $transportStatus='Unavailable';$transportPath=$null
    if (-not [string]::IsNullOrWhiteSpace($IntuneLogDirectory) -and (Test-Path -LiteralPath $IntuneLogDirectory -PathType Container)) {
        $transportPath=Join-Path $IntuneLogDirectory 'ESAF-Assurance.log'
        try {
            Assert-ESAFStoragePath $transportPath
            Write-ESAFTextAtomic -Content $serialized -Path $transportPath
            $transportStatus='Copied'
        } catch { $transportStatus='Failed' }
    }
    [pscustomobject]@{supportPath=[IO.Path]::GetFullPath($SupportPath);intuneTransportStatus=$transportStatus;intuneTransportPath=$transportPath}
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
