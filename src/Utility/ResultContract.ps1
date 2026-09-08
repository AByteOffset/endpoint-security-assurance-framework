function Assert-ESAFResultContract {
    param($Result,[string]$EngineVersion='0.1.1',[string]$BaselineVersion='1.0.0')
    if ($null -eq $Result -or $Result.schemaVersion -cne '1.0' -or $Result.engineVersion -cne $EngineVersion -or $Result.baseline.name -cne 'Corporate-W11' -or $Result.baseline.version -cne $BaselineVersion -or $Result.runId -cnotmatch '^ESAF-\d{8}-[A-F0-9]{32}$' -or [string]::IsNullOrWhiteSpace($Result.device)) { throw 'Invalid certification identity.' }
    $started=[DateTimeOffset]::Parse($Result.startedAt)
    $completed=[DateTimeOffset]::Parse($Result.completedAt)
    if ($completed -lt $started -or $completed -gt [DateTimeOffset]::UtcNow.AddMinutes(5) -or $Result.provisioning -isnot [bool]) { throw 'Invalid certification completion.' }
    $ids=@('ESAF-MDE-001','ESAF-MDE-002','ESAF-AV-001','ESAF-AV-002','ESAF-NET-001')
    $expected=@('Onboarded','Running','Active','Enabled','Block')
    $categories=@('mde','mde','defender','defender','network')
    $domains=@(@('Onboarded','NotOnboarded'),@('Running','Stopped','Missing','Paused'),@('Active','Passive','Disabled'),@('Enabled','Disabled'),@('Block','Audit','Disabled'))
    if ($Result.controls -isnot [array] -or $Result.controls.Count -ne 5) { throw 'Incomplete certification.' }
    $counts=@{passed=0;failed=0;review=0;pending=0;notApplicable=0;errors=0;criticalFailures=0;highFailures=0}
    $map=@{PASS='passed';FAIL='failed';REVIEW='review';PENDING='pending';NOT_APPLICABLE='notApplicable';ERROR='errors'}
    for ($i=0;$i -lt $ids.Count;$i++) {
        $matches=@($Result.controls | Where-Object { $_.id -ceq $ids[$i] })
        if ($matches.Count -ne 1) { throw 'Duplicate or missing control.' }
        $c=$matches[0]; $severity=if ($i -eq 4) {'high'} else {'critical'}
        if ($c.required -isnot [bool] -or -not $c.required -or $c.category -cne $categories[$i] -or $c.severity -cne $severity -or $c.expected -cne $expected[$i] -or @($map.Keys) -cnotcontains $c.status) { throw 'Invalid control contract.' }
        if ($c.status -eq 'PASS' -and $c.observed -cne $c.expected) { throw 'Inconsistent pass.' }
        if ($c.status -eq 'FAIL' -and ($domains[$i] -cnotcontains $c.observed -or $c.observed -ceq $c.expected)) { throw 'Inconsistent failure.' }
        if ($c.status -in @('REVIEW','PENDING','NOT_APPLICABLE') -and $c.observed -cne 'Unknown') { throw 'Inconsistent unknown state.' }
        if ($c.status -eq 'PENDING' -and -not $Result.provisioning) { throw 'Pending without provisioning context.' }
        if ($c.status -eq 'ERROR' -and $c.observed -cne 'Error') { throw 'Inconsistent error.' }
        $counts[$map[$c.status]]++
        if ($c.status -in @('FAIL','ERROR')) { if ($severity -eq 'critical') { $counts.criticalFailures++ } else { $counts.highFailures++ } }
    }
    foreach ($key in $counts.Keys) {
        $value=$Result.summary.$key
        if (($value -isnot [int] -and $value -isnot [long]) -or $value -ne $counts[$key]) { throw 'Invalid certification summary.' }
    }
    $status=if ($counts.criticalFailures+$counts.highFailures -gt 0) {'FAIL'} elseif ($counts.pending -gt 0) {'PENDING'} elseif ($counts.review+$counts.notApplicable -gt 0) {'REVIEW'} else {'PASS'}
    if ($Result.status -cne $status) { throw 'Inconsistent aggregate verdict.' }
}

function Assert-ESAFRegistryConsistency {
    param($Result,$Registry)
    $pairs=@{EngineVersion=$Result.engineVersion;BaselineName=$Result.baseline.name;BaselineVersion=$Result.baseline.version;LastRun=$Result.completedAt;LastRunId=$Result.runId;Status=$Result.status;CriticalFailures=$Result.summary.criticalFailures;HighFailures=$Result.summary.highFailures}
    foreach ($key in $pairs.Keys) { if ($null -eq $Registry -or $null -eq $Registry.PSObject.Properties[$key] -or $Registry.$key -cne $pairs[$key]) { throw 'Registry/result mismatch.' } }
}

function Test-ESAFStorageAcl {
    param([string]$Path)
    try {
        $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
        $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin @('S-1-5-18','S-1-5-32-544')) { return $false }
        $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
            if (@($rules | Where-Object { $_.IdentityReference.Value -eq $sid -and $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl }).Count -eq 0) { return $false }
        }
        foreach ($rule in $rules) {
            if ($rule.AccessControlType -eq 'Deny') { return $false }
            if ($rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) { return $false }
        }
        return $true
    } catch { return $false }
}
