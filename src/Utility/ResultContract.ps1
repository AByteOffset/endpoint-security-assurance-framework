function Get-ESAFCertificationControls {
    [pscustomobject]@{id='ESAF-MDE-001';category='mde';severity='critical';required=$true;expected='Onboarded';provider='MDEOnboardingState';domain=@('Onboarded','NotOnboarded')}
    [pscustomobject]@{id='ESAF-MDE-002';category='mde';severity='critical';required=$true;expected='Running';provider='MDESensorService';domain=@('Running','Stopped','Missing','Paused')}
    [pscustomobject]@{id='ESAF-AV-001';category='defender';severity='critical';required=$true;expected='Active';provider='DefenderAntivirus';domain=@('Active','Passive','Disabled')}
    [pscustomobject]@{id='ESAF-AV-002';category='defender';severity='critical';required=$true;expected='Enabled';provider='RealTimeProtection';domain=@('Enabled','Disabled')}
    [pscustomobject]@{id='ESAF-NET-001';category='network';severity='high';required=$true;expected='Block';provider='NetworkProtection';domain=@('Block','Audit','Disabled')}
    [pscustomobject]@{id='ESAF-AV-003';category='defender';severity='high';required=$true;expected='Enabled';provider='CloudProtection';domain=@('Enabled','Disabled')}
    [pscustomobject]@{id='ESAF-AV-004';category='defender';severity='high';required=$true;expected='Fresh';provider='SecurityIntelligence';domain=@('Fresh','Stale','Missing')}
    [pscustomobject]@{id='ESAF-AV-005';category='defender';severity='critical';required=$true;expected='Enabled';provider='TamperProtection';domain=@('Enabled','Disabled')}
    [pscustomobject]@{id='ESAF-AV-006';category='defender';severity='informational';required=$false;expected='Clear';provider='DefenderExclusions';domain=@('Clear','Present')}
    [pscustomobject]@{id='ESAF-NET-002';category='network';severity='high';required=$true;expected='Enabled';provider='WindowsFirewall';domain=@('Enabled','Disabled')}
    [pscustomobject]@{id='ESAF-DISK-001';category='disk';severity='high';required=$true;expected='Protected';provider='BitLockerOS';domain=@('Protected','Off','Suspended','InProgress','Unsupported')}
    [pscustomobject]@{id='ESAF-HW-001';category='hardware';severity='high';required=$true;expected='Ready';provider='TPMReadiness';domain=@('Ready','Missing','NotReady','Unsupported')}
    [pscustomobject]@{id='ESAF-HW-002';category='hardware';severity='high';required=$true;expected='Enabled';provider='SecureBoot';domain=@('Enabled','Disabled','Unsupported')}
    [pscustomobject]@{id='ESAF-ASR-001';category='asr';severity='informational';required=$false;expected='Assessed';provider='ASRAssessment';domain=@('Assessed')}
}
function Assert-ESAFResultContract {
    param($Result,[string]$EngineVersion='0.3.0',[string]$BaselineVersion='1.1.0')
    if ($null -eq $Result -or $Result.schemaVersion -cne '1.0' -or $Result.engineVersion -cne $EngineVersion -or $Result.baseline.name -cne 'Corporate-W11' -or $Result.baseline.version -cne $BaselineVersion -or $Result.runId -cnotmatch '^ESAF-\d{8}-[A-F0-9]{32}$' -or [string]::IsNullOrWhiteSpace($Result.device)) { throw 'Invalid certification identity.' }
    $started=[DateTimeOffset]::Parse($Result.startedAt)
    $completed=[DateTimeOffset]::Parse($Result.completedAt)
    if ($completed -lt $started -or $completed -gt [DateTimeOffset]::UtcNow.AddMinutes(5) -or $Result.provisioning -isnot [bool]) { throw 'Invalid certification completion.' }
    $specs=@(Get-ESAFCertificationControls)
    if ($Result.controls -isnot [array] -or $Result.controls.Count -ne $specs.Count) { throw 'Incomplete certification.' }
    $counts=@{passed=0;failed=0;review=0;pending=0;notApplicable=0;errors=0;criticalFailures=0;highFailures=0}
    $map=@{PASS='passed';FAIL='failed';REVIEW='review';PENDING='pending';NOT_APPLICABLE='notApplicable';ERROR='errors'}
    foreach ($spec in $specs) {
        $matches=@($Result.controls | Where-Object { $_.id -ceq $spec.id })
        if ($matches.Count -ne 1) { throw 'Duplicate or missing control.' }
        $c=$matches[0]; $severity=$spec.severity
        if ($c.required -isnot [bool] -or $c.required -ne $spec.required -or $c.category -cne $spec.category -or $c.severity -cne $severity -or $c.expected -cne $spec.expected -or $c.evidenceProvider -cne $spec.provider -or @($map.Keys) -cnotcontains $c.status) { throw 'Invalid control contract.' }
        if (-not $spec.required -and $c.status -eq 'FAIL') { throw 'Assessment cannot be a hard failure.' }
        if ($c.status -eq 'PASS' -and $c.observed -cne $c.expected) { throw 'Inconsistent pass.' }
        if ($c.status -eq 'FAIL' -and ($spec.domain -cnotcontains $c.observed -or $c.observed -ceq $c.expected)) { throw 'Inconsistent failure.' }
        if ($c.status -in @('REVIEW','PENDING','NOT_APPLICABLE') -and $c.observed -cne 'Unknown' -and -not ($c.id -ceq 'ESAF-AV-006' -and $c.status -ceq 'REVIEW' -and $c.observed -ceq 'Present')) { throw 'Inconsistent unknown state.' }
        if ($c.status -eq 'PENDING' -and -not $Result.provisioning) { throw 'Pending without provisioning context.' }
        if ($c.status -eq 'ERROR' -and $c.observed -cne 'Error') { throw 'Inconsistent error.' }
        $counts[$map[$c.status]]++
        if ($c.required -and $c.status -in @('FAIL','ERROR')) { if ($severity -eq 'critical') { $counts.criticalFailures++ } elseif ($severity -eq 'high') { $counts.highFailures++ } }
    }
    foreach ($key in $counts.Keys) {
        $value=$Result.summary.$key
        if (($value -isnot [int] -and $value -isnot [long]) -or $value -ne $counts[$key]) { throw 'Invalid certification summary.' }
    }
    $status=if ($counts.criticalFailures+$counts.highFailures -gt 0) {'FAIL'} elseif (@($Result.controls | Where-Object { $_.required -and $_.status -eq 'PENDING' }).Count) {'PENDING'} elseif (@($Result.controls | Where-Object { $_.required -and $_.status -in @('FAIL','ERROR','REVIEW','PENDING','NOT_APPLICABLE') }).Count) {'REVIEW'} else {'PASS'}
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
