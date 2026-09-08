function ConvertTo-ESAFEnumState {
    param($Value,[hashtable]$Map)
    if ($null -eq $Value -or $Value -is [bool] -or $Value -is [array]) { return 'Unknown' }
    $key=[string]$Value
    if ($Map.ContainsKey($key)) { return $Map[$key] }
    'Unknown'
}

function Get-ESAFCloudEvidence {
    $p=Get-MpPreference -ErrorAction Stop
    $state=ConvertTo-ESAFEnumState (Get-ESAFProperty $p 'MAPSReporting') @{ '0'='Disabled';Disabled='Disabled';'1'='Enabled';Basic='Enabled';'2'='Enabled';Advanced='Enabled' }
    [pscustomobject]@{observed=$state;raw=[pscustomobject]@{mapsParticipation=$state;scope='Local effective preference; connectivity not tested'}}
}

function Get-ESAFSignatureEvidence {
    param($Policy)
    if ($null -eq $Policy -or $Policy.securityIntelligenceMaxAgeHours -lt 1) { throw 'Missing freshness policy.' }
    $s=Get-MpComputerStatus -ErrorAction Stop
    $value=Get-ESAFProperty $s 'AntivirusSignatureLastUpdated'
    $now=[DateTime]::UtcNow
    $stamp=$null;$age=$null;$observed='Unknown'
    if ($null -ne $value) {
        # CIM supplies DateTime. Strings must be unambiguous ISO timestamps.
        if ($value -is [DateTime]) { $date=$value.ToUniversalTime() }
        elseif ($value -is [DateTimeOffset]) { $date=$value.UtcDateTime }
        elseif ($value -is [string] -and $value -match '^\d{4}-\d\d-\d\dT.*(Z|[+-]\d\d:\d\d)$') { $date=[DateTimeOffset]::Parse($value,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime }
        else { throw 'Invalid signature timestamp.' }
        $stamp=$date.ToString('o');$age=[math]::Round(($now-$date).TotalHours,6)
        if ($date.Year -lt 2000) { $observed='Missing' }
        elseif ($age -lt 0) { $observed='Unknown' }
        elseif (($now-$date).TotalHours -le $Policy.securityIntelligenceMaxAgeHours) { $observed='Fresh' }
        else { $observed='Stale' }
    } else { $observed='Missing' }
    [pscustomobject]@{observed=$observed;raw=[pscustomobject]@{signatureTimestampUtc=$stamp;assessedAtUtc=$now.ToString('o');ageHours=$age;maximumAgeHours=$Policy.securityIntelligenceMaxAgeHours}}
}

function Get-ESAFTamperEvidence {
    $s=Get-MpComputerStatus -ErrorAction Stop
    $state=ConvertTo-ESAFBooleanState (Get-ESAFProperty $s 'IsTamperProtected')
    [pscustomobject]@{observed=$state;raw=[pscustomobject]@{tamperProtection=$state}}
}

function Get-ESAFExclusionEvidence {
    $p=Get-MpPreference -ErrorAction Stop
    $counts=[ordered]@{};$unavailable=@();$total=0
    foreach ($category in @('Path','Process','Extension','IpAddress')) {
        $name='Exclusion'+$category
        if ($null -eq $p -or $null -eq $p.PSObject.Properties[$name]) { $counts[$category]=$null;$unavailable+=$category;continue }
        $count=@($p.$name | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) }).Count
        $counts[$category]=$count;$total+=$count
    }
    # A local empty list is visibility only; hidden exclusions are not disproved.
    $state=if ($unavailable.Count) {'Unknown'} elseif ($total) {'Present'} else {'Clear'}
    [pscustomobject]@{observed=$state;raw=[pscustomobject]@{visibleCounts=[pscustomobject]$counts;totalVisible=$total;unavailableCategories=$unavailable;scope='Locally visible exclusions only'}}
}

function Get-ESAFFirewallEvidence {
    $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    $states=[ordered]@{}
    foreach ($name in @('Domain','Private','Public')) {
        $found=@($profiles | Where-Object { $_.Name -eq $name })
        $state='Unknown'
        if ($found.Count -eq 1) {
            $v=Get-ESAFProperty $found[0] 'Enabled'
            if ($v -is [bool]) { $state=ConvertTo-ESAFBooleanState $v }
            else { $state=ConvertTo-ESAFEnumState $v @{'1'='Enabled';True='Enabled';'0'='Disabled';False='Disabled'} }
        }
        $states[$name]=$state
    }
    $observed=if (@($states.Values) -contains 'Disabled') {'Disabled'} elseif (@($states.Values) -contains 'Unknown') {'Unknown'} else {'Enabled'}
    [pscustomobject]@{observed=$observed;raw=[pscustomobject]@{profiles=[pscustomobject]$states;policyStore='ActiveStore'}}
}

function Get-ESAFBitLockerEvidence {
    $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $drive=Get-ESAFProperty $os 'SystemDrive'
    if ($drive -notmatch '^[A-Za-z]:$') { throw 'OS drive unavailable.' }
    $volumes=@(Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop)
    if ($volumes.Count -ne 1) { return [pscustomobject]@{observed='Unknown';raw=[pscustomobject]@{volume='OS';state='Unavailable'}} }
    $v=$volumes[0]
    $volume=ConvertTo-ESAFEnumState (Get-ESAFProperty $v 'VolumeStatus') @{'0'='FullyDecrypted';FullyDecrypted='FullyDecrypted';'1'='FullyEncrypted';FullyEncrypted='FullyEncrypted';'2'='EncryptionInProgress';EncryptionInProgress='EncryptionInProgress';'3'='DecryptionInProgress';DecryptionInProgress='DecryptionInProgress';'4'='EncryptionPaused';EncryptionPaused='EncryptionPaused';'5'='DecryptionPaused';DecryptionPaused='DecryptionPaused'}
    $protection=ConvertTo-ESAFEnumState (Get-ESAFProperty $v 'ProtectionStatus') @{'0'='Off';Off='Off';'1'='On';On='On'}
    $observed=if ($volume -eq 'FullyEncrypted' -and $protection -eq 'On') {'Protected'} elseif ($volume -eq 'FullyEncrypted' -and $protection -eq 'Off') {'Suspended'} elseif ($volume -eq 'FullyDecrypted') {'Off'} elseif ($volume -in @('EncryptionInProgress','EncryptionPaused')) {'InProgress'} elseif ($volume -in @('DecryptionInProgress','DecryptionPaused')) {'Off'} else {'Unknown'}
    [pscustomobject]@{observed=$observed;raw=[pscustomobject]@{volume='OS';volumeStatus=$volume;protectionStatus=$protection}}
}

function Get-ESAFTpmEvidence {
    $t=Get-Tpm -ErrorAction Stop
    $present=Get-ESAFProperty $t 'TpmPresent';$ready=Get-ESAFProperty $t 'TpmReady'
    $state=if ($present -is [bool] -and -not $present) {'Missing'} elseif ($present -is [bool] -and $present -and $ready -is [bool]) { if($ready){'Ready'}else{'NotReady'} } else {'Unknown'}
    [pscustomobject]@{observed=$state;raw=[pscustomobject]@{presence=(ConvertTo-ESAFBooleanState $present);readiness=(ConvertTo-ESAFBooleanState $ready)}}
}

function Get-ESAFSecureBootEvidence {
    try { $state=ConvertTo-ESAFBooleanState (Confirm-SecureBootUEFI -ErrorAction Stop) }
    catch [PlatformNotSupportedException] { return [pscustomobject]@{observed='Unsupported';raw=[pscustomobject]@{state='Unsupported'}} }
    # Other failures, including localized non-UEFI errors, remain explicit provider ERROR.
    [pscustomobject]@{observed=$state;raw=[pscustomobject]@{state=$state}}
}

function Get-ESAFAsrEvidence {
    $p=Get-MpPreference -ErrorAction Stop
    if ($null -eq $p -or $null -eq $p.PSObject.Properties['AttackSurfaceReductionRules_Ids'] -or $null -eq $p.PSObject.Properties['AttackSurfaceReductionRules_Actions']) { return [pscustomobject]@{observed='Unknown';raw=[pscustomobject]@{available=$false}} }
    $ids=@($p.AttackSurfaceReductionRules_Ids | Where-Object { $null -ne $_ });$actions=@($p.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ })
    if ($ids.Count -ne $actions.Count) { throw 'Inconsistent ASR arrays.' }
    $seen=@{};$rules=@();$counts=[ordered]@{Block=0;Audit=0;Warn=0;Disabled=0;Unknown=0}
    for($i=0;$i -lt $ids.Count;$i++) {
        if ([string]$ids[$i] -notmatch '^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$') { throw 'Invalid ASR identifier.' }
        $id=([string]$ids[$i]).ToLowerInvariant()
        if($seen.ContainsKey($id)){throw 'Duplicate ASR identifier.'};$seen[$id]=$true
        $action=ConvertTo-ESAFEnumState $actions[$i] @{'0'='Disabled';Disabled='Disabled';'1'='Block';Enabled='Block';Block='Block';'2'='Audit';AuditMode='Audit';Audit='Audit';'6'='Warn';Warn='Warn'}
        $counts[$action]++;$rules+=[pscustomobject]@{id=$id;action=$action}
    }
    $state=if($counts.Unknown){'Unknown'}else{'Assessed'}
    [pscustomobject]@{observed=$state;raw=[pscustomobject]@{ruleCount=$ids.Count;actions=[pscustomobject]$counts;rules=@($rules | Sort-Object id);scope='Local effective preferences; no required rule set'}}
}
