function Get-ESAFProviderRegistry {
    # Function names and value domains are code-owned. JSON can only select a key.
    @{
        MDEOnboardingState = @{ Function='Get-ESAFOnboardingEvidence'; Category='mde'; ExpectedStates=@('Onboarded','NotOnboarded') }
        MDESensorService = @{ Function='Get-ESAFSensorEvidence'; Category='mde'; ExpectedStates=@('Running','Stopped','Missing','Paused') }
        DefenderAntivirus = @{ Function='Get-ESAFAntivirusEvidence'; Category='defender'; ExpectedStates=@('Active','Passive','Disabled') }
        RealTimeProtection = @{ Function='Get-ESAFRealTimeEvidence'; Category='defender'; ExpectedStates=@('Enabled','Disabled') }
        CloudProtection = @{ Function='Get-ESAFCloudEvidence'; Category='defender'; ExpectedStates=@('Enabled') }
        SecurityIntelligence = @{ Function='Get-ESAFSignatureEvidence'; Category='defender'; ExpectedStates=@('Fresh') }
        TamperProtection = @{ Function='Get-ESAFTamperEvidence'; Category='defender'; ExpectedStates=@('Enabled') }
        DefenderExclusions = @{ Function='Get-ESAFExclusionEvidence'; Category='defender'; ExpectedStates=@('Clear') }
        WindowsFirewall = @{ Function='Get-ESAFFirewallEvidence'; Category='network'; ExpectedStates=@('Enabled') }
        BitLockerOS = @{ Function='Get-ESAFBitLockerEvidence'; Category='disk'; ExpectedStates=@('Protected') }
        TPMReadiness = @{ Function='Get-ESAFTpmEvidence'; Category='hardware'; ExpectedStates=@('Ready') }
        SecureBoot = @{ Function='Get-ESAFSecureBootEvidence'; Category='hardware'; ExpectedStates=@('Enabled') }
        ASRAssessment = @{ Function='Get-ESAFAsrEvidence'; Category='asr'; ExpectedStates=@('Assessed') }
        NetworkProtection = @{ Function='Get-ESAFNetworkEvidence'; Category='network'; ExpectedStates=@('Block','Audit','Disabled') }
    }
}

function Get-ESAFOnboardingEvidence {
    $path='HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
    $present=Test-Path -LiteralPath $path -ErrorAction Stop
    $state=$null
    if ($present) {
        $properties=Get-ItemProperty -LiteralPath $path -ErrorAction Stop
        $state=Get-ESAFProperty $properties 'OnboardingState'
    }
    [pscustomobject]@{ observed=(ConvertTo-ESAFOnboardingState $state); raw=[pscustomobject]@{registryPresent=$present;OnboardingState=$state} }
}

function Get-ESAFSensorEvidence {
    $service=Get-CimInstance -ClassName Win32_Service -Filter "Name='Sense'" -ErrorAction Stop
    $state=Get-ESAFProperty $service 'State'
    [pscustomobject]@{ observed=(ConvertTo-ESAFServiceState $state ($null -ne $service)); raw=[pscustomobject]@{exists=($null -ne $service);State=$state;StartMode=(Get-ESAFProperty $service 'StartMode')} }
}

function Get-ESAFDefenderRawState {
    $state=Get-MpComputerStatus -ErrorAction Stop
    [pscustomobject]@{
        AMRunningMode=(Get-ESAFProperty $state 'AMRunningMode')
        AMServiceEnabled=(Get-ESAFProperty $state 'AMServiceEnabled')
        AntivirusEnabled=(Get-ESAFProperty $state 'AntivirusEnabled')
        RealTimeProtectionEnabled=(Get-ESAFProperty $state 'RealTimeProtectionEnabled')
    }
}

function Get-ESAFAntivirusEvidence {
    $raw=Get-ESAFDefenderRawState
    [pscustomobject]@{raw=$raw;observed=(ConvertTo-ESAFAntivirusState $raw.AMRunningMode $raw.AMServiceEnabled $raw.AntivirusEnabled)}
}

function Get-ESAFRealTimeEvidence {
    $raw=Get-ESAFDefenderRawState
    [pscustomobject]@{raw=$raw;observed=(ConvertTo-ESAFBooleanState $raw.RealTimeProtectionEnabled)}
}

function Get-ESAFNetworkEvidence {
    $state=Get-MpPreference -ErrorAction Stop
    $value=Get-ESAFProperty $state 'EnableNetworkProtection'
    [pscustomobject]@{raw=[pscustomobject]@{EnableNetworkProtection=$value};observed=(ConvertTo-ESAFNetworkState $value)}
}

function Get-ESAFEvidence {
    param([string]$Provider,$Policy)
    try {
        $registry=Get-ESAFProviderRegistry
        if (@($registry.Keys) -cnotcontains $Provider) { throw 'Unapproved provider.' }
        $item=if ($Provider -ceq 'SecurityIntelligence') { & $registry[$Provider].Function -Policy $Policy } else { & $registry[$Provider].Function }
        [pscustomobject]@{evidenceProvider=$Provider;observed=$item.observed;collectedAt=[DateTime]::UtcNow.ToString('o');raw=$item.raw;status='Collected';errorCategory=$null;errorMessage=$null}
    } catch {
        # Never serialize provider exceptions, which could contain sensitive output.
        $category=if ($_.Exception -is [UnauthorizedAccessException]) { 'AccessDenied' } elseif ($_.Exception -is [Management.Automation.CommandNotFoundException] -or $_.Exception -is [PlatformNotSupportedException]) { 'Unsupported' } else { 'CollectionFailed' }
        [pscustomobject]@{evidenceProvider=$Provider;observed='Error';collectedAt=[DateTime]::UtcNow.ToString('o');raw=[pscustomobject]@{};status='ERROR';errorCategory=$category;errorMessage='Evidence collection failed; inspect approved local diagnostics.'}
    }
}
