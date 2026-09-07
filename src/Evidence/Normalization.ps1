function Get-ESAFProperty {
    param($Object, [string]$Name)
    if ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]) { $Object.$Name }
}

function ConvertTo-ESAFOnboardingState {
    param($Value)
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32]) {
        if ($Value -eq 1) { return 'Onboarded' }
        if ($Value -eq 0) { return 'NotOnboarded' }
    }
    'Unknown'
}

function ConvertTo-ESAFServiceState {
    param($Value, [bool]$Exists)
    if (-not $Exists) { return 'Missing' }
    switch -Exact ($Value) {
        'Running' { return 'Running' }
        'Stopped' { return 'Stopped' }
        'Paused' { return 'Paused' }
        default { return 'Unknown' }
    }
}

function ConvertTo-ESAFBooleanState {
    param($Value)
    if ($Value -isnot [bool]) { return 'Unknown' }
    if ($Value) { 'Enabled' } else { 'Disabled' }
}

function ConvertTo-ESAFAntivirusState {
    param($Mode, $ServiceEnabled, $AntivirusEnabled)
    if ($Mode -in @('Passive','Passive Mode','SxS Passive Mode','EDR Block Mode')) { return 'Passive' }
    if (($ServiceEnabled -is [bool] -and -not $ServiceEnabled) -or ($AntivirusEnabled -is [bool] -and -not $AntivirusEnabled)) { return 'Disabled' }
    if ($Mode -eq 'Normal' -and $ServiceEnabled -is [bool] -and $ServiceEnabled -and $AntivirusEnabled -is [bool] -and $AntivirusEnabled) { return 'Active' }
    'Unknown'
}

function ConvertTo-ESAFNetworkState {
    param($Value)
    # Defender CIM values can be integers or enum names depending on serialization.
    if ($null -eq $Value -or $Value -is [bool] -or $Value -is [array]) { return 'Unknown' }
    switch -Exact ([string]$Value) {
        '0' { 'Disabled' }
        'Disabled' { 'Disabled' }
        '1' { 'Block' }
        'Enabled' { 'Block' }
        '2' { 'Audit' }
        'AuditMode' { 'Audit' }
        default { 'Unknown' }
    }
}
