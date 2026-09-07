function Get-ESAFEvidence {
    param([string]$Provider)
    $observed = 'Unknown'
    $raw = [ordered]@{}
    try {
        switch -Exact ($Provider) {
            'MDEOnboardingState' {
                $path = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
                if (Test-Path -LiteralPath $path -ErrorAction Stop) {
                    $state = Get-ItemPropertyValue -LiteralPath $path -Name OnboardingState -ErrorAction Stop
                    $raw.onboardingState = $state
                    if ($state -eq 1) { $observed = 'Onboarded' } elseif ($state -eq 0) { $observed = 'NotOnboarded' }
                } else { $raw.registryPresent = $false }
            }
            'MDESensorService' {
                $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='Sense'" -ErrorAction Stop
                $raw.exists = $null -ne $service
                if ($service) {
                    $raw.status = [string]$service.State; $raw.startMode = [string]$service.StartMode
                    $observed = if ($service.State -eq 'Running') { 'Running' } else { 'Stopped' }
                } else { $observed = 'Missing' }
            }
            { $_ -in @('DefenderAntivirus','RealTimeProtection') } {
                $state = Get-MpComputerStatus -ErrorAction Stop
                $raw.amRunningMode = $state.AMRunningMode
                $raw.amServiceEnabled = $state.AMServiceEnabled
                $raw.antivirusEnabled = $state.AntivirusEnabled
                $raw.realTimeProtectionEnabled = $state.RealTimeProtectionEnabled
                if ($Provider -eq 'DefenderAntivirus') {
                    if ($state.AMRunningMode -match 'Passive|EDR Block') { $observed = 'Passive' }
                    elseif ($state.AMServiceEnabled -eq $false -or $state.AntivirusEnabled -eq $false) { $observed = 'Disabled' }
                    elseif ($state.AMRunningMode -eq 'Normal' -and $state.AMServiceEnabled -eq $true -and $state.AntivirusEnabled -eq $true) { $observed = 'Active' }
                } else {
                    if ($state.RealTimeProtectionEnabled -eq $true) { $observed = 'Enabled' }
                    elseif ($state.RealTimeProtectionEnabled -eq $false) { $observed = 'Disabled' }
                }
            }
            'NetworkProtection' {
                $state = Get-MpPreference -ErrorAction Stop
                $raw.enableNetworkProtection = $state.EnableNetworkProtection
                switch ([string]$state.EnableNetworkProtection) { '0' { $observed = 'Disabled' }; '1' { $observed = 'Block' }; '2' { $observed = 'Audit' } }
            }
            default { throw 'Unapproved provider.' }
        }
        [pscustomobject]@{ evidenceProvider=$Provider; observed=$observed; collectedAt=[DateTime]::UtcNow.ToString('o'); raw=[pscustomobject]$raw; status='Collected'; errorCategory=$null; errorMessage=$null }
    } catch {
        # Never serialize exception text: it can contain paths, tokens, or provider output.
        $category = if ($_.Exception -is [UnauthorizedAccessException]) { 'AccessDenied' } else { 'CollectionFailed' }
        [pscustomobject]@{ evidenceProvider=$Provider; observed='Error'; collectedAt=[DateTime]::UtcNow.ToString('o'); raw=[pscustomobject]@{}; status='ERROR'; errorCategory=$category; errorMessage='Evidence collection failed; inspect approved local diagnostics.' }
    }
}
