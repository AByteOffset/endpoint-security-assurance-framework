BeforeAll {
    . (Join-Path $PSScriptRoot 'Fixtures.ps1')
    $script:root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $script:root 'src/ESAF.psd1') -Force
}

Describe 'ESAF definitions and verdicts' {
    InModuleScope ESAF {
        BeforeAll {
            $script:baselineFile = Join-Path $script:RepositoryRoot 'baselines/Corporate-W11.json'
            $script:controlFolder = Join-Path $script:RepositoryRoot 'controls'
        }
        BeforeEach {
            $b = Get-ESAFBaseline $script:baselineFile
            $cs = @(Get-ESAFControls $b $script:controlFolder)
            $e = [pscustomobject]@{observed='Onboarded';status='Collected';errorCategory=$null;errorMessage=$null}
        }
        It 'loads a versioned baseline and fourteen approved controls' {
            $b.version | Should -Be '1.1.0'
            $cs.Count | Should -Be 14
        }
        It 'rejects malformed JSON' {
            '{broken' | Set-Content (Join-Path $TestDrive 'bad.json')
            { Get-ESAFBaseline (Join-Path $TestDrive 'bad.json') } | Should -Throw
        }
        It 'rejects invalid, empty, duplicate and path-traversal baselines' {
            foreach ($ids in @(@(),@('ESAF-MDE-001','ESAF-MDE-001'),@('../payload'))) {
                $b.controls=$ids
                $b | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $TestDrive 'bad.json')
                { Get-ESAFBaseline (Join-Path $TestDrive 'bad.json') } | Should -Throw
            }
        }
        It 'rejects unknown baseline fields and incompatible engines' {
            $b.engineCompatibility='>= 99.0.0'
            $b | ConvertTo-Json | Set-Content (Join-Path $TestDrive 'bad.json')
            { Get-ESAFBaseline (Join-Path $TestDrive 'bad.json') } | Should -Throw
            $b.engineCompatibility='>= 0.1.0'
            $b | Add-Member command 'whoami'
            $b | ConvertTo-Json | Set-Content (Join-Path $TestDrive 'bad.json')
            { Get-ESAFBaseline (Join-Path $TestDrive 'bad.json') } | Should -Throw
        }
        It 'rejects command injection and provider substitution in definitions' {
            $destination=Join-Path $TestDrive 'controls'
            Copy-Item $script:controlFolder $destination -Recurse
            $c=$cs[0]; $c.evidenceProvider='Invoke-Expression'
            $c | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $destination 'mde/ESAF-MDE-001.json')
            { Get-ESAFControls $b $destination } | Should -Throw
        }
        It 'evaluates client build and profile applicability' {
            Test-ESAFApplicability $cs[0] $b ([pscustomobject]@{platform='Windows';build=22631;productType=1}) | Should -BeTrue
            Test-ESAFApplicability $cs[0] $b ([pscustomobject]@{platform='Windows';build=19045;productType=1}) | Should -BeFalse
            Test-ESAFApplicability $cs[0] $b ([pscustomobject]@{platform='Windows';build=26000;productType=3}) | Should -BeFalse
            $cs[0].profiles=@('Another')
            Test-ESAFApplicability $cs[0] $b ([pscustomobject]@{platform='Windows';build=26000;productType=1}) | Should -BeFalse
        }
        It 'passes matching required evidence' {
            $r=Get-ESAFControlResult $cs[0] $e $true $false
            $r.status | Should -Be PASS
            (Get-ESAFVerdict @($r)).status | Should -Be PASS
        }
        It 'critical failure overrides passes and pending' {
            $pass=Get-ESAFControlResult $cs[0] $e $true $false
            $e.observed='NotOnboarded'
            $fail=Get-ESAFControlResult $cs[0] $e $true $true
            $e.observed='Unknown'
            $pending=Get-ESAFControlResult $cs[0] $e $true $true
            $v=Get-ESAFVerdict @($pass,$fail,$pending)
            $v.status | Should -Be FAIL
            $v.summary.criticalFailures | Should -Be 1
        }
        It 'maps required high failures to FAIL and required medium failures to REVIEW' {
            $e.observed='Audit'
            $r=Get-ESAFControlResult $cs[4] $e $true $false
            (Get-ESAFVerdict @($r)).status | Should -Be FAIL
            $r.required=$false
            (Get-ESAFVerdict @($r)).status | Should -Be PASS
            $r.required=$true; $r.severity='medium'
            (Get-ESAFVerdict @($r)).status | Should -Be REVIEW
        }
        It 'only treats unknown evidence as pending in explicit provisioning context' {
            $e.observed='Unknown'
            (Get-ESAFControlResult $cs[0] $e $true $false).status | Should -Be REVIEW
            $r=Get-ESAFControlResult $cs[0] $e $true $true
            (Get-ESAFVerdict @($r)).status | Should -Be PENDING
        }
        It 'does not certify required inapplicable controls or empty assessments' {
            $r=Get-ESAFControlResult $cs[0] $e $false $false
            $r.status | Should -Be NOT_APPLICABLE
            (Get-ESAFVerdict @($r)).status | Should -Be REVIEW
            (Get-ESAFVerdict @()).status | Should -Be REVIEW
        }
        It 'fails required critical collection errors' {
            $e.status='ERROR'; $e.observed='Error'
            $r=Get-ESAFControlResult $cs[0] $e $true $true
            $r.status | Should -Be ERROR
            (Get-ESAFVerdict @($r)).status | Should -Be FAIL
        }
        It 'generates unique cryptographically random run identifiers' {
            $ids=@(1..100 | ForEach-Object { New-ESAFRunId })
            $ids[0] | Should -Match '^ESAF-\d{8}-[A-F0-9]{32}$'
            @($ids | Select-Object -Unique).Count | Should -Be 100
        }
    }
}

Describe 'Read-only evidence providers' {
    InModuleScope ESAF {
        BeforeAll {
            # Shims allow mocks without Defender being installed on the test host.
            function Get-MpComputerStatus { param($ErrorAction) }
            function Get-MpPreference { param($ErrorAction) }
        }
        It 'normalizes onboarding registry values' {
            Mock Test-Path { $true }
            Mock Get-ItemProperty { [pscustomobject]@{OnboardingState=1} }
            (Get-ESAFEvidence MDEOnboardingState).observed | Should -Be Onboarded
            Mock Get-ItemProperty { [pscustomobject]@{OnboardingState=0} }
            (Get-ESAFEvidence MDEOnboardingState).observed | Should -Be NotOnboarded
            Mock Test-Path { $false }
            (Get-ESAFEvidence MDEOnboardingState).observed | Should -Be Unknown
        }
        It 'collects sensor service status and startup mode without changing it' {
            Mock Get-CimInstance { [pscustomobject]@{State='Running';StartMode='Auto'} }
            $e=Get-ESAFEvidence MDESensorService
            $e.observed | Should -Be Running
            $e.raw.startMode | Should -Be Auto
            Mock Get-CimInstance { $null }
            (Get-ESAFEvidence MDESensorService).observed | Should -Be Missing
        }
        It 'distinguishes active passive disabled and unknown antivirus modes' {
            Mock Get-MpComputerStatus { [pscustomobject]@{AMRunningMode='Normal';AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$true} }
            (Get-ESAFEvidence DefenderAntivirus).observed | Should -Be Active
            (Get-ESAFEvidence RealTimeProtection).observed | Should -Be Enabled
            Mock Get-MpComputerStatus { [pscustomobject]@{AMRunningMode='Passive';AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$false} }
            (Get-ESAFEvidence DefenderAntivirus).observed | Should -Be Passive
            (Get-ESAFEvidence RealTimeProtection).observed | Should -Be Disabled
            Mock Get-MpComputerStatus { [pscustomobject]@{AMRunningMode='Normal';AMServiceEnabled=$false;AntivirusEnabled=$false;RealTimeProtectionEnabled=$false} }
            (Get-ESAFEvidence DefenderAntivirus).observed | Should -Be Disabled
            Mock Get-MpComputerStatus { [pscustomobject]@{AMRunningMode='Other';AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$null} }
            (Get-ESAFEvidence DefenderAntivirus).observed | Should -Be Unknown
            (Get-ESAFEvidence RealTimeProtection).observed | Should -Be Unknown
        }
        It 'normalizes network protection modes' {
            Mock Get-MpPreference { [pscustomobject]@{EnableNetworkProtection=1} }
            (Get-ESAFEvidence NetworkProtection).observed | Should -Be Block
            Mock Get-MpPreference { [pscustomobject]@{EnableNetworkProtection=2} }
            (Get-ESAFEvidence NetworkProtection).observed | Should -Be Audit
            Mock Get-MpPreference { [pscustomobject]@{EnableNetworkProtection=0} }
            (Get-ESAFEvidence NetworkProtection).observed | Should -Be Disabled
            Mock Get-MpPreference { [pscustomobject]@{EnableNetworkProtection=99} }
            (Get-ESAFEvidence NetworkProtection).observed | Should -Be Unknown
        }
        It 'sanitizes provider exceptions and rejects unapproved providers' {
            Mock Get-MpPreference { throw 'sensitive-provider-payload' }
            $e=Get-ESAFEvidence NetworkProtection
            $e.status | Should -Be ERROR
            ($e | ConvertTo-Json) | Should -Not -Match 'sensitive-provider-payload'
            (Get-ESAFEvidence 'whoami').status | Should -Be ERROR
        }
    }
}

Describe 'Reporting and full mocked validation' {
    InModuleScope ESAF {
        BeforeEach {
            Mock Get-ESAFPlatform { [pscustomobject]@{platform='Windows';build=22631;productType=1} }
            Mock Set-ESAFStoragePermissions {}
            Mock Set-ESAFRegistrySummary {}
            Mock Get-ESAFEvidence {
                param($Provider)
                $values=@{MDEOnboardingState='Onboarded';MDESensorService='Running';DefenderAntivirus='Active';RealTimeProtection='Enabled';NetworkProtection='Block';CloudProtection='Enabled';SecurityIntelligence='Fresh';TamperProtection='Enabled';DefenderExclusions='Clear';WindowsFirewall='Enabled';BitLockerOS='Protected';TPMReadiness='Ready';SecureBoot='Enabled';ASRAssessment='Assessed'}
                [pscustomobject]@{evidenceProvider=$Provider;observed=$values[$Provider];status='Collected';errorCategory=$null;errorMessage=$null}
            }
        }
        It 'publishes consistent result evidence history log and registry summary' {
            $out=Join-Path $TestDrive 'run'
            $r=Invoke-ESAFValidation -OutputPath $out
            $r.status | Should -Be PASS
            $r.engineVersion | Should -Be '0.3.0'
            $json=Get-Content (Join-Path $out 'result.json') -Raw | ConvertFrom-Json
            $json.runId | Should -Be $r.runId
            (Get-Content (Join-Path $out 'evidence.json') -Raw | ConvertFrom-Json).runId | Should -Be $r.runId
            Test-Path (Join-Path $out ('history/'+$r.runId+'/result.json')) | Should -BeTrue
            Get-Content (Join-Path $out 'ESAF.log') -Raw | Should -Match $r.runId
            Should -Invoke Set-ESAFRegistrySummary -Times 1 -Exactly
            $next=Invoke-ESAFValidation -OutputPath $out
            $next.runId | Should -Not -Be $r.runId
            @(Get-ChildItem (Join-Path $out 'history')).Count | Should -Be 2
            @(Get-ChildItem $out -Filter *.tmp).Count | Should -Be 0
        }
        It 'continues other controls when a provider returns an error' {
            Mock Get-ESAFEvidence { [pscustomobject]@{observed='Error';status='ERROR';errorCategory='CollectionFailed';errorMessage='Sanitized'} } -ParameterFilter { $Provider -eq 'MDEOnboardingState' }
            $r=Invoke-ESAFValidation -OutputPath (Join-Path $TestDrive 'error-run')
            $r.status | Should -Be FAIL
            $r.summary.passed | Should -Be 13
            $r.summary.errors | Should -Be 1
        }
        It 'surfaces report publication failures as execution failures' {
            Mock Set-ESAFRegistrySummary { throw 'registry unavailable' }
            { Invoke-ESAFValidation -OutputPath (Join-Path $TestDrive 'publish-error') } | Should -Throw
        }
    }
}

Describe 'Registry summary schema' {
    InModuleScope ESAF {
        It 'writes only the eight small registry summary values' {
            Mock New-Item {}
            Mock New-ItemProperty {}
            $r=[pscustomobject]@{engineVersion='0.1.0';baseline=@{name='Corporate-W11';version='1.1.0'};completedAt='2026-09-07T00:00:00Z';runId='test';status='PASS';summary=@{criticalFailures=0;highFailures=0}}
            Set-ESAFRegistrySummary $r
            Should -Invoke New-ItemProperty -Times 8 -Exactly
            Should -Invoke New-ItemProperty -Times 0 -ParameterFilter { $Name -notin @('EngineVersion','BaselineName','BaselineVersion','LastRun','LastRunId','Status','CriticalFailures','HighFailures') }
        }
    }
}

Describe 'Intune lightweight compliance' {
    BeforeEach {
        $script:resultFile=Join-Path $TestDrive (([guid]::NewGuid().ToString())+'.json')
        $script:run='ESAF-20260907-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        $script:fixture=New-ESAFTestResult
        $global:ESAFTestFixture=$script:fixture
        Mock Get-ItemProperty { New-ESAFTestRegistry $global:ESAFTestFixture }
        Mock Get-Acl { & (Get-Module ESAF) { New-ESAFStorageAcl } }
    }
    It 'emits exactly one compressed JSON object for a current complete result' {
        $script:fixture | ConvertTo-Json -Depth 10 | Set-Content $script:resultFile
        $text=& (Join-Path $script:root 'intune/compliance/Compliance-Discovery.ps1') -ResultPath $script:resultFile -InstallPath $script:root
        @($text).Count | Should -Be 1
        $text | Should -Not -Match "`n"
        ($text | ConvertFrom-Json).ESAFStatus | Should -Be PASS
        ($text | ConvertFrom-Json).NetworkAssurance | Should -Be PASS
    }
    It 'reports age separately without converting a recorded verdict to PENDING' {
        $script:fixture.completedAt=[DateTime]::UtcNow.AddDays(-365).ToString('o')
        $script:fixture.startedAt=[DateTime]::UtcNow.AddDays(-366).ToString('o')
        $script:fixture | ConvertTo-Json -Depth 10 | Set-Content $script:resultFile
        $r=& (Join-Path $script:root 'intune/compliance/Compliance-Discovery.ps1') -ResultPath $script:resultFile -InstallPath $script:root | ConvertFrom-Json
        $r.ESAFStatus | Should -Be PASS
        $r.CertificationFreshness | Should -Be Stale
    }
    It 'never promotes pending security certification to compliance PASS' {
        $script:fixture=New-ESAFTestResult PENDING
        $global:ESAFTestFixture=$script:fixture
        $script:fixture | ConvertTo-Json -Depth 10 | Set-Content $script:resultFile
        $r=& (Join-Path $script:root 'intune/compliance/Compliance-Discovery.ps1') -ResultPath $script:resultFile -InstallPath $script:root | ConvertFrom-Json
        $r.ESAFStatus | Should -Be PENDING
        $r.MDEAssurance | Should -Not -Be PASS
    }
    It 'fails closed for missing malformed incomplete or inconsistent results' {
        (& (Join-Path $script:root 'intune/compliance/Compliance-Discovery.ps1') -ResultPath $script:resultFile -InstallPath $script:root | ConvertFrom-Json).ESAFStatus | Should -Be PENDING
        foreach ($mode in @('malformed','incomplete','mismatch')) {
            $f=$script:fixture | ConvertTo-Json -Depth 10 | ConvertFrom-Json
            if ($mode -eq 'incomplete') { $f.controls=@() }
            if ($mode -eq 'mismatch') { $f.runId='different' }
            $f | ConvertTo-Json -Depth 10 | Set-Content $script:resultFile
            if ($mode -eq 'malformed') { '{' | Set-Content $script:resultFile }
            (& (Join-Path $script:root 'intune/compliance/Compliance-Discovery.ps1') -ResultPath $script:resultFile -InstallPath $script:root | ConvertFrom-Json).ESAFStatus | Should -Be PENDING
        }
    }
}
