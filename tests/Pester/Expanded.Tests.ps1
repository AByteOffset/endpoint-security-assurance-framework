BeforeAll {
    $script:root=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $PSScriptRoot 'Fixtures.ps1')
    Import-Module (Join-Path $script:root 'src/ESAF.psd1') -Force
}
Describe 'Expanded read-only providers' {
    InModuleScope ESAF {
        BeforeAll {
            function Get-MpPreference { param($ErrorAction) }
            function Get-MpComputerStatus { param($ErrorAction) }
            function Get-NetFirewallProfile { param($PolicyStore,$ErrorAction) }
            function Get-BitLockerVolume { param($MountPoint,$ErrorAction) }
            function Get-Tpm { param($ErrorAction) }
            function Confirm-SecureBootUEFI { param($ErrorAction) }
        }
        BeforeEach { $script:policy=[pscustomobject]@{securityIntelligenceMaxAgeHours=72} }
        It 'normalizes cloud participation <Value> as <Expected>' -ForEach @(
            @{Value=0;Expected='Disabled'},@{Value=1;Expected='Enabled'},@{Value=2;Expected='Enabled'},@{Value='Advanced';Expected='Enabled'},@{Value=$null;Expected='Unknown'},@{Value=99;Expected='Unknown'}
        ) {
            $script:value=$Value
            Mock Get-MpPreference { [pscustomobject]@{MAPSReporting=$script:value} }
            (Get-ESAFEvidence CloudProtection).observed | Should -Be $Expected
        }
        It 'evaluates signature age <Age> against the baseline threshold' -ForEach @(@{Age=1;Expected='Fresh'},@{Age=73;Expected='Stale'},@{Age=-3;Expected='Unknown'}) {
            $script:stamp=[DateTime]::UtcNow.AddHours(-$Age)
            Mock Get-MpComputerStatus { [pscustomobject]@{AntivirusSignatureLastUpdated=$script:stamp} }
            $e=Get-ESAFEvidence SecurityIntelligence $script:policy
            $e.observed | Should -Be $Expected
            $e.raw.maximumAgeHours | Should -Be 72
            $e.raw.signatureTimestampUtc | Should -Match 'Z$'
            $e.raw.ageHours | Should -BeGreaterOrEqual ($Age-0.01)
        }
        It 'uses a changed threshold without changing provider code' {
            Mock Get-MpComputerStatus { [pscustomobject]@{AntivirusSignatureLastUpdated=[DateTime]::UtcNow.AddHours(-30)} }
            (Get-ESAFEvidence SecurityIntelligence ([pscustomobject]@{securityIntelligenceMaxAgeHours=24})).observed | Should -Be Stale
            (Get-ESAFEvidence SecurityIntelligence $script:policy).observed | Should -Be Fresh
        }
        It 'does not certify missing or malformed signature timestamps' {
            Mock Get-MpComputerStatus { [pscustomobject]@{} }
            (Get-ESAFEvidence SecurityIntelligence $script:policy).observed | Should -Be Missing
            Mock Get-MpComputerStatus { [pscustomobject]@{AntivirusSignatureLastUpdated='not-a-date'} }
            (Get-ESAFEvidence SecurityIntelligence $script:policy).status | Should -Be ERROR
            (Get-ESAFEvidence SecurityIntelligence).status | Should -Be ERROR
        }
        It 'normalizes Tamper Protection <Value>' -ForEach @(@{Value=$true;Expected='Enabled'},@{Value=$false;Expected='Disabled'},@{Value=$null;Expected='Unknown'},@{Value='true';Expected='Unknown'}) {
            $script:value=$Value
            Mock Get-MpComputerStatus { [pscustomobject]@{IsTamperProtected=$script:value} }
            (Get-ESAFEvidence TamperProtection).observed | Should -Be $Expected
        }
        It 'assesses all active-store firewall profiles with <Disabled> disabled' -ForEach @(@{Disabled=0},@{Disabled=1},@{Disabled=2},@{Disabled=3}) {
            $script:disabled=$Disabled
            Mock Get-NetFirewallProfile { $i=0;foreach($n in @('Domain','Private','Public')){[pscustomobject]@{Name=$n;Enabled=($i++ -ge $script:disabled)}} }
            $e=Get-ESAFEvidence WindowsFirewall
            $e.observed | Should -Be $(if($Disabled){'Disabled'}else{'Enabled'})
            @($e.raw.profiles.PSObject.Properties).Count | Should -Be 3
            Should -Invoke Get-NetFirewallProfile -ParameterFilter { $PolicyStore -eq 'ActiveStore' } -Times 1
        }
        It 'does not pass missing or duplicate firewall profiles' {
            Mock Get-NetFirewallProfile { [pscustomobject]@{Name='Domain';Enabled=$true} }
            (Get-ESAFEvidence WindowsFirewall).observed | Should -Be Unknown
            Mock Get-NetFirewallProfile { foreach($n in @('Domain','Private','Public','Public')){[pscustomobject]@{Name=$n;Enabled=$true}} }
            (Get-ESAFEvidence WindowsFirewall).observed | Should -Be Unknown
        }
        It 'distinguishes BitLocker <Volume>/<Protection>' -ForEach @(
            @{Volume='FullyEncrypted';Protection='On';Expected='Protected'},@{Volume=1;Protection=1;Expected='Protected'},
            @{Volume='FullyEncrypted';Protection='Off';Expected='Suspended'},@{Volume='FullyDecrypted';Protection='Off';Expected='Off'},
            @{Volume='EncryptionInProgress';Protection='On';Expected='InProgress'},@{Volume='EncryptionPaused';Protection='Off';Expected='InProgress'},
            @{Volume='DecryptionInProgress';Protection='Off';Expected='Off'},@{Volume='Unknown';Protection='On';Expected='Unknown'}
        ) {
            $script:volume=$Volume;$script:protection=$Protection
            Mock Get-CimInstance { [pscustomobject]@{SystemDrive='D:'} }
            Mock Get-BitLockerVolume { [pscustomobject]@{VolumeStatus=$script:volume;ProtectionStatus=$script:protection;KeyProtector='sensitive-recovery-key'} }
            $e=Get-ESAFEvidence BitLockerOS
            $e.observed | Should -Be $Expected
            ($e | ConvertTo-Json -Depth 5) | Should -Not -Match 'sensitive-recovery-key|KeyProtector'
            Should -Invoke Get-BitLockerVolume -ParameterFilter { $MountPoint -eq 'D:' } -Times 1
        }
        It 'does not pass unavailable OS volume' {
            Mock Get-CimInstance { [pscustomobject]@{SystemDrive='C:'} }
            Mock Get-BitLockerVolume { $null }
            (Get-ESAFEvidence BitLockerOS).observed | Should -Be Unknown
        }
        It 'normalizes TPM presence <Present> readiness <Ready>' -ForEach @(
            @{Present=$true;Ready=$true;Expected='Ready'},@{Present=$false;Ready=$false;Expected='Missing'},@{Present=$true;Ready=$false;Expected='NotReady'},@{Present=$null;Ready=$null;Expected='Unknown'}
        ) {
            $script:present=$Present;$script:ready=$Ready
            Mock Get-Tpm { [pscustomobject]@{TpmPresent=$script:present;TpmReady=$script:ready;OwnerAuth='sensitive-owner-auth'} }
            $e=Get-ESAFEvidence TPMReadiness
            $e.observed | Should -Be $Expected
            ($e | ConvertTo-Json -Depth 5) | Should -Not -Match 'sensitive-owner-auth|OwnerAuth'
        }
        It 'normalizes Secure Boot <Value>' -ForEach @(@{Value=$true;Expected='Enabled'},@{Value=$false;Expected='Disabled'},@{Value=$null;Expected='Unknown'}) {
            $script:value=$Value;Mock Confirm-SecureBootUEFI { $script:value }
            (Get-ESAFEvidence SecureBoot).observed | Should -Be $Expected
        }
        It 'reports unsupported Secure Boot separately from operational failure' {
            Mock Confirm-SecureBootUEFI { throw [PlatformNotSupportedException]::new('not UEFI') }
            (Get-ESAFEvidence SecureBoot).observed | Should -Be Unsupported
            Mock Confirm-SecureBootUEFI { throw [UnauthorizedAccessException]::new('secret') }
            (Get-ESAFEvidence SecureBoot).errorCategory | Should -Be AccessDenied
        }
        It 'summarizes exclusions without serializing values' {
            Mock Get-MpPreference { [pscustomobject]@{ExclusionPath=@('private-path');ExclusionProcess=@('private-process');ExclusionExtension=@('private-extension');ExclusionIpAddress=@('private-ip')} }
            $e=Get-ESAFEvidence DefenderExclusions
            $e.observed | Should -Be Present
            $e.raw.totalVisible | Should -Be 4
            ($e | ConvertTo-Json -Depth 5) | Should -Not -Match 'private-'
            Mock Get-MpPreference { [pscustomobject]@{ExclusionPath=$null;ExclusionProcess=@();ExclusionExtension=@();ExclusionIpAddress=@()} }
            (Get-ESAFEvidence DefenderExclusions).observed | Should -Be Clear
            Mock Get-MpPreference { [pscustomobject]@{} }
            (Get-ESAFEvidence DefenderExclusions).observed | Should -Be Unknown
        }
        It 'normalizes ASR actions <Value> into deterministic summaries' -ForEach @(@{Value=0;Expected='Disabled'},@{Value=1;Expected='Block'},@{Value=2;Expected='Audit'},@{Value=6;Expected='Warn'},@{Value='Enabled';Expected='Block'},@{Value=99;Expected='Unknown'}) {
            $script:value=$Value
            Mock Get-MpPreference { [pscustomobject]@{AttackSurfaceReductionRules_Ids=@('BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550');AttackSurfaceReductionRules_Actions=@($script:value)} }
            $e=Get-ESAFEvidence ASRAssessment
            $e.raw.actions.($Expected) | Should -Be 1
            $e.raw.rules[0].id | Should -Be 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
            $e.observed | Should -Be $(if($Expected -eq 'Unknown'){'Unknown'}else{'Assessed'})
        }
        It 'handles empty unavailable and malformed ASR inventories' {
            Mock Get-MpPreference { [pscustomobject]@{AttackSurfaceReductionRules_Ids=@();AttackSurfaceReductionRules_Actions=@()} }
            (Get-ESAFEvidence ASRAssessment).raw.ruleCount | Should -Be 0
            Mock Get-MpPreference { [pscustomobject]@{} }
            (Get-ESAFEvidence ASRAssessment).observed | Should -Be Unknown
            Mock Get-MpPreference { [pscustomobject]@{AttackSurfaceReductionRules_Ids=@('private-invalid');AttackSurfaceReductionRules_Actions=@(1)} }
            $e=Get-ESAFEvidence ASRAssessment
            $e.status | Should -Be ERROR
            ($e | ConvertTo-Json) | Should -Not -Match 'private-invalid'
        }
        It 'keeps <Provider> provider failures explicit and sanitized' -ForEach @(
            @{Provider='CloudProtection';Command='Get-MpPreference'},@{Provider='SecurityIntelligence';Command='Get-MpComputerStatus'},@{Provider='TamperProtection';Command='Get-MpComputerStatus'},@{Provider='DefenderExclusions';Command='Get-MpPreference'},@{Provider='WindowsFirewall';Command='Get-NetFirewallProfile'},@{Provider='BitLockerOS';Command='Get-BitLockerVolume'},@{Provider='TPMReadiness';Command='Get-Tpm'},@{Provider='SecureBoot';Command='Confirm-SecureBootUEFI'},@{Provider='ASRAssessment';Command='Get-MpPreference'}
        ) {
            Mock Get-CimInstance { [pscustomobject]@{SystemDrive='C:'} }
            Mock $Command { throw 'private-provider-failure' }
            $e=Get-ESAFEvidence $Provider $script:policy
            $e.status | Should -Be ERROR
            $e.observed | Should -Be Error
            ($e | ConvertTo-Json) | Should -Not -Match 'private-provider-failure'
        }
    }
}

Describe 'Expanded baseline and certification contract' {
    InModuleScope ESAF {
        BeforeAll { . (Join-Path $script:RepositoryRoot 'tests/Pester/Fixtures.ps1') }
        BeforeEach { $b=Get-ESAFBaseline (Join-Path $script:RepositoryRoot 'baselines/Corporate-W11.json');$controls=@(Get-ESAFControls $b (Join-Path $script:RepositoryRoot 'controls')) }
        It 'keeps control definitions aligned with the lightweight contract' {
            $specs=@(Get-ESAFCertificationControls)
            foreach($c in $controls) {
                $spec=$specs | Where-Object id -eq $c.id
                $c.category | Should -Be $spec.category
                $c.required | Should -Be $spec.required
                $c.severity | Should -Be $spec.severity
                $c.expected.state | Should -Be $spec.expected
                $c.evidenceProvider | Should -Be $spec.provider
            }
        }
        It 'rejects invalid freshness thresholds' {
            foreach($value in @(0,721,'72',1.5)) {
                $b.securityIntelligenceMaxAgeHours=$value
                $path=Join-Path $TestDrive 'policy.json';$b | ConvertTo-Json -Depth 5 | Set-Content $path
                { Get-ESAFBaseline $path } | Should -Throw
            }
        }
        It 'does not fail solely because exclusions or ASR observations exist' {
            $c=$controls | Where-Object id -eq 'ESAF-AV-006'
            $e=[pscustomobject]@{observed='Present';status='Collected';errorCategory=$null;errorMessage=$null}
            $r=Get-ESAFControlResult $c $e $true $false
            $r.status | Should -Be REVIEW
            (Get-ESAFVerdict @($r)).status | Should -Be PASS
            $c=$controls | Where-Object id -eq 'ESAF-ASR-001';$e.observed='Assessed'
            $r=Get-ESAFControlResult $c $e $true $false
            $r.status | Should -Be PASS
            $r.reason | Should -Match 'no universal policy adequacy'
        }
        It 'makes every new required negative and provider error affect the verdict' {
            $specs=@(Get-ESAFCertificationControls | Where-Object { $_.id -notin @('ESAF-MDE-001','ESAF-MDE-002','ESAF-AV-001','ESAF-AV-002','ESAF-NET-001') -and $_.required })
            foreach($spec in $specs) {
                $c=$controls | Where-Object id -eq $spec.id
                foreach($observed in @($spec.domain | Where-Object { $_ -ne $spec.expected })) {
                    $e=[pscustomobject]@{observed=$observed;status='Collected';errorCategory=$null;errorMessage=$null}
                    (Get-ESAFVerdict @(Get-ESAFControlResult $c $e $true $false)).status | Should -Be FAIL
                }
                $e=[pscustomobject]@{observed='Error';status='ERROR';errorCategory='CollectionFailed';errorMessage='Safe'}
                (Get-ESAFVerdict @(Get-ESAFControlResult $c $e $true $false)).status | Should -Be FAIL
            }
        }
        It 'validates all fourteen controls and rejects missing or forged metadata' {
            $r=New-ESAFTestResult
            { Assert-ESAFResultContract $r } | Should -Not -Throw
            foreach($id in @($r.controls.id)) {
                $bad=New-ESAFTestResult;$bad.controls=@($bad.controls | Where-Object id -ne $id)
                { Assert-ESAFResultContract $bad } | Should -Throw
            }
            $r.controls[5].required=$false
            { Assert-ESAFResultContract $r } | Should -Throw
        }
        It 'preserves optional findings without downgrading certification or required failure counts' {
            $r=New-ESAFTestResult;$c=$r.controls | Where-Object id -eq 'ESAF-AV-006';$c.observed='Present';$c.status='REVIEW'
            $v=Get-ESAFVerdict $r.controls;$r.status=$v.status;$r.summary=$v.summary
            { Assert-ESAFResultContract $r } | Should -Not -Throw
            $c.observed='Error';$c.status='ERROR';$v=Get-ESAFVerdict $r.controls;$r.status=$v.status;$r.summary=$v.summary
            $r.status | Should -Be PASS
            { Assert-ESAFResultContract $r } | Should -Not -Throw
        }
    }
    It 'rejects old engine or baseline certificates in current Intune detection' {
        $r=New-ESAFTestResult;$global:ESAFTestFixture=$r
        Mock Get-ItemProperty { New-ESAFTestRegistry $global:ESAFTestFixture }
        $path=Join-Path $TestDrive 'result.json'
        foreach($old in @('engine','baseline','both')) {
            $r=New-ESAFTestResult
            if($old -in @('engine','both')){$r.engineVersion='0.1.1'}
            if($old -in @('baseline','both')){$r.baseline.version='1.0.0'}
            $global:ESAFTestFixture=$r;$r | ConvertTo-Json -Depth 8 | Set-Content $path
            $null=& (Join-Path $script:root 'intune/package/Detect-ESAF.ps1') -InstallPath $script:root -ResultPath $path
            $LASTEXITCODE | Should -Be 1
        }
    }
}

Describe 'Milestone 3 upgrade and passive consumers' {
    It 'keeps release metadata and complete staged inventory aligned' {
        . (Join-Path $script:root 'packaging/PackageSupport.ps1')
        $build=& (Join-Path $script:root 'packaging/Build-ESAFPackage.ps1') -OutputRoot (Join-Path $TestDrive 'release')
        $m=Assert-ESAFPackage $build.stagingPath
        $module=Import-PowerShellDataFile (Join-Path $script:root 'src/ESAF.psd1')
        $b=Get-Content (Join-Path $script:root 'baselines/Corporate-W11.json') -Raw | ConvertFrom-Json
        $m.engineVersion | Should -Be $module.ModuleVersion
        $m.baseline.version | Should -Be $b.version
        @($m.files | Where-Object { $_.path -like 'payload/controls/*' }).Count | Should -Be 14
        $m.files.path | Should -Contain 'payload/src/Evidence/ExpandedProviders.ps1'
    }
    It 'detects a physically installed old release as outdated' {
        $old=Join-Path $TestDrive 'old'
        $null=New-Item -ItemType Directory -Path (Join-Path $old 'src/Utility') -Force
        $null=New-Item -ItemType Directory -Path (Join-Path $old 'baselines') -Force
        Copy-Item (Join-Path $script:root 'src/Utility/ResultContract.ps1') (Join-Path $old 'src/Utility')
        (Get-Content (Join-Path $script:root 'src/ESAF.psd1') -Raw).Replace('0.2.0','0.1.1') | Set-Content (Join-Path $old 'src/ESAF.psd1')
        '' | Set-Content (Join-Path $old 'src/ESAF.psm1')
        (Get-Content (Join-Path $script:root 'baselines/Corporate-W11.json') -Raw).Replace('1.1.0','1.0.0') | Set-Content (Join-Path $old 'baselines/Corporate-W11.json')
        $null=& (Join-Path $script:root 'intune/package/Detect-ESAF.ps1') -InstallPath $old
        $LASTEXITCODE | Should -Be 1
    }
    It 'reads current compliance without importing or rerunning the engine and rejects an old certificate' {
        Mock Import-Module { throw 'Consumer must not import engine' }
        Mock Get-ItemProperty { New-ESAFTestRegistry $global:ESAFTestFixture }
        Mock Get-Acl { & (Get-Module ESAF) { New-ESAFStorageAcl } }
        $path=Join-Path $TestDrive 'current.json'
        $global:ESAFTestFixture=New-ESAFTestResult
        $global:ESAFTestFixture | ConvertTo-Json -Depth 8 | Set-Content $path
        $r=& (Join-Path $script:root 'intune/compliance/Compliance-Discovery.ps1') -InstallPath $script:root -ResultPath $path | ConvertFrom-Json
        $r.ESAFStatus | Should -Be PASS
        $r.CertificationRunId | Should -Be $global:ESAFTestFixture.runId
        $global:ESAFTestFixture.engineVersion='0.1.1';$global:ESAFTestFixture.baseline.version='1.0.0'
        $global:ESAFTestFixture | ConvertTo-Json -Depth 8 | Set-Content $path
        (& (Join-Path $script:root 'intune/compliance/Compliance-Discovery.ps1') -InstallPath $script:root -ResultPath $path | ConvertFrom-Json).ESAFStatus | Should -Be PENDING
        Should -Invoke Import-Module -Times 0
        $source=Get-Content (Join-Path $script:root 'intune/compliance/Compliance-Discovery.ps1') -Raw
        $source | Should -Not -Match 'Invoke-ESAFValidation|Get-ESAFEvidence|Get-MpPreference|Get-MpComputerStatus'
    }
}

Describe 'Required-only certification semantics' {
    InModuleScope ESAF {
        BeforeAll { . (Join-Path $script:RepositoryRoot 'tests/Pester/Fixtures.ps1') }
        It 'retains <Id> <Finding> while required controls certify PASS' -ForEach @(
            @{Id='ESAF-AV-006';Finding='REVIEW';Observed='Present';Counter='review'},
            @{Id='ESAF-ASR-001';Finding='REVIEW';Observed='Unknown';Counter='review'},
            @{Id='ESAF-AV-006';Finding='ERROR';Observed='Error';Counter='errors'},
            @{Id='ESAF-ASR-001';Finding='ERROR';Observed='Error';Counter='errors'},
            @{Id='ESAF-ASR-001';Finding='PENDING';Observed='Unknown';Counter='pending'},
            @{Id='ESAF-AV-006';Finding='NOT_APPLICABLE';Observed='Unknown';Counter='notApplicable'}
        ) {
            $r=New-ESAFTestResult
            $c=$r.controls | Where-Object id -eq $Id
            $c.status=$Finding;$c.observed=$Observed;$r.provisioning=($Finding -eq 'PENDING')
            $v=Get-ESAFVerdict $r.controls;$r.status=$v.status;$r.summary=$v.summary
            $r.status | Should -Be PASS
            $c.status | Should -Be $Finding
            $r.summary.$Counter | Should -Be 1
            $r.summary.passed | Should -Be 13
            $r.summary.criticalFailures | Should -Be 0
            $r.summary.highFailures | Should -Be 0
            { Assert-ESAFResultContract $r } | Should -Not -Throw
            $r.status='REVIEW'
            { Assert-ESAFResultContract $r } | Should -Throw
        }
        It 'retains simultaneous optional review and error summary counts' {
            $r=New-ESAFTestResult
            $c=$r.controls | Where-Object id -eq 'ESAF-AV-006';$c.status='REVIEW';$c.observed='Present'
            $c=$r.controls | Where-Object id -eq 'ESAF-ASR-001';$c.status='ERROR';$c.observed='Error'
            $v=Get-ESAFVerdict $r.controls;$r.status=$v.status;$r.summary=$v.summary
            $r.status | Should -Be PASS
            $r.summary.review | Should -Be 1
            $r.summary.errors | Should -Be 1
            $r.summary.passed | Should -Be 12
            { Assert-ESAFResultContract $r } | Should -Not -Throw
        }
        It 'retains required <Finding> precedence as <Expected>' -ForEach @(
            @{Id='ESAF-AV-003';Finding='FAIL';Observed='Disabled';Expected='FAIL'},
            @{Id='ESAF-AV-005';Finding='ERROR';Observed='Error';Expected='FAIL'},
            @{Id='ESAF-AV-003';Finding='REVIEW';Observed='Unknown';Expected='REVIEW'},
            @{Id='ESAF-AV-003';Finding='PENDING';Observed='Unknown';Expected='PENDING'},
            @{Id='ESAF-AV-003';Finding='NOT_APPLICABLE';Observed='Unknown';Expected='REVIEW'}
        ) {
            $r=New-ESAFTestResult
            $c=$r.controls | Where-Object id -eq $Id;$c.status=$Finding;$c.observed=$Observed
            $r.provisioning=($Finding -eq 'PENDING')
            $optional=$r.controls | Where-Object id -eq 'ESAF-AV-006';$optional.status='ERROR';$optional.observed='Error'
            $v=Get-ESAFVerdict $r.controls;$r.status=$v.status;$r.summary=$v.summary
            $r.status | Should -Be $Expected
            { Assert-ESAFResultContract $r } | Should -Not -Throw
        }
        It 'keeps required lower-severity failures at REVIEW and optional FAIL visible without gating' {
            foreach($finding in @('FAIL','ERROR')) {
                $r=[pscustomobject]@{required=$true;severity='medium';status=$finding}
                (Get-ESAFVerdict @($r)).status | Should -Be REVIEW
                $r.required=$false
                $v=Get-ESAFVerdict @($r)
                $v.status | Should -Be PASS
                ($v.summary.failed+$v.summary.errors) | Should -Be 1
            }
        }
    }
}

Describe 'Optional assessments in passive Intune compliance' {
    It 'emits overall PASS while preserving optional review and error evidence' {
        $r=New-ESAFTestResult
        $c=$r.controls | Where-Object id -eq 'ESAF-AV-006';$c.status='REVIEW';$c.observed='Present'
        $c=$r.controls | Where-Object id -eq 'ESAF-ASR-001';$c.status='ERROR';$c.observed='Error'
        $v=& (Get-Module ESAF) { param($controls) Get-ESAFVerdict $controls } $r.controls
        $r.status=$v.status;$r.summary=$v.summary;$global:ESAFTestFixture=$r
        Mock Get-ItemProperty { New-ESAFTestRegistry $global:ESAFTestFixture }
        Mock Get-Acl { & (Get-Module ESAF) { New-ESAFStorageAcl } }
        $path=Join-Path $TestDrive 'optional.json';$r | ConvertTo-Json -Depth 8 | Set-Content $path
        $before=(Get-FileHash $path).Hash
        $result=& (Join-Path $script:root 'intune/compliance/Compliance-Discovery.ps1') -InstallPath $script:root -ResultPath $path | ConvertFrom-Json
        $result.ESAFStatus | Should -Be PASS
        $result.DefenderAssurance | Should -Be REVIEW
        (Get-FileHash $path).Hash | Should -Be $before
        $saved=Get-Content $path -Raw | ConvertFrom-Json
        $saved.summary.review | Should -Be 1
        $saved.summary.errors | Should -Be 1
    }
}
