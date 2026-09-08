BeforeAll {
    . (Join-Path $PSScriptRoot 'Fixtures.ps1')
    $script:repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
}
Describe 'Version-aware Intune detection' {
    BeforeEach {
        $script:install=Join-Path $TestDrive 'installed'
        $null=New-Item -ItemType Directory -Path (Join-Path $script:install 'src') -Force
        $null=New-Item -ItemType Directory -Path (Join-Path $script:install 'src/Utility') -Force
        Copy-Item (Join-Path $script:repo 'src/Utility/ResultContract.ps1') (Join-Path $script:install 'src/Utility/ResultContract.ps1') -Force
        Copy-Item (Join-Path $script:repo 'src/ESAF.psm1') (Join-Path $script:install 'src/ESAF.psm1') -Force
        $null=New-Item -ItemType Directory -Path (Join-Path $script:install 'baselines') -Force
        Copy-Item (Join-Path $script:repo 'src/ESAF.psd1') (Join-Path $script:install 'src/ESAF.psd1') -Force
        Copy-Item (Join-Path $script:repo 'baselines/Corporate-W11.json') (Join-Path $script:install 'baselines/Corporate-W11.json') -Force
        $script:path=Join-Path $TestDrive 'detection.json'
        $script:data=New-ESAFTestResult FAIL
        $global:ESAFTestFixture=$script:data
        $script:data | ConvertTo-Json -Depth 10 | Set-Content $script:path
        Mock Get-ItemProperty { New-ESAFTestRegistry $global:ESAFTestFixture }
    }
    It 'detects a successful installation despite security FAIL' {
        $text=& (Join-Path $script:repo 'intune/package/Detect-ESAF.ps1') -InstallPath $script:install -ResultPath $script:path
        $LASTEXITCODE | Should -Be 0
        $text | Should -Match 'certification versions current'
    }
    It 'detects completed PENDING execution without treating it as security PASS' {
        $script:data=New-ESAFTestResult PENDING
        $global:ESAFTestFixture=$script:data
        $script:data | ConvertTo-Json -Depth 10 | Set-Content $script:path
        $null=& (Join-Path $script:repo 'intune/package/Detect-ESAF.ps1') -InstallPath $script:install -ResultPath $script:path
        $LASTEXITCODE | Should -Be 0
        (Get-Content $script:path -Raw | ConvertFrom-Json).status | Should -Be PENDING
    }
    It 'requires recertification for a new baseline or engine' {
        $text=& (Join-Path $script:repo 'intune/package/Detect-ESAF.ps1') -InstallPath $script:install -ResultPath $script:path -RequiredBaselineVersion '1.1.0'
        $LASTEXITCODE | Should -Be 1
        $text | Should -BeNullOrEmpty
        $null=& (Join-Path $script:repo 'intune/package/Detect-ESAF.ps1') -InstallPath $script:install -ResultPath $script:path -RequiredEngineVersion '0.2.0'
        $LASTEXITCODE | Should -Be 1
    }
    It 'accepts old certificates but rejects incomplete certificates' {
        $script:data.completedAt=[DateTime]::UtcNow.AddDays(-8).ToString('o')
        $script:data.startedAt=[DateTime]::UtcNow.AddDays(-9).ToString('o')
        $script:data | ConvertTo-Json -Depth 10 | Set-Content $script:path
        $null=& (Join-Path $script:repo 'intune/package/Detect-ESAF.ps1') -InstallPath $script:install -ResultPath $script:path
        $LASTEXITCODE | Should -Be 0
        $script:data.completedAt=[DateTime]::UtcNow.ToString('o'); $script:data.controls=@()
        $script:data | ConvertTo-Json -Depth 10 | Set-Content $script:path
        $null=& (Join-Path $script:repo 'intune/package/Detect-ESAF.ps1') -InstallPath $script:install -ResultPath $script:path
        $LASTEXITCODE | Should -Be 1
    }
}

Describe 'Installer execution contract' {
    It 'maps completed validation including FAIL to exit zero and exceptions to one' {
        # Run actual installer body in an isolated child, replacing only privileged boundaries.
        # The fixture omits Requires-RunAsAdministrator because it never performs machine writes.
        $body=Get-Content (Join-Path $script:repo 'intune/package/Install-ESAF.ps1') -Raw
        $body=$body -replace '(?m)^#Requires -RunAsAdministrator\r?\n',''
        $fixture=Join-Path $TestDrive 'installer.ps1'
        $body | Set-Content $fixture
        'function Assert-ESAFPackage { [pscustomobject]@{engineVersion="0.1.1"} }' | Set-Content (Join-Path $TestDrive 'PackageSupport.ps1')
        'function Enter-ESAFExecutionLock { [pscustomobject]@{} }; function Exit-ESAFExecutionLock {}' | Set-Content (Join-Path $TestDrive 'ExecutionLock.ps1')
        $harness=Join-Path $TestDrive 'harness.ps1'
        @'
param([string]$Fixture,[switch]$FailExecution,[string]$Verdict='FAIL')
function Remove-Module {}
function Copy-Item {}
function Import-Module {
    $m=New-Module -ArgumentList $FailExecution,$Verdict -ScriptBlock {
        param($failure,$verdict)
        $script:failure=$failure
        $script:verdict=$verdict
        function Copy-ESAFPayload {}
        function Invoke-ESAFValidation { if ($script:failure) { throw 'Simulated failure' }; [pscustomobject]@{runId='test';status=$script:verdict} }
    }
    $m | Add-Member -MemberType NoteProperty -Name ModuleBase -Value (Join-Path $env:ProgramFiles 'ESAF/src') -Force
    $m
}
& $Fixture -PackageRoot $PSScriptRoot
exit $LASTEXITCODE
'@ | Set-Content $harness
        $hostPath=Join-Path $PSHOME 'powershell.exe'
        $text=& $hostPath -NoProfile -ExecutionPolicy Bypass -File $harness -Fixture $fixture
        $LASTEXITCODE | Should -Be 0
        $text | Should -Match 'security verdict=FAIL'
        $text=& $hostPath -NoProfile -ExecutionPolicy Bypass -File $harness -Fixture $fixture -Verdict PENDING
        $LASTEXITCODE | Should -Be 0
        $text | Should -Match 'security verdict=PENDING'
        $null=& $hostPath -NoProfile -ExecutionPolicy Bypass -File $harness -Fixture $fixture -FailExecution
        $LASTEXITCODE | Should -Be 1
    }
}
