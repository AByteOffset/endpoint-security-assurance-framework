BeforeAll {
    $script:repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
}
Describe 'Version-aware Intune detection' {
    BeforeEach {
        $script:install=Join-Path $TestDrive 'installed'
        $null=New-Item -ItemType Directory -Path (Join-Path $script:install 'src') -Force
        $null=New-Item -ItemType Directory -Path (Join-Path $script:install 'baselines') -Force
        Copy-Item (Join-Path $script:repo 'src/ESAF.psd1') (Join-Path $script:install 'src/ESAF.psd1') -Force
        Copy-Item (Join-Path $script:repo 'baselines/Corporate-W11.json') (Join-Path $script:install 'baselines/Corporate-W11.json') -Force
        $script:path=Join-Path $TestDrive 'detection.json'
        $script:data=@{schemaVersion='1.0';runId='ESAF-20260907-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';completedAt=[DateTime]::UtcNow.ToString('o');engineVersion='0.1.0';baseline=@{name='Corporate-W11';version='1.0.0'};status='FAIL';controls=@(@('ESAF-MDE-001','ESAF-MDE-002','ESAF-AV-001','ESAF-AV-002','ESAF-NET-001') | ForEach-Object { @{id=$_;required=$true;status='FAIL'} })}
        $script:data | ConvertTo-Json -Depth 10 | Set-Content $script:path
        Mock Get-ItemProperty { [pscustomobject]@{LastRunId='ESAF-20260907-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';Status='FAIL';EngineVersion='0.1.0';BaselineVersion='1.0.0'} }
    }
    It 'detects a successful installation despite security FAIL' {
        $text=& (Join-Path $script:repo 'intune/package/Detect-ESAF.ps1') -InstallPath $script:install -ResultPath $script:path
        $LASTEXITCODE | Should -Be 0
        $text | Should -Match 'certification versions current'
    }
    It 'requires recertification for a new baseline or engine' {
        $text=& (Join-Path $script:repo 'intune/package/Detect-ESAF.ps1') -InstallPath $script:install -ResultPath $script:path -RequiredBaselineVersion '1.1.0'
        $LASTEXITCODE | Should -Be 1
        $text | Should -BeNullOrEmpty
        $null=& (Join-Path $script:repo 'intune/package/Detect-ESAF.ps1') -InstallPath $script:install -ResultPath $script:path -RequiredEngineVersion '0.2.0'
        $LASTEXITCODE | Should -Be 1
    }
    It 'rejects stale and incomplete certificates' {
        $script:data.completedAt=[DateTime]::UtcNow.AddDays(-8).ToString('o')
        $script:data | ConvertTo-Json -Depth 10 | Set-Content $script:path
        $null=& (Join-Path $script:repo 'intune/package/Detect-ESAF.ps1') -InstallPath $script:install -ResultPath $script:path
        $LASTEXITCODE | Should -Be 1
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
        $harness=Join-Path $TestDrive 'harness.ps1'
        @'
param([string]$Fixture,[switch]$FailExecution)
function Import-Module {}
function Get-Module { New-Module -ScriptBlock { function Assert-ESAFStoragePath {}; function Set-ESAFStoragePermissions {} } }
function New-Item {}
function Copy-Item {}
function Invoke-ESAFValidation { if ($FailExecution) { throw 'Simulated failure' }; [pscustomobject]@{runId='test';status='FAIL'} }
& $Fixture -SourceRoot $PSScriptRoot
exit $LASTEXITCODE
'@ | Set-Content $harness
        $hostPath=Join-Path $PSHOME 'powershell.exe'
        $text=& $hostPath -NoProfile -ExecutionPolicy Bypass -File $harness -Fixture $fixture
        $LASTEXITCODE | Should -Be 0
        $text | Should -Match 'security verdict=FAIL'
        $null=& $hostPath -NoProfile -ExecutionPolicy Bypass -File $harness -Fixture $fixture -FailExecution
        $LASTEXITCODE | Should -Be 1
    }
}
