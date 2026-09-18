BeforeAll {
    $script:root=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $PSScriptRoot 'Fixtures.ps1')
    . (Join-Path $script:root 'packaging/PackageSupport.ps1')
    Import-Module (Join-Path $script:root 'src/ESAF.psd1') -Force
}

Describe 'Deterministic pilot staging' {
    BeforeEach {
        $script:out=Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $script:build=& (Join-Path $script:root 'packaging/Build-ESAFPackage.ps1') -OutputRoot $script:out
    }
    It 'stages only runtime payload and creates verified SHA256 manifest' {
        $m=Assert-ESAFPackage $script:build.stagingPath
        $m.engineVersion | Should -Be '0.3.0'
        (Import-PowerShellDataFile (Join-Path $script:root 'src/ESAF.psd1')).ModuleVersion | Should -Be '0.3.0'
        $m.schemaVersion | Should -Be '1.0'
        $m.baseline.version | Should -Be '1.1.0'
        $m.files.Count | Should -BeGreaterThan 20
        @($m.files | Where-Object { $_.path -match '\.git|tests/|Test-ESAF.ps1|artifacts|Pester|Test-ESAFSecurity' }).Count | Should -Be 0
        $script:build.intunewinPath | Should -BeNullOrEmpty
    }
    It 'derives package version from the authoritative module manifest' {
        $body=Get-Content (Join-Path $script:root 'packaging/Build-ESAFPackage.ps1') -Raw
        $body | Should -Match 'Test-ModuleManifest'
        $body | Should -Match 'engineVersion=\$engineVersion'
        $body | Should -Not -Match "engineVersion='0\.3\.0'"
    }
    It 'rebuilds with identical paths and content hashes and removes old staged output' {
        $first=Assert-ESAFPackage $script:build.stagingPath
        'extra' | Set-Content (Join-Path $script:build.stagingPath 'obsolete.txt')
        $secondBuild=& (Join-Path $script:root 'packaging/Build-ESAFPackage.ps1') -OutputRoot $script:out
        $second=Assert-ESAFPackage $secondBuild.stagingPath
        ($first.files | ConvertTo-Json -Compress) | Should -Be ($second.files | ConvertTo-Json -Compress)
        Test-Path (Join-Path $secondBuild.stagingPath 'obsolete.txt') | Should -BeFalse
    }
    It 'rejects payload tampering before module import' {
        Add-Content (Join-Path $script:build.stagingPath 'payload/src/ESAF.psm1') '#tamper'
        { Assert-ESAFPackage $script:build.stagingPath } | Should -Throw
    }
    It 'accepts the current package version and rejects incompatible package metadata' {
        { Assert-ESAFPackage $script:build.stagingPath } | Should -Not -Throw
        $path=Join-Path $script:build.stagingPath 'package-manifest.json'
        $manifest=Get-Content $path -Raw | ConvertFrom-Json
        $manifest.engineVersion='0.2.0'
        $manifest | ConvertTo-Json -Depth 8 | Set-Content $path
        { Assert-ESAFPackage $script:build.stagingPath } | Should -Throw
    }
    It 'cleans incomplete staging after a copy failure so rebuilding is safe' {
        Mock Copy-Item { throw 'Simulated copy failure' }
        { & (Join-Path $script:root 'packaging/Build-ESAFPackage.ps1') -OutputRoot $script:out } | Should -Throw
        Test-Path (Join-Path $script:out 'ESAF-Package') | Should -BeFalse
    }
    It 'rejects a missing required payload file' {
        Remove-Item -LiteralPath (Join-Path $script:build.stagingPath 'payload/src/ESAF.psd1')
        { Assert-ESAFPackage $script:build.stagingPath } | Should -Throw
    }
    It 'rejects missing and unlisted files and traversal manifest paths' {
        'unexpected' | Set-Content (Join-Path $script:build.stagingPath 'extra.txt')
        { Assert-ESAFPackage $script:build.stagingPath } | Should -Throw
        Remove-Item (Join-Path $script:build.stagingPath 'extra.txt')
        $path=Join-Path $script:build.stagingPath 'package-manifest.json'
        $m=Get-Content $path -Raw | ConvertFrom-Json
        $m.files[0].path='../outside.ps1'
        $m | ConvertTo-Json -Depth 8 | Set-Content $path
        { Assert-ESAFPackage $script:build.stagingPath } | Should -Throw
    }
    It 'refuses to clean an unmarked directory' {
        $other=Join-Path $TestDrive 'unowned'
        $null=New-Item -ItemType Directory -Path (Join-Path $other 'ESAF-Package') -Force
        { & (Join-Path $script:root 'packaging/Build-ESAFPackage.ps1') -OutputRoot $other } | Should -Throw
    }
}

Describe 'Publication and execution locking' {
    InModuleScope ESAF {
        It 'keeps the previous destination when temporary JSON validation fails' {
            $path=Join-Path $TestDrive 'atomic.json'
            '{"state":"old"}' | Set-Content $path
            Mock Get-Content { '{invalid' } -ParameterFilter { $LiteralPath -like '*.tmp' }
            { Write-ESAFJson @{state='new'} $path } | Should -Throw
            (Get-Content $path -Raw | ConvertFrom-Json).state | Should -Be old
            Test-Path ($path+'.tmp') | Should -BeFalse
        }
        It 'releases the execution lock on framework failure' {
            Mock Enter-ESAFExecutionLock { [pscustomobject]@{} }
            Mock Exit-ESAFExecutionLock {}
            Mock Get-ESAFBaseline { throw 'invalid baseline' }
            { Invoke-ESAFValidation -OutputPath $TestDrive } | Should -Throw
            Should -Invoke Exit-ESAFExecutionLock -Times 1
        }
    }
    It 'times out competing processes and permits acquisition after release' {
        $lockSource=Get-Content (Join-Path $script:root 'src/Utility/ExecutionLock.ps1') -Raw
        $lockSource=$lockSource.Replace('Global\ESAF.Execution.v1',('Local\ESAF.Test.'+[guid]::NewGuid().ToString('N')))
        $lockFile=Join-Path $TestDrive 'test-lock.ps1'
        $lockSource | Set-Content $lockFile
        . $lockFile
        $child=Join-Path $TestDrive 'competitor.ps1'
        'param($LockFile); . $LockFile; try { $m=Enter-ESAFExecutionLock -TimeoutSeconds 0; Exit-ESAFExecutionLock $m; exit 0 } catch { exit 2 }' | Set-Content $child
        $held=Enter-ESAFExecutionLock -TimeoutSeconds 0
        try {
            $null=& (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $child -LockFile $lockFile
            $LASTEXITCODE | Should -Be 2
        } finally { Exit-ESAFExecutionLock $held }
        $null=& (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $child -LockFile $lockFile
        $LASTEXITCODE | Should -Be 0
    }
}

Describe 'Pilot result contract and read-only adapters' {
    BeforeEach {
        $script:path=Join-Path $TestDrive 'result.json'
        $global:ESAFTestFixture=New-ESAFTestResult
        Mock Get-ItemProperty { New-ESAFTestRegistry $global:ESAFTestFixture }
        Mock Get-Acl { & (Get-Module ESAF) { New-ESAFStorageAcl } }
    }
    It 'preserves PASS FAIL REVIEW and PENDING in compliance without changing the endpoint' {
        foreach ($status in @('PASS','FAIL','REVIEW','PENDING')) {
            $global:ESAFTestFixture=New-ESAFTestResult $status
            $global:ESAFTestFixture | ConvertTo-Json -Depth 10 | Set-Content $script:path
            $r=& (Join-Path $script:root 'intune/compliance/Compliance-Discovery.ps1') -InstallPath $script:root -ResultPath $script:path | ConvertFrom-Json
            $r.ESAFStatus | Should -Be $status
            $r.CertificationRunId | Should -Be $global:ESAFTestFixture.runId
        }
    }
    It 'rejects forged pass summary unsupported schema and missing completion' {
        foreach ($mode in @('summary','schema','completion','state')) {
            $r=New-ESAFTestResult
            switch($mode) { summary {$r.summary.passed=4};schema {$r.schemaVersion='999'};completion {$r.completedAt=$null};state {$r.controls[0].observed='NotOnboarded'} }
            $r | ConvertTo-Json -Depth 10 | Set-Content $script:path
            (& (Join-Path $script:root 'intune/compliance/Compliance-Discovery.ps1') -InstallPath $script:root -ResultPath $script:path | ConvertFrom-Json).ESAFStatus | Should -Be PENDING
        }
    }
    It 'fails closed on unsafe result ACL' {
        $global:ESAFTestFixture | ConvertTo-Json -Depth 10 | Set-Content $script:path
        Mock Get-Acl { throw 'no permission' }
        (& (Join-Path $script:root 'intune/compliance/Compliance-Discovery.ps1') -InstallPath $script:root -ResultPath $script:path | ConvertFrom-Json).ESAFStatus | Should -Be PENDING
    }
    It 'detects current 0.3.0 and rejects a previous 0.2.0 certificate' {
        $global:ESAFTestFixture | ConvertTo-Json -Depth 10 | Set-Content $script:path
        $null=& (Join-Path $script:root 'intune/package/Detect-ESAF.ps1') -InstallPath $script:root -ResultPath $script:path
        $LASTEXITCODE | Should -Be 0
        $global:ESAFTestFixture.engineVersion='0.2.0'
        $global:ESAFTestFixture | ConvertTo-Json -Depth 10 | Set-Content $script:path
        $null=& (Join-Path $script:root 'intune/package/Detect-ESAF.ps1') -InstallPath $script:root -ResultPath $script:path
        $LASTEXITCODE | Should -Be 1
    }
    It 'verification reports consistency without writing files or registry' {
        $global:ESAFTestFixture | ConvertTo-Json -Depth 10 | Set-Content $script:path
        $before=(Get-FileHash $script:path).Hash
        Mock Set-Content { throw 'write forbidden' }
        Mock New-ItemProperty { throw 'write forbidden' }
        Mock Set-Acl { throw 'write forbidden' }
        $r=& (Join-Path $script:root 'tools/Test-ESAFInstallation.ps1') -InstallPath $script:root -ResultPath $script:path
        $r.Engine | Should -Be PASS
        $r.ResultIntegrity | Should -Be PASS
        $r.RegistryConsistency | Should -Be PASS
        (Get-FileHash $script:path).Hash | Should -Be $before
        Should -Invoke Set-Content -Times 0
        Should -Invoke New-ItemProperty -Times 0
        Should -Invoke Set-Acl -Times 0
    }
    It 'retains historical Milestone 3 validation versions' {
        (Get-Content (Join-Path $script:root 'docs/MILESTONE3_LIVE_VALIDATION.md') -Raw) | Should -Match 'engine 0\.1\.1.+engine 0\.2\.0'
        (Get-Content (Join-Path $script:root 'docs/VALIDATION_REPORT.md') -Raw) | Should -Match 'upgraded from 0\.1\.1 to 0\.2\.0'
    }
    It 'pilot rules require only overall PASS' {
        $rules=Get-Content (Join-Path $script:root 'intune/compliance/Compliance-Rules.json') -Raw | ConvertFrom-Json
        $rules.Rules.Count | Should -Be 1
        $rules.Rules[0].SettingName | Should -Be ESAFStatus
        $rules.Rules[0].Operand | Should -Be PASS
    }
}

Describe 'Safe uninstall and rollback' {
    BeforeEach {
        $script:lab=Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $null=New-Item -ItemType Directory -Path $script:lab
        $body=Get-Content (Join-Path $script:root 'intune/package/Uninstall-ESAF.ps1') -Raw
        $body=$body -replace '(?m)^#Requires -RunAsAdministrator\r?\n',''
        # Substitute only machine-path and registry boundaries in the isolated fixture.
        $body=$body.Replace('[Environment]::GetFolderPath(''ProgramFiles'')','(Join-Path $PSScriptRoot ''program'')')
        $body=$body.Replace('[Environment]::GetFolderPath(''CommonApplicationData'')','(Join-Path $PSScriptRoot ''data'')')
        $body=$body.Replace('if (Test-Path ''HKLM:\SOFTWARE\ESAF'')','if ($false)')
        $body | Set-Content (Join-Path $script:lab 'Uninstall-ESAF.ps1')
        'function Enter-ESAFExecutionLock { [pscustomobject]@{} }; function Exit-ESAFExecutionLock {}' | Set-Content (Join-Path $script:lab 'ExecutionLock.ps1')
        foreach ($folder in @('program/ESAF','program/Defender','data/ESAF/history/old','data/Intune')) {
            $null=New-Item -ItemType Directory -Path (Join-Path $script:lab $folder) -Force
            'preserve' | Set-Content (Join-Path $script:lab ($folder+'/sentinel.txt'))
        }
    }
    It 'removes only ESAF program files and preserves history on repeated uninstall' {
        foreach ($iteration in 1..2) {
            $null=& (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File (Join-Path $script:lab 'Uninstall-ESAF.ps1')
            $LASTEXITCODE | Should -Be 0
        }
        Test-Path (Join-Path $script:lab 'program/ESAF') | Should -BeFalse
        Get-Content (Join-Path $script:lab 'data/ESAF/history/old/sentinel.txt') | Should -Be preserve
        Get-Content (Join-Path $script:lab 'program/Defender/sentinel.txt') | Should -Be preserve
        Get-Content (Join-Path $script:lab 'data/Intune/sentinel.txt') | Should -Be preserve
    }
    It 'purges only ESAF data when explicitly requested' {
        $null=& (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File (Join-Path $script:lab 'Uninstall-ESAF.ps1') -Purge
        $LASTEXITCODE | Should -Be 0
        Test-Path (Join-Path $script:lab 'data/ESAF') | Should -BeFalse
        Test-Path (Join-Path $script:lab 'data/Intune/sentinel.txt') | Should -BeTrue
    }
    It 'contains no security-changing commands' {
        $tokens=$null;$errors=$null
        $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $script:root 'intune/package/Uninstall-ESAF.ps1'),[ref]$tokens,[ref]$errors)
        $names=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
        @($names | Where-Object { $_ -match '^(Set|Add|Remove)-Mp|Firewall|^(Stop|Start|Set)-Service$' }).Count | Should -Be 0
    }
}

Describe 'Process-only pilot execution policy' {
    It 'documents the exact native Intune install command in both deployment guides' {
        $expected='%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-ESAF.ps1'
        foreach ($path in @('docs/INTUNE_PILOT_GUIDE.md','docs/INTUNE_DEPLOYMENT.md')) {
            @(Get-Content (Join-Path $script:root $path)) | Should -Contain $expected
        }
    }
    It 'launches uninstall with the process-only override and preserves native selection and exit code' {
        $lines=@(Get-Content (Join-Path $script:root 'intune/package/Uninstall-ESAF.cmd'))
        $lines | Should -Contain '"%ESAF_PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Uninstall-ESAF.ps1"'
        $lines | Should -Contain 'set "ESAF_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"'
        $lines | Should -Contain 'if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "ESAF_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"'
        $lines | Should -Contain 'exit /b %errorlevel%'
    }
    It 'contains no persistent execution-policy changes in runtime or deployment code' {
        foreach ($folder in @('src','intune','packaging')) {
            foreach ($file in Get-ChildItem (Join-Path $script:root $folder) -Recurse -File | Where-Object { $_.Extension -in @('.ps1','.psm1','.psd1','.cmd') }) {
                $content=Get-Content $file.FullName -Raw
                # Only the process launch option is allowed. Policy cmdlets, registry value
                # names and policy-store paths fail this conservative source guard.
                $content | Should -Not -Match '(?i)Set-ExecutionPolicy|\bsecpol\b|EnableScripts|ShellIds|\\Policies\\Microsoft\\Windows\\PowerShell'
                ($content -replace '(?i)-ExecutionPolicy\s+Bypass','') | Should -Not -Match '(?i)ExecutionPolicy'
            }
        }
    }
}
