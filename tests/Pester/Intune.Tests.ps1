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
        $body=$body.Replace('[Environment]::GetFolderPath(''CommonApplicationData'')','$PSScriptRoot')
        # Replace only protected storage for this unprivileged installer harness.
        $body=$body.Replace('param($Record)','param($Record); $Record | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $PSScriptRoot ''captured.json''); return')
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
        (Get-Content (Join-Path $TestDrive 'captured.json') -Raw | ConvertFrom-Json).stage | Should -Be 'ESAF validation'
    }
}

Describe 'Secure bootstrap installer diagnostics' {
    BeforeAll {
        $script:installer=Get-Content (Join-Path $script:repo 'intune/package/Install-ESAF.ps1') -Raw
        $tokens=$null;$errors=$null
        $ast=[Management.Automation.Language.Parser]::ParseInput($script:installer,[ref]$tokens,[ref]$errors)
        $functions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false))
        foreach ($function in $functions) {
            $source=$function.Extent.Text.Replace('[Environment]::GetFolderPath(''CommonApplicationData'')','$TestDrive')
            . ([scriptblock]::Create($source))
        }
    }
    It 'records each required stage before its corresponding operation' {
        $expected=[ordered]@{
            'architecture check'='if (-not [Environment]::Is64BitProcess)';
            'package support load'=". (Join-Path `$PackageRoot 'PackageSupport.ps1')";
            'package validation'='$manifest=Assert-ESAFPackage';
            'execution-lock load'=". (Join-Path `$PackageRoot 'ExecutionLock.ps1')";
            'execution-lock acquire'='$executionLock=Enter-ESAFExecutionLock';
            'payload module import'='$module=Import-Module';
            'payload copy'='& $module { param($source,$target)';
            'uninstall script copy'='Copy-Item -LiteralPath';
            'installed module import'='$installed=Import-Module';
            'installed module path verification'='if ([IO.Path]::GetFullPath($installed.ModuleBase)';
            'ESAF validation'='$r=& $installed';
            'result validation'='if ($r.status'
        }
        foreach ($entry in $expected.GetEnumerator()) {
            $pattern=[regex]::Escape("`$stage='$($entry.Key)'")+ '\s*'+[regex]::Escape($entry.Value)
            $script:installer | Should -Match $pattern
        }
    }
    It 'preserves reviewed messages and records UTC type and numeric line metadata' {
        try { throw 'Unexpected installed module.' } catch { $record=New-ESAFInstallerDiagnostic $_ 'installed module path verification' }
        $record.message | Should -Be 'Unexpected installed module.'
        $record.stage | Should -Be 'installed module path verification'
        $record.exceptionType | Should -Be 'System.Management.Automation.RuntimeException'
        $record.scriptLineNumber | Should -BeGreaterThan 0
        $record.timestampUtc | Should -Match 'Z$'
        $record.exitCode | Should -Be 1
    }
    It 'redacts arbitrary secrets in messages error IDs and stack paths without environment dumps' {
        $secret='unique-sensitive-fixture-value'
        $exception=New-Object InvalidOperationException("password=$secret Bearer $secret path=C:\private\$secret")
        $failure=New-Object Management.Automation.ErrorRecord($exception,$secret,[Management.Automation.ErrorCategory]::InvalidOperation,$secret)
        $record=New-ESAFInstallerDiagnostic $failure 'payload copy'
        $json=$record | ConvertTo-Json -Depth 4
        $json | Should -Not -Match $secret
        $record.message | Should -Be '[Redacted untrusted exception text]'
        $record.fullyQualifiedErrorId | Should -Be '[Redacted untrusted error ID]'
        @($record.Keys).Count | Should -Be 9
        $json | Should -Not -Match 'password|Bearer|private|environment|TargetObject|PositionMessage'
    }
    It 'creates only SYSTEM and Administrators inheritable FullControl ACL intent' {
        $acl=New-ESAFInstallerLogAcl
        $acl.AreAccessRulesProtected | Should -BeTrue
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value | Should -Be 'S-1-5-32-544'
        $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        $rules.Count | Should -Be 2
        foreach($rule in $rules) {
            $rule.IdentityReference.Value | Should -BeIn @('S-1-5-18','S-1-5-32-544')
            $rule.FileSystemRights | Should -Be FullControl
            $rule.AccessControlType | Should -Be Allow
        }
    }
    It 'persists sanitized JSON in a protected unique file' {
        try { throw 'Unexpected installed module.' } catch { $record=New-ESAFInstallerDiagnostic $_ 'installed module path verification' }
        # Filesystem writes are real; privileged ACL inspection is a boundary mock.
        $null=New-Item -ItemType Directory -Path (Join-Path $TestDrive 'ESAF/installer-diagnostics') -Force
        Mock Get-Acl { New-ESAFInstallerLogAcl }
        Write-ESAFInstallerDiagnostic $record
        $file=Get-ChildItem (Join-Path $TestDrive 'ESAF/installer-diagnostics') -Filter 'installer-*.json' | Select-Object -First 1
        (Get-Content $file.FullName -Raw | ConvertFrom-Json).stage | Should -Be 'installed module path verification'
        $rules=@((Get-Acl $file.FullName).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        $rules.Count | Should -Be 2
        foreach($rule in $rules) { $rule.IdentityReference.Value | Should -BeIn @('S-1-5-18','S-1-5-32-544'); $rule.FileSystemRights | Should -Be FullControl }
    }
    It 'keeps exit one and generic stdout when diagnostic writing fails' {
        $body=$script:installer -replace '(?m)^#Requires -RunAsAdministrator\r?\n',''
        $body=$body.Replace('param($Record)',"param(`$Record)`n throw 'Diagnostic fixture failure'")
        $fixture=Join-Path $TestDrive 'logging-failure.ps1'
        $body | Set-Content $fixture
        # Missing package support fails before any installation operations or lock.
        $text=& (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $fixture -PackageRoot (Join-Path $TestDrive 'missing-package')
        $LASTEXITCODE | Should -Be 1
        $text | Should -Be 'ESAF installation, validation or publication failed.'
    }
}
