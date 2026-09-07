BeforeAll {
    $script:root=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $script:root 'src/ESAF.psd1') -Force
}
Describe 'Provider registry and normalization' {
    InModuleScope ESAF {
        It 'loads a new control using an existing approved provider with a different valid expected state' {
            $b=Get-ESAFBaseline (Join-Path $script:RepositoryRoot 'baselines/Corporate-W11.json')
            $folder=Join-Path $TestDrive 'controls'
            Copy-Item (Join-Path $script:RepositoryRoot 'controls') $folder -Recurse
            $c=Read-ESAFJson (Join-Path $folder 'network/ESAF-NET-001.json')
            $c.id='ESAF-NET-099'; $c.expected.state='Audit'
            $c | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $folder 'network/ESAF-NET-099.json')
            $b.controls=@('ESAF-NET-099')
            $loaded=@(Get-ESAFControls $b $folder)
            $loaded[0].expected.state | Should -Be Audit
            $e=[pscustomobject]@{observed='Audit';status='Collected';errorCategory=$null;errorMessage=$null}
            (Get-ESAFControlResult $loaded[0] $e $true $false).status | Should -Be PASS
            foreach ($invalid in @('Enabled','Unknown','Block; whoami',1,@('Block'))) {
                $c.expected.state=$invalid
                $c | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $folder 'network/ESAF-NET-099.json')
                { Get-ESAFControls $b $folder } | Should -Throw
            }
        }
        It 'never invokes unknown or executable-looking provider names' {
            Mock Get-ESAFSensorEvidence { throw 'Should not run' }
            foreach ($name in @('Unknown','Get-ESAFSensorEvidence','MDESensorService; whoami','$(whoami)','{whoami}')) {
                (Get-ESAFEvidence $name).status | Should -Be ERROR
            }
            Should -Invoke Get-ESAFSensorEvidence -Times 0
        }
        It 'dispatches approved names only through internal functions' {
            Mock Get-ESAFSensorEvidence { [pscustomobject]@{observed='Running';raw=@{State='Running'}} }
            (Get-ESAFEvidence MDESensorService).observed | Should -Be Running
            Should -Invoke Get-ESAFSensorEvidence -Times 1
        }
        It 'handles numeric strings named enums and unknown Network Protection values' {
            foreach ($value in @(1,'1','Enabled')) { ConvertTo-ESAFNetworkState $value | Should -Be Block }
            foreach ($value in @(2,'2','AuditMode')) { ConvertTo-ESAFNetworkState $value | Should -Be Audit }
            foreach ($value in @(0,'0','Disabled')) { ConvertTo-ESAFNetworkState $value | Should -Be Disabled }
            foreach ($value in @($null,$true,'Block','Warn',99)) { ConvertTo-ESAFNetworkState $value | Should -Be Unknown }
            ConvertTo-ESAFNetworkState ([DayOfWeek]::Monday) | Should -Be Unknown
        }
        It 'does not coerce missing or textual booleans into active protection' {
            ConvertTo-ESAFBooleanState 'False' | Should -Be Unknown
            ConvertTo-ESAFBooleanState 1 | Should -Be Unknown
            ConvertTo-ESAFAntivirusState Normal 'True' 'True' | Should -Be Unknown
            foreach ($mode in @('Passive Mode','SxS Passive Mode','EDR Block Mode')) { ConvertTo-ESAFAntivirusState $mode $true $true | Should -Be Passive }
            ConvertTo-ESAFAntivirusState 'NotPassiveGarbage' $true $true | Should -Be Unknown
        }
        It 'preserves raw Network Protection enum values beside normalized observations' {
            function Get-MpPreference {}
            Add-Type -TypeDefinition 'public enum ESAFTestNetworkMode { Disabled=0, Enabled=1, AuditMode=2 }'
            Mock Get-MpPreference { [pscustomobject]@{EnableNetworkProtection=[ESAFTestNetworkMode]::Enabled} }
            $e=Get-ESAFEvidence NetworkProtection
            $e.observed | Should -Be Block
            $e.raw.EnableNetworkProtection | Should -Be ([ESAFTestNetworkMode]::Enabled)
        }
        It 'handles service transitions and missing onboarding properties conservatively' {
            ConvertTo-ESAFServiceState 'Start Pending' $true | Should -Be Unknown
            ConvertTo-ESAFServiceState 'Stop Pending' $true | Should -Be Unknown
            ConvertTo-ESAFOnboardingState $null | Should -Be Unknown
            ConvertTo-ESAFOnboardingState $true | Should -Be Unknown
            Mock Test-Path { $true }
            Mock Get-ItemProperty { [pscustomobject]@{} }
            $e=Get-ESAFEvidence MDEOnboardingState
            $e.status | Should -Be Collected
            $e.observed | Should -Be Unknown
            $e.raw.OnboardingState | Should -BeNullOrEmpty
        }
    }
}
Describe 'Storage access control' {
    InModuleScope ESAF {
        It 'builds protected file and directory ACLs with only SYSTEM and Administrators full control' {
            foreach ($file in @($false,$true)) {
                $acl=New-ESAFStorageAcl -File:$file
                $acl.AreAccessRulesProtected | Should -BeTrue
                $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value | Should -Be 'S-1-5-32-544'
                $rules=@($acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]))
                $rules.Count | Should -Be 2
                foreach ($rule in $rules) {
                    $rule.IdentityReference.Value | Should -BeIn @('S-1-5-18','S-1-5-32-544')
                    $rule.FileSystemRights | Should -Be ([Security.AccessControl.FileSystemRights]::FullControl)
                    $rule.AccessControlType | Should -Be Allow
                    if ($file) { $rule.InheritanceFlags | Should -Be None }
                    else { [int]$rule.InheritanceFlags | Should -Be 3 }
                }
            }
        }
        It 'replaces explicit permissions on existing result evidence and history children' {
            $path=Join-Path $TestDrive 'acl'
            $null=New-Item -ItemType Directory -Path (Join-Path $path 'history') -Force
            'x' | Set-Content (Join-Path $path 'result.json')
            'x' | Set-Content (Join-Path $path 'evidence.json')
            Mock Set-Acl {}
            Set-ESAFStoragePermissions $path
            Should -Invoke Set-Acl -Times 4 -Exactly
        }
    }
}
Describe 'Repeated installation payload copies' {
    InModuleScope ESAF {
        It 'updates exact destination files removes obsolete code and preserves separate history' {
            Mock Set-ESAFStoragePermissions {}
            $source=Join-Path $TestDrive 'source'; $target=Join-Path $TestDrive 'installed'
            foreach ($name in @('src','controls','baselines','tools')) {
                $null=New-Item -ItemType Directory -Path (Join-Path $source $name) -Force
                'v1' | Set-Content (Join-Path $source ($name+'/file.txt'))
            }
            $history=Join-Path $TestDrive 'ProgramData/history/old'
            $null=New-Item -ItemType Directory -Path $history -Force
            'history' | Set-Content (Join-Path $history 'result.json')
            Copy-ESAFPayload $source $target
            'old code' | Set-Content (Join-Path $target 'src/obsolete.ps1')
            'v2' | Set-Content (Join-Path $source 'src/file.txt')
            Copy-ESAFPayload $source $target
            Get-Content (Join-Path $target 'src/file.txt') | Should -Be v2
            Test-Path (Join-Path $target 'src/obsolete.ps1') | Should -BeFalse
            Test-Path (Join-Path $target 'src/src') | Should -BeFalse
            Get-Content (Join-Path $history 'result.json') | Should -Be history
            @(Get-ChildItem $target -Recurse -File).Count | Should -Be 4
        }
        It 'rejects overlapping paths before copying' {
            { Copy-ESAFPayload $TestDrive $TestDrive } | Should -Throw
            { Copy-ESAFPayload $TestDrive (Join-Path $TestDrive 'child') } | Should -Throw
        }
    }
}

Describe 'Installed module identity' {
    It 'reloads the actual installed module with installed baseline and provider paths' {
        $payload=Join-Path $TestDrive 'payload'
        $null=New-Item -ItemType Directory -Path $payload
        foreach ($folder in @('src','controls','baselines','tools')) { Copy-Item (Join-Path $script:root $folder) $payload -Recurse }
        $harness=Join-Path $TestDrive 'module-test.ps1'
        @'
param([string]$Source,[string]$Target)
$ErrorActionPreference='Stop'
$module=Import-Module (Join-Path $Source 'src/ESAF.psd1') -Force -PassThru
& $module {
    param($source,$target)
    function Set-ESAFStoragePermissions {}
    Copy-ESAFPayload $source $target
} $Source $Target
Remove-Module ESAF -Force
$installed=Import-Module (Join-Path $Target 'src/ESAF.psd1') -Force -PassThru
& $installed {
    param($target)
    if ($script:RepositoryRoot -ne $target) { throw 'Source module root leaked.' }
    $b=Get-ESAFBaseline (Join-Path $script:RepositoryRoot 'baselines/Corporate-W11.json')
    $controls=@(Get-ESAFControls $b (Join-Path $script:RepositoryRoot 'controls'))
    if ($controls.Count -ne 5) { throw 'Installed controls not loaded.' }
} $Target
Write-Output $installed.ModuleBase
'@ | Set-Content $harness
        $target=Join-Path $TestDrive 'installed-module'
        $text=& (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $harness -Source $payload -Target $target
        $LASTEXITCODE | Should -Be 0
        $text | Should -Be (Join-Path $target 'src')
    }
}
