BeforeAll {
 $script:root=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
 Import-Module (Join-Path $script:root 'src/ESAF.psd1') -Force
}
Describe 'Milestone 5 support evidence export' {
 InModuleScope ESAF {
  BeforeEach {
   $script:evidencePath=Join-Path $TestDrive 'canonical-evidence.json'
   $script:supportPath=Join-Path $TestDrive 'support/latest-assurance.json'
   $script:imeDirectory=Join-Path $TestDrive 'ime-logs'
   $null=New-Item -ItemType Directory -Path $script:imeDirectory -Force
    $firstEvidence=[pscustomobject]@{evidenceProvider='RealTimeProtection';observed='Enabled';collectedAt='2026-01-01T00:00:00Z';status='Collected';raw=[pscustomobject]@{private='raw-value'};errorMessage='uncontrolled-provider-detail'}
    $firstEvidence|Add-Member -NotePropertyName ('access'+'Token') -NotePropertyValue 'synthetic-placeholder'
    $script:source=[pscustomobject][ordered]@{
     schemaVersion='1.0';runId='ESAF-20260101-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';device='TEST-DEVICE'
     tenantMetadata='must-not-export';authorization='Bearer synthetic-value'
     controls=@(
      [pscustomobject]@{id='ESAF-AV-002';evidence=$firstEvidence}
     [pscustomobject]@{id='ESAF-NET-001';evidence=[pscustomobject]@{evidenceProvider='NetworkProtection';observed='Block';collectedAt='2026-01-01T00:00:01Z';status='Collected';raw=[pscustomobject]@{private='raw-value-2'};errorMessage=$null}}
    )
    }
    $script:source|Add-Member -NotePropertyName ('client'+'Secret') -NotePropertyValue 'synthetic-placeholder'
   $json=$script:source|ConvertTo-Json -Depth 12
   [IO.File]::WriteAllText($script:evidencePath,$json,(New-Object Text.UTF8Encoding($false)))
   $script:sourceBytes=[IO.File]::ReadAllBytes($script:evidencePath)
    Mock Set-ESAFStoragePermissions {}
    $script:invokeSupportExport={Export-ESAFSupportEvidence -EvidencePath $script:evidencePath -SupportPath $script:supportPath -IntuneLogDirectory $script:imeDirectory}
   }
  It 'exports valid ESAF schema 1.0 evidence successfully' {
    $r=& $script:invokeSupportExport
   Test-Path $script:supportPath|Should -BeTrue
   $r.intuneTransportStatus|Should -Be Copied
  }
  It 'writes transport contract version 0.1 without changing the evidence schema' {
    $null=& $script:invokeSupportExport;$o=Get-Content $script:supportPath -Raw|ConvertFrom-Json
   $o.transportVersion|Should -Be '0.1';$o.evidenceSchemaVersion|Should -Be '1.0'
  }
  It 'retains the canonical device and run ID' {
    $null=& $script:invokeSupportExport;$o=Get-Content $script:supportPath -Raw|ConvertFrom-Json
   $o.device|Should -Be TEST-DEVICE;$o.runId|Should -Be 'ESAF-20260101-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
  }
  It 'links the exact canonical source bytes with SHA-256' {
   $expected=(Get-FileHash $script:evidencePath -Algorithm SHA256).Hash
    $null=& $script:invokeSupportExport
   (Get-Content $script:supportPath -Raw|ConvertFrom-Json).sourceEvidenceSha256|Should -Be $expected
  }
  It 'retains only normalized control fields' {
    $null=& $script:invokeSupportExport;$c=(Get-Content $script:supportPath -Raw|ConvertFrom-Json).controls[0]
   $c.id|Should -Be 'ESAF-AV-002';$c.evidenceProvider|Should -Be RealTimeProtection
   $c.observed|Should -Be Enabled;$c.collectedAt|Should -Be '2026-01-01T00:00:00Z';$c.status|Should -Be Collected
   @($c.PSObject.Properties.Name)|Should -Be @('id','evidenceProvider','observed','collectedAt','status')
  }
  It 'never exports raw provider evidence' {
    $null=& $script:invokeSupportExport
   (Get-Content $script:supportPath -Raw)|Should -Not -Match 'raw-value|"raw"'
  }
  It 'never exports uncontrolled provider error detail' {
    $null=& $script:invokeSupportExport
   (Get-Content $script:supportPath -Raw)|Should -Not -Match 'uncontrolled-provider-detail|errorMessage'
  }
  It 'never exports authorization token credential or tenant fields' {
    $null=& $script:invokeSupportExport
   (Get-Content $script:supportPath -Raw)|Should -Not -Match 'tenantMetadata|authorization|Bearer|clientSecret|accessToken|synthetic-secret|synthetic-token'
  }
  It 'does not modify canonical evidence' {
    $null=& $script:invokeSupportExport
   [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:evidencePath))|Should -Be ([Convert]::ToBase64String($script:sourceBytes))
  }
  It 'creates the support artifact atomically without retaining a temporary file' {
    $null=& $script:invokeSupportExport
   Test-Path ($script:supportPath+'.tmp')|Should -BeFalse
   {Get-Content $script:supportPath -Raw|ConvertFrom-Json -ErrorAction Stop}|Should -Not -Throw
  }
  It 'writes byte-equivalent canonical support and Intune adapter artifacts' {
    $null=& $script:invokeSupportExport;$adapter=Join-Path $script:imeDirectory 'ESAF-Assurance.log'
   [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:supportPath))|Should -Be ([Convert]::ToBase64String([IO.File]::ReadAllBytes($adapter)))
  }
  It 'atomically replaces an existing transport artifact' {
   $adapter=Join-Path $script:imeDirectory 'ESAF-Assurance.log';'old-partial-value'|Set-Content $adapter
    $null=& $script:invokeSupportExport
   (Get-Content $adapter -Raw|ConvertFrom-Json).transportVersion|Should -Be '0.1'
   (Get-Content $adapter -Raw)|Should -Not -Match 'old-partial-value'
   Test-Path ($adapter+'.tmp')|Should -BeFalse
  }
  It 'creates canonical support evidence when IME Logs is unavailable' {
    [IO.Directory]::Delete($script:imeDirectory,$true)
    $r=& $script:invokeSupportExport
   Test-Path $script:supportPath|Should -BeTrue
   $r.intuneTransportStatus|Should -Be Unavailable
  }
  It 'does not create missing IME infrastructure' {
    [IO.Directory]::Delete($script:imeDirectory,$true)
    $null=& $script:invokeSupportExport
   Test-Path $script:imeDirectory|Should -BeFalse
  }
  It 'rejects an invalid evidence schema' {
   $script:source.schemaVersion='2.0';[IO.File]::WriteAllText($script:evidencePath,($script:source|ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($false)))
    {& $script:invokeSupportExport}|Should -Throw
  }
  It 'rejects malformed canonical JSON safely' {
   [IO.File]::WriteAllText($script:evidencePath,'{broken',(New-Object Text.UTF8Encoding($false)))
    {& $script:invokeSupportExport}|Should -Throw
  }
  It 'rejects missing runId device and controls' -ForEach @('runId','device','controls') {
   $script:source.PSObject.Properties.Remove($_)
   [IO.File]::WriteAllText($script:evidencePath,($script:source|ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($false)))
    {& $script:invokeSupportExport}|Should -Throw
  }
  It 'rejects controls that are not an array' {
   $script:source.controls=[pscustomobject]@{id='ESAF-AV-002';evidence=[pscustomobject]@{}}
   [IO.File]::WriteAllText($script:evidencePath,($script:source|ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($false)))
    {& $script:invokeSupportExport}|Should -Throw
  }
  It 'rejects duplicate control identifiers' {
   $script:source.controls+=($script:source.controls[0]|ConvertTo-Json -Depth 8|ConvertFrom-Json)
   [IO.File]::WriteAllText($script:evidencePath,($script:source|ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($false)))
    {& $script:invokeSupportExport}|Should -Throw
  }
   It 'does not corrupt canonical evidence when support export fails' {
   $before=[Convert]::ToBase64String([IO.File]::ReadAllBytes($script:evidencePath))
   {Export-ESAFSupportEvidence -EvidencePath $script:evidencePath -SupportPath (Join-Path $script:evidencePath 'invalid-child') -IntuneLogDirectory $script:imeDirectory}|Should -Throw
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:evidencePath))|Should -Be $before
   }
   It 'preserves the last successfully exported artifact when a later export fails' {
    $null=& $script:invokeSupportExport
    $before=[Convert]::ToBase64String([IO.File]::ReadAllBytes($script:supportPath))
    [IO.File]::WriteAllText($script:evidencePath,'{broken',(New-Object Text.UTF8Encoding($false)))
    {& $script:invokeSupportExport}|Should -Throw
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:supportPath))|Should -Be $before
   }
  It 'uses the existing protected ESAF ACL utility only for support storage' {
    $null=& $script:invokeSupportExport
   Should -Invoke Set-ESAFStoragePermissions -Times 2 -ParameterFilter{$Path -eq (Split-Path $script:supportPath -Parent)}
   Should -Invoke Set-ESAFStoragePermissions -Times 0 -ParameterFilter{$Path -eq $script:imeDirectory}
  }
  It 'contains no network Graph registry or endpoint-security mutation commands' {
   $body=(Get-Command Export-ESAFSupportEvidence).ScriptBlock.ToString()
   $body|Should -Not -Match '(?i)Invoke-WebRequest|Invoke-RestMethod|Invoke-MgGraphRequest|Connect-MgGraph|New-ItemProperty|Set-ItemProperty'
   $body|Should -Not -Match '(?i)Set-MpPreference|Add-MpPreference|Remove-MpPreference|Set-NetFirewall|Enable-BitLocker|Disable-BitLocker|Set-SecureBoot'
  }
  It 'contains no live endpoint or tenant identifiers in exporter production and tests' {
   $files=@((Join-Path $script:RepositoryRoot 'src/Reporting/Reporting.ps1'),$PSCommandPath)
    $content=($files|ForEach-Object{Get-Content -LiteralPath $_ -Raw})-join [Environment]::NewLine
   $content|Should -Not -Match 'DESKTOP-[A-Z0-9]+'
   $content|Should -Not -Match '(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b'
  }
  It 'contains no common credential patterns' {
   $files=@((Join-Path $script:RepositoryRoot 'src/Reporting/Reporting.ps1'),$PSCommandPath)
    $content=($files|ForEach-Object{Get-Content -LiteralPath $_ -Raw})-join [Environment]::NewLine
   $content|Should -Not -Match '(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)'
  }
  It 'remains clean under the production security scan' {
   {& (Join-Path $script:RepositoryRoot 'tools/Test-ESAFSecurity.ps1') -RepositoryRoot $script:RepositoryRoot}|Should -Not -Throw
  }
 }
}
Describe 'Milestone 5 publication integration' {
 InModuleScope ESAF {
  BeforeEach {
   Mock Get-ESAFPlatform{[pscustomobject]@{platform='Windows';build=22631;productType=1}}
   Mock Set-ESAFStoragePermissions{}
   Mock Get-ESAFEvidence{
    param($Provider)
    $values=@{MDEOnboardingState='Onboarded';MDESensorService='Running';DefenderAntivirus='Active';RealTimeProtection='Enabled';NetworkProtection='Block';CloudProtection='Enabled';SecurityIntelligence='Fresh';TamperProtection='Enabled';DefenderExclusions='Clear';WindowsFirewall='Enabled';BitLockerOS='Protected';TPMReadiness='Ready';SecureBoot='Enabled';ASRAssessment='Assessed'}
    [pscustomobject]@{evidenceProvider=$Provider;observed=$values[$Provider];collectedAt='2026-01-01T00:00:00Z';raw=[pscustomobject]@{};status='Collected';errorCategory=$null;errorMessage=$null}
   }
   Mock Add-Content{}
  }
  It 'starts support export only after canonical publication completes' {
   $script:published=$false
   Mock Write-ESAFReport{$script:published=$true}
   Mock Export-ESAFSupportEvidence{if(-not $script:published){throw 'ordering failure'};[pscustomobject]@{intuneTransportStatus='Unavailable'}}
   $r=Invoke-ESAFValidation -OutputPath (Join-Path $TestDrive 'ordered')
   $r.status|Should -Be PASS
   Should -Invoke Export-ESAFSupportEvidence -Times 1
  }
  It 'does not attempt support export after canonical publication fails' {
   Mock Write-ESAFReport{throw 'canonical publication failed'}
   Mock Export-ESAFSupportEvidence{}
   {Invoke-ESAFValidation -OutputPath (Join-Path $TestDrive 'failed-publication')}|Should -Throw
   Should -Invoke Export-ESAFSupportEvidence -Times 0
  }
  It 'preserves the completed assessment when support export fails' {
   Mock Write-ESAFReport{}
   Mock Export-ESAFSupportEvidence{throw 'support export failed'}
   $r=Invoke-ESAFValidation -OutputPath (Join-Path $TestDrive 'failed-export') -WarningAction SilentlyContinue
   $r.status|Should -Be PASS
  }
  It 'records optional Intune transport unavailability separately' {
   Mock Write-ESAFReport{}
   Mock Export-ESAFSupportEvidence{[pscustomobject]@{intuneTransportStatus='Unavailable'}}
   $null=Invoke-ESAFValidation -OutputPath (Join-Path $TestDrive 'unavailable')
   Should -Invoke Add-Content -Times 1 -ParameterFilter{$Value -match 'SupportExport=Complete IntuneTransport=Unavailable'}
  }
 }
}
