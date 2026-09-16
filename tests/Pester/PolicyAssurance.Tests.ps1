BeforeAll {
 $script:root=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
 Import-Module (Join-Path $script:root 'policy-assurance/ESAF.PolicyAssurance.psm1') -Force
 $script:policyId='11111111-1111-4111-8111-111111111111'
 $script:managedId='22222222-2222-4222-8222-222222222222'
 $script:entraDeviceId='33333333-3333-4333-8333-333333333333'
 $script:entraObjectId='44444444-4444-4444-8444-444444444444'
 $script:groupId='55555555-5555-4555-8555-555555555555'
 $script:defId='device_vendor_msft_policy_config_defender_allowrealtimemonitoring'
 $script:scopes=@('DeviceManagementConfiguration.Read.All','DeviceManagementManagedDevices.Read.All','Device.Read.All')

 function New-PolicyState {
  $enabled=$script:defId+'_1';$disabled=$script:defId+'_0'
  @{
   ManagedDevices=@([pscustomobject]@{id=$script:managedId;deviceName='TEST-DEVICE';azureADDeviceId=$script:entraDeviceId})
   EntraDevices=@([pscustomobject]@{id=$script:entraObjectId;deviceId=$script:entraDeviceId})
   Memberships=@([pscustomobject]@{id=$script:groupId})
   Policy=[pscustomobject]@{id=$script:policyId;name='Synthetic Antivirus Policy';technologies='mdm,microsoftSense';templateReference=[pscustomobject]@{templateDisplayName='Microsoft Defender Antivirus'}}
   Assignments=@([pscustomobject]@{target=[pscustomobject]@{'@odata.type'='#microsoft.graph.groupAssignmentTarget';groupId=$script:groupId;deviceAndAppManagementAssignmentFilterType='none';deviceAndAppManagementAssignmentFilterId=$null}})
   Settings=@([pscustomobject]@{id='setting-1';settingInstance=[pscustomobject]@{settingDefinitionId=$script:defId;choiceSettingValue=[pscustomobject]@{value=$enabled}}})
   Definition=[pscustomobject]@{id=$script:defId;displayName='Allow Realtime Monitoring';options=@(
    [pscustomobject]@{itemId=$enabled;displayName='Allowed';optionValue=[pscustomobject]@{value=1}}
    [pscustomobject]@{itemId=$disabled;displayName='Not allowed';optionValue=[pscustomobject]@{value=0}}
   )}
   Requests=New-Object Collections.ArrayList
   FailGraph=$false
  }
 }
 function New-GraphGet {
  param([hashtable]$State)
  {
   param($Uri)
   $null=$State.Requests.Add($Uri)
   if($State.FailGraph){throw 'synthetic Graph failure'}
   if($Uri -match '/managedDevices\?'){return [pscustomobject]@{value=@($State.ManagedDevices)}}
   if($Uri -match '/devices\?'){return [pscustomobject]@{value=@($State.EntraDevices)}}
   if($Uri -match '/transitiveMemberOf/'){return [pscustomobject]@{value=@($State.Memberships)}}
   if($Uri -match '/deviceManagement/configurationSettings/'){return $State.Definition}
   if($Uri -match '/assignments$'){return [pscustomobject]@{value=@($State.Assignments)}}
   if($Uri -match '/settings$'){return [pscustomobject]@{value=@($State.Settings)}}
   if($Uri -match '/configurationPolicies/[0-9a-f-]+$'){return $State.Policy}
   throw "Unexpected synthetic URI: $Uri"
  }.GetNewClosure()
 }
 function Write-Evidence {
  param([string]$Path,[string]$Observed='Enabled',[string]$Status='Collected',[string]$Device='TEST-DEVICE',[string]$Schema='1.0',[int]$ControlCount=1)
  $controls=@()
  if($ControlCount -gt 0){1..$ControlCount|ForEach-Object{$controls+=[pscustomobject]@{id='ESAF-AV-002';evidence=[pscustomobject]@{evidenceProvider='RealTimeProtection';observed=$Observed;collectedAt='2026-01-01T00:00:00Z';status=$Status}}}}
  [pscustomobject]@{schemaVersion=$Schema;runId='ESAF-20260101-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';device=$Device;controls=$controls}|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $Path
 }
 function Invoke-Synthetic {
  param([hashtable]$State,[string]$Observed='Enabled',[string]$Status='Collected',[string]$Device='TEST-DEVICE',[string]$Schema='1.0',[int]$ControlCount=1,[string]$OutputPath)
  $path=Join-Path $TestDrive ([Guid]::NewGuid().ToString()+'.json')
  Write-Evidence $path $Observed $Status $Device $Schema $ControlCount
  Invoke-ESAFPolicyReconciliation -PolicyId $script:policyId -DeviceName 'TEST-DEVICE' -EvidencePath $path -GraphGet (New-GraphGet $State) -GrantedScopes $script:scopes -OutputPath $OutputPath
 }
}
Describe 'Milestone 4 policy intent reconciliation' {
 BeforeEach {$script:state=New-PolicyState}
 It 'returns MATCH for Microsoft Enabled and ESAF Enabled' {
  $r=Invoke-Synthetic $state Enabled
  $r.result|Should -Be MATCH
  $r.setting.normalizedIntent|Should -Be Enabled
  $r.assignment.applies|Should -BeTrue
  @($r.assignment.matchedGroupIds)|Should -Be @($script:groupId)
  $state.Requests|Should -Contain ('https://graph.microsoft.com/beta/deviceManagement/configurationSettings/'+[Uri]::EscapeDataString($script:defId))
  @($state.Requests|Where-Object{$_ -match '/settings/[^/]+/settingDefinitions'}).Count|Should -Be 0
 }
 It 'returns MATCH for Microsoft Disabled and ESAF Disabled' {
  $state.Settings[0].settingInstance.choiceSettingValue.value=$script:defId+'_0'
  (Invoke-Synthetic $state Disabled).result|Should -Be MATCH
 }
 It 'returns MISMATCH for Microsoft Enabled and ESAF Disabled' {
  (Invoke-Synthetic $state Disabled).result|Should -Be MISMATCH
 }
 It 'returns MISMATCH for Microsoft Disabled and ESAF Enabled' {
  $state.Settings[0].settingInstance.choiceSettingValue.value=$script:defId+'_0'
  (Invoke-Synthetic $state Enabled).result|Should -Be MISMATCH
 }
 It 'returns UNKNOWN for an unsupported Microsoft choice even when the definition contains it' {
  $choice=$script:defId+'_2';$state.Settings[0].settingInstance.choiceSettingValue.value=$choice
  $state.Definition.options+= [pscustomobject]@{itemId=$choice;displayName='Synthetic other choice';optionValue=[pscustomobject]@{value=2}}
  (Invoke-Synthetic $state).result|Should -Be UNKNOWN
 }
 It 'does not infer normalization from a configured item ID suffix' {
  $state.Definition.options[0].optionValue.value=0
  (Invoke-Synthetic $state Enabled).result|Should -Be MISMATCH
 }
 It 'returns UNKNOWN when the retrieved definition identity is unexpected' {
  $state.Definition.id='synthetic_unexpected_definition'
  (Invoke-Synthetic $state).result|Should -Be UNKNOWN
 }
 It 'uses configurationSettings by definition ID and rejects the old nested definition route' {
  $state.Settings[0].id='0'
  $r=Invoke-Synthetic $state
  $r.result|Should -Be MATCH
  $expected='https://graph.microsoft.com/beta/deviceManagement/configurationSettings/'+[Uri]::EscapeDataString($script:defId)
  $state.Requests|Should -Contain $expected
  @($state.Requests|Where-Object{$_ -match '/configurationPolicies/.+/settings/0/settingDefinitions'}).Count|Should -Be 0
  $source=Get-Content (Join-Path $script:root 'policy-assurance/ESAF.PolicyAssurance.psm1') -Raw
  $source|Should -Match '/deviceManagement/configurationSettings/'
  $source|Should -Not -Match 'settingsUri.*settingDefinitions|/settings/[^/]+/settingDefinitions'
 }
 It 'returns UNKNOWN when the mapped Microsoft choice is missing' {
  $state.Settings[0].settingInstance.PSObject.Properties.Remove('choiceSettingValue')
  (Invoke-Synthetic $state).result|Should -Be UNKNOWN
 }
 It 'returns UNKNOWN when policy intent is absent' {
  $state.Settings=@()
  (Invoke-Synthetic $state).result|Should -Be UNKNOWN
 }
 It 'returns UNKNOWN when settingDefinitionId is missing' {
  $state.Settings[0].settingInstance.PSObject.Properties.Remove('settingDefinitionId')
  $r=Invoke-Synthetic $state
  $r.result|Should -Be UNKNOWN
  @($state.Requests|Where-Object{$_ -match '/deviceManagement/configurationSettings/'}).Count|Should -Be 0
 }
 It 'returns UNKNOWN when the definition endpoint returns no definition' {
  $state.Definition=$null
  (Invoke-Synthetic $state).result|Should -Be UNKNOWN
 }
 It 'returns UNKNOWN when supported group assignments do not apply' {
  $state.Memberships=@([pscustomobject]@{id='66666666-6666-4666-8666-666666666666'})
  $r=Invoke-Synthetic $state
  $r.result|Should -Be UNKNOWN;$r.assignment.applies|Should -BeFalse
 }
 It 'returns UNKNOWN when an assignment filter is present' {
  $state.Assignments[0].target.deviceAndAppManagementAssignmentFilterType='include'
  $r=Invoke-Synthetic $state
  $r.result|Should -Be UNKNOWN;$r.assignment.filtersPresent|Should -BeTrue
 }
 It 'returns UNKNOWN for an unsupported assignment target' {
  $state.Assignments[0].target.'@odata.type'='#microsoft.graph.allDevicesAssignmentTarget'
  (Invoke-Synthetic $state).result|Should -Be UNKNOWN
 }
 It 'returns ERROR when no Intune managed device matches' {
  $state.ManagedDevices=@()
  $r=Invoke-Synthetic $state
  $r.result|Should -Be ERROR;$r.reason|Should -Match 'No Intune managed device'
 }
 It 'returns ERROR rather than guessing when managed-device identity is ambiguous' {
  $state.ManagedDevices+= [pscustomobject]@{id='77777777-7777-4777-8777-777777777777';deviceName='TEST-DEVICE';azureADDeviceId='88888888-8888-4888-8888-888888888888'}
  $r=Invoke-Synthetic $state
  $r.result|Should -Be ERROR;$r.reason|Should -Match 'ambiguous'
 }
 It 'returns ERROR when evidence device does not match the requested device' {
  (Invoke-Synthetic $state Enabled Collected 'OTHER-DEVICE').result|Should -Be ERROR
 }
 It 'returns UNKNOWN when ESAF-AV-002 is missing' {
  (Invoke-Synthetic $state Enabled Collected 'TEST-DEVICE' '1.0' 0).result|Should -Be UNKNOWN
 }
 It 'returns ERROR when ESAF-AV-002 is duplicated' {
  (Invoke-Synthetic $state Enabled Collected 'TEST-DEVICE' '1.0' 2).result|Should -Be ERROR
 }
 It 'returns UNKNOWN when ESAF-AV-002 was not collected' {
  (Invoke-Synthetic $state Enabled ERROR).result|Should -Be UNKNOWN
 }
 It 'returns ERROR for a schema other than ESAF evidence schema 1.0' {
  (Invoke-Synthetic $state Enabled Collected 'TEST-DEVICE' '2.0').result|Should -Be ERROR
 }
 It 'returns ERROR with sanitized text for a Graph exception' {
  $state.FailGraph=$true
  $r=Invoke-Synthetic $state
  $r.result|Should -Be ERROR
  ($r|ConvertTo-Json -Depth 8)|Should -Not -Match 'synthetic Graph failure'
 }
 It 'uses normalized evidence.observed and does not expose raw evidence' {
  $path=Join-Path $TestDrive 'normalized.json'
  $e=[pscustomobject]@{schemaVersion='1.0';runId='ESAF-20260101-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';device='TEST-DEVICE';controls=@([pscustomobject]@{id='ESAF-AV-002';evidence=[pscustomobject]@{evidenceProvider='RealTimeProtection';observed='Enabled';raw=[pscustomobject]@{RealTimeProtectionEnabled=$false;secret='do-not-copy'};collectedAt='2026-01-01T00:00:00Z';status='Collected'}})}
  $e|ConvertTo-Json -Depth 8|Set-Content $path
  $r=Invoke-ESAFPolicyReconciliation -PolicyId $script:policyId -DeviceName TEST-DEVICE -EvidencePath $path -GraphGet (New-GraphGet $state) -GrantedScopes $script:scopes
  $r.result|Should -Be MATCH
  ($r|ConvertTo-Json -Depth 8)|Should -Not -Match 'do-not-copy|RealTimeProtectionEnabled'
 }
 It 'writes optional JSON outside the repository' {
  $out=Join-Path $TestDrive 'result.json';$r=Invoke-Synthetic $state Enabled Collected TEST-DEVICE '1.0' 1 $out
  $r.result|Should -Be MATCH
  (Get-Content $out -Raw|ConvertFrom-Json).result|Should -Be MATCH
 }
 It 'refuses repository output unless a test fixture root is explicit' {
  $evidence=Join-Path $TestDrive 'evidence.json';Write-Evidence $evidence
  $out=Join-Path $script:root 'policy-assurance/refused-test-output.json'
  $r=Invoke-ESAFPolicyReconciliation -PolicyId $script:policyId -DeviceName TEST-DEVICE -EvidencePath $evidence -GraphGet (New-GraphGet $state) -GrantedScopes $script:scopes -OutputPath $out
  $r.result|Should -Be ERROR
  Test-Path $out|Should -BeFalse
 }
 It 'fails when the delegated session lacks a required read scope' {
  $path=Join-Path $TestDrive 'scopes.json';Write-Evidence $path
  $r=Invoke-ESAFPolicyReconciliation -PolicyId $script:policyId -DeviceName TEST-DEVICE -EvidencePath $path -GraphGet (New-GraphGet $state) -GrantedScopes @('Device.Read.All')
  $r.result|Should -Be ERROR;$r.reason|Should -Match 'missing required scopes'
 }
 It 'contains only GET in production Graph request code' {
  $files=Get-ChildItem (Join-Path $script:root 'policy-assurance') -File|Where-Object{$_.Extension -in @('.ps1','.psm1')}
  $content=($files|Get-Content -Raw)-join [Environment]::NewLine
  $content|Should -Not -Match '(?i)\b(POST|PATCH|PUT|DELETE)\b'
  $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($content,[ref]$tokens,[ref]$errors)
  @($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-MgGraphRequest'},$true)).Count|Should -Be 1
  $content|Should -Match 'Invoke-MgGraphRequest -Method GET'
 }
 It 'contains only synthetic GUIDs and no endpoint-style device names in production or tests' {
  $files=@(Get-ChildItem (Join-Path $script:root 'policy-assurance') -Recurse -File)+@(Get-Item $PSCommandPath)
  $content=($files|Get-Content -Raw)-join [Environment]::NewLine
  $content|Should -Not -Match 'DESKTOP-[A-Z0-9]+'
  $guids=@([regex]::Matches($content,'(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b')|ForEach-Object{$_.Value})
  @($guids|Where-Object{$_ -notmatch '^(11111111|22222222|33333333|44444444|55555555|66666666|77777777|88888888)-'}).Count|Should -Be 0
 }
 It 'keeps common credential patterns out of the POC source and test fixture' {
  $files=@(Get-ChildItem (Join-Path $script:root 'policy-assurance') -Recurse -File)+@(Get-Item $PSCommandPath)
  $content=($files|Get-Content -Raw)-join [Environment]::NewLine
  $content|Should -Not -Match '(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)'
 }
}
