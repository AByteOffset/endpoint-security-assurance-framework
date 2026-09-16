#Requires -Version 5.1
Set-StrictMode -Version 2.0
$script:DefinitionId='device_vendor_msft_policy_config_defender_allowrealtimemonitoring'
$script:RequiredScopes=@('DeviceManagementConfiguration.Read.All','DeviceManagementManagedDevices.Read.All','Device.Read.All')

function Test-ESAFPathWithin {
 param([string]$Path,[string]$Parent)
 $p=[IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
 $r=[IO.Path]::GetFullPath($Parent).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
 $p.Equals($r,[StringComparison]::OrdinalIgnoreCase) -or $p.StartsWith($r+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)
}
function Get-ESAFObjectProperty {
 param($InputObject,[string]$Name)
 if($null -eq $InputObject){return $null}
 $property=$InputObject.PSObject.Properties[$Name]
 if($null -eq $property){return $null}
 $property.Value
}
function Get-ESAFGraphCollection {
 param([string]$Uri,[scriptblock]$GraphGet)
 $items=@();$next=$Uri;$pages=0
 while($next){
  if($next -notmatch '^https://graph\.microsoft\.com/(v1\.0|beta)/'){throw 'Unsupported continuation URI.'}
  $pages++;if($pages -gt 100){throw 'Pagination limit exceeded.'}
  $response=& $GraphGet $next
  if($null -eq $response){throw 'Empty response.'}
  $vp=$response.PSObject.Properties['value'];if($null -eq $vp){throw 'Invalid collection response.'}
  $items+=@($vp.Value)
  $np=$response.PSObject.Properties['@odata.nextLink'];$next=if($null -ne $np){[string]$np.Value}else{$null}
 }
 @($items)
}
function New-ESAFReconciliationResult {
 param([string]$DeviceName,[string]$PolicyId)
 [pscustomobject][ordered]@{
  reconciliationVersion='0.1';evaluatedAtUtc=[DateTime]::UtcNow.ToString('o')
  device=[pscustomobject][ordered]@{deviceName=$DeviceName;intuneManagedDeviceId=$null;entraDeviceId=$null}
  policy=[pscustomobject][ordered]@{policyId=$PolicyId;policyName=$null;templateDisplayName=$null;technologies=$null}
  assignment=[pscustomobject][ordered]@{applies=$null;matchedGroupIds=@();assignmentType=$null;filtersPresent=$false}
  setting=[pscustomobject][ordered]@{definitionId=$script:DefinitionId;displayName=$null;selectedItemId=$null;selectedDisplayName=$null;normalizedIntent=$null}
  probe=[pscustomobject][ordered]@{controlId='ESAF-AV-002';evidenceProvider=$null;observed=$null;collectedAt=$null;runId=$null}
  result='ERROR';reason='Reconciliation did not complete.'
 }
}
function Set-ESAFOutcome {
 param($Result,[ValidateSet('MATCH','MISMATCH','UNKNOWN','ERROR')][string]$Outcome,[string]$Reason)
 $Result.result=$Outcome;$Result.reason=$Reason;$Result
}
function Write-ESAFReconciliationOutput {
 param($Result,[string]$OutputPath,[string]$TestFixtureRoot)
 if([string]::IsNullOrWhiteSpace($OutputPath)){return $Result}
 $full=[IO.Path]::GetFullPath($OutputPath);$repo=Split-Path $PSScriptRoot -Parent
 if(Test-ESAFPathWithin $full $repo){
  $allowed=-not[string]::IsNullOrWhiteSpace($TestFixtureRoot) -and (Test-ESAFPathWithin $full $TestFixtureRoot)
  if(-not $allowed){return Set-ESAFOutcome $Result ERROR 'OutputPath inside the Git repository is refused.'}
 }
 $parent=Split-Path $full -Parent
 if(-not(Test-Path -LiteralPath $parent -PathType Container)){return Set-ESAFOutcome $Result ERROR 'OutputPath parent directory does not exist.'}
 try{$json=$Result|ConvertTo-Json -Depth 8;[IO.File]::WriteAllText($full,$json,(New-Object Text.UTF8Encoding($false)))}
 catch{return Set-ESAFOutcome $Result ERROR 'Reconciliation output could not be written.'}
 $Result
}
function Complete-ESAFReconciliation {
 param($Result,[string]$Outcome,[string]$Reason,[string]$OutputPath,[string]$TestFixtureRoot)
 Write-ESAFReconciliationOutput (Set-ESAFOutcome $Result $Outcome $Reason) $OutputPath $TestFixtureRoot
}
function Invoke-ESAFPolicyReconciliation {
 [CmdletBinding()]
 param(
  [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$PolicyId,
  [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$DeviceName,
  [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$EvidencePath,
  [string]$OutputPath,[scriptblock]$GraphGet,[string[]]$GrantedScopes,[string]$TestFixtureRoot
 )
 $r=New-ESAFReconciliationResult $DeviceName $PolicyId
 try{
  $guid=[Guid]::Empty
  if(-not[Guid]::TryParse($PolicyId,[ref]$guid)){return Complete-ESAFReconciliation $r ERROR 'PolicyId must be a GUID.' $OutputPath $TestFixtureRoot}
  if(-not(Test-Path -LiteralPath $EvidencePath -PathType Leaf)){return Complete-ESAFReconciliation $r ERROR 'EvidencePath does not identify an existing file.' $OutputPath $TestFixtureRoot}
  try{$e=Get-Content -LiteralPath $EvidencePath -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop}
  catch{return Complete-ESAFReconciliation $r ERROR 'Evidence file is not valid JSON.' $OutputPath $TestFixtureRoot}
  if([string]$e.schemaVersion -ne '1.0'){return Complete-ESAFReconciliation $r ERROR 'Evidence schemaVersion must be 1.0.' $OutputPath $TestFixtureRoot}
  if([string]::IsNullOrWhiteSpace([string]$e.runId) -or [string]::IsNullOrWhiteSpace([string]$e.device) -or $null -eq $e.PSObject.Properties['controls']){return Complete-ESAFReconciliation $r ERROR 'Evidence is missing required top-level fields.' $OutputPath $TestFixtureRoot}
  if(-not([string]$e.device).Equals($DeviceName,[StringComparison]::OrdinalIgnoreCase)){return Complete-ESAFReconciliation $r ERROR 'Evidence device does not match DeviceName.' $OutputPath $TestFixtureRoot}
  $r.probe.runId=[string]$e.runId;$controls=@($e.controls|Where-Object{[string]$_.id -eq 'ESAF-AV-002'})
  if($controls.Count -gt 1){return Complete-ESAFReconciliation $r ERROR 'Evidence contains duplicate ESAF-AV-002 controls.' $OutputPath $TestFixtureRoot}
  if($controls.Count -eq 0){return Complete-ESAFReconciliation $r UNKNOWN 'Evidence does not contain ESAF-AV-002.' $OutputPath $TestFixtureRoot}
  $pe=$controls[0].evidence
  if($null -eq $pe){return Complete-ESAFReconciliation $r UNKNOWN 'ESAF-AV-002 evidence is missing.' $OutputPath $TestFixtureRoot}
  $r.probe.evidenceProvider=[string]$pe.evidenceProvider;$r.probe.observed=[string]$pe.observed;$r.probe.collectedAt=[string]$pe.collectedAt
  if([string]$pe.status -ne 'Collected'){return Complete-ESAFReconciliation $r UNKNOWN 'ESAF-AV-002 evidence status is not Collected.' $OutputPath $TestFixtureRoot}
  if([string]$pe.evidenceProvider -ne 'RealTimeProtection'){return Complete-ESAFReconciliation $r UNKNOWN 'ESAF-AV-002 evidence provider is unsupported.' $OutputPath $TestFixtureRoot}
  if([string]$pe.observed -notin @('Enabled','Disabled')){return Complete-ESAFReconciliation $r UNKNOWN 'ESAF-AV-002 observed state is unsupported.' $OutputPath $TestFixtureRoot}

  if($null -eq $GraphGet){
   $gc=Get-Command Get-MgContext -ErrorAction SilentlyContinue;$rc=Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue
   if($null -eq $gc -or $null -eq $rc){return Complete-ESAFReconciliation $r ERROR 'Microsoft Graph PowerShell is unavailable.' $OutputPath $TestFixtureRoot}
   $ctx=Get-MgContext
   if($null -eq $ctx -or [string]$ctx.AuthType -ne 'Delegated'){return Complete-ESAFReconciliation $r ERROR 'An authenticated delegated Microsoft Graph session is required.' $OutputPath $TestFixtureRoot}
   $GrantedScopes=@($ctx.Scopes);$GraphGet={param($Uri) Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject}
  }elseif($null -eq $GrantedScopes){return Complete-ESAFReconciliation $r ERROR 'Injected Graph GET requires explicit GrantedScopes.' $OutputPath $TestFixtureRoot}
  $missing=@($script:RequiredScopes|Where-Object{$_ -notin $GrantedScopes})
  if($missing.Count){return Complete-ESAFReconciliation $r ERROR ('Delegated Graph session is missing required scopes: '+($missing -join ', ')+'.') $OutputPath $TestFixtureRoot}

  $escaped=$DeviceName.Replace("'","''");$filter=[Uri]::EscapeDataString("deviceName eq '$escaped'")
  $uri='https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$filter='+$filter+'&$select=id,deviceName,azureADDeviceId'
  $md=@(Get-ESAFGraphCollection $uri $GraphGet)
  if($md.Count -eq 0){return Complete-ESAFReconciliation $r ERROR 'No Intune managed device matched DeviceName.' $OutputPath $TestFixtureRoot}
  if($md.Count -gt 1){return Complete-ESAFReconciliation $r ERROR 'Multiple Intune managed devices matched DeviceName; identity is ambiguous.' $OutputPath $TestFixtureRoot}
  if([string]::IsNullOrWhiteSpace([string]$md[0].id) -or [string]::IsNullOrWhiteSpace([string]$md[0].azureADDeviceId)){return Complete-ESAFReconciliation $r ERROR 'Managed device identity is incomplete.' $OutputPath $TestFixtureRoot}
  $r.device.intuneManagedDeviceId=[string]$md[0].id;$r.device.entraDeviceId=[string]$md[0].azureADDeviceId
  $filter=[Uri]::EscapeDataString("deviceId eq '$($md[0].azureADDeviceId)'")
  $uri='https://graph.microsoft.com/v1.0/devices?$filter='+$filter+'&$select=id,deviceId'
  $ed=@(Get-ESAFGraphCollection $uri $GraphGet)
  if($ed.Count -ne 1){return Complete-ESAFReconciliation $r ERROR 'Entra device identity could not be resolved uniquely.' $OutputPath $TestFixtureRoot}

  $policyUri="https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$PolicyId";$p=& $GraphGet $policyUri
  if($null -eq $p){throw 'Empty policy response.'}
  $r.policy.policyName=[string]$p.name;$r.policy.technologies=[string]$p.technologies
  if($null -ne $p.templateReference){$r.policy.templateDisplayName=[string]$p.templateReference.templateDisplayName}

  $assign=@(Get-ESAFGraphCollection "$policyUri/assignments" $GraphGet);$groupIds=@()
  foreach($a in $assign){
   $t=Get-ESAFObjectProperty $a 'target';$type=([string](Get-ESAFObjectProperty $t '@odata.type')).TrimStart('#')
   $ft=[string](Get-ESAFObjectProperty $t 'deviceAndAppManagementAssignmentFilterType')
   $fid=[string](Get-ESAFObjectProperty $t 'deviceAndAppManagementAssignmentFilterId')
   if($ft -ne 'none' -or -not[string]::IsNullOrWhiteSpace($fid)){$r.assignment.filtersPresent=$true;return Complete-ESAFReconciliation $r UNKNOWN 'Policy assignment filters are unsupported by this POC.' $OutputPath $TestFixtureRoot}
   if($type -ne 'microsoft.graph.groupAssignmentTarget'){return Complete-ESAFReconciliation $r UNKNOWN 'Policy contains an unsupported assignment target.' $OutputPath $TestFixtureRoot}
   $groupId=[string](Get-ESAFObjectProperty $t 'groupId')
   if([string]::IsNullOrWhiteSpace($groupId)){return Complete-ESAFReconciliation $r UNKNOWN 'Policy contains an incomplete group assignment.' $OutputPath $TestFixtureRoot}
   $groupIds+=$groupId
  }
  $r.assignment.assignmentType='groupAssignmentTarget'
  $uri='https://graph.microsoft.com/v1.0/devices/'+[string]$ed[0].id+'/transitiveMemberOf/microsoft.graph.group?$select=id'
  $members=@(Get-ESAFGraphCollection $uri $GraphGet);$memberIds=@($members|ForEach-Object{[string]$_.id})
  $matched=@($groupIds|Where-Object{$_ -in $memberIds}|Select-Object -Unique);$r.assignment.matchedGroupIds=$matched
  if($matched.Count -eq 0){$r.assignment.applies=$false;return Complete-ESAFReconciliation $r UNKNOWN 'Supported direct group assignments do not apply to the resolved device.' $OutputPath $TestFixtureRoot}
  $r.assignment.applies=$true

  $settingsUri="$policyUri/settings";$settings=@(Get-ESAFGraphCollection $settingsUri $GraphGet)
  $mapped=@($settings|Where-Object{$instance=Get-ESAFObjectProperty $_ 'settingInstance';$null -ne $instance -and [string](Get-ESAFObjectProperty $instance 'settingDefinitionId') -eq $script:DefinitionId})
  if($mapped.Count -ne 1){return Complete-ESAFReconciliation $r UNKNOWN 'Policy intent for AllowRealtimeMonitoring is missing or ambiguous.' $OutputPath $TestFixtureRoot}
  $s=$mapped[0];$instance=Get-ESAFObjectProperty $s 'settingInstance'
  $settingDefinitionId=[string](Get-ESAFObjectProperty $instance 'settingDefinitionId')
  if([string]::IsNullOrWhiteSpace($settingDefinitionId)){return Complete-ESAFReconciliation $r UNKNOWN 'Microsoft setting definition identifier is missing.' $OutputPath $TestFixtureRoot}
  $choiceValue=Get-ESAFObjectProperty $instance 'choiceSettingValue'
  $choice=[string](Get-ESAFObjectProperty $choiceValue 'value');$r.setting.selectedItemId=$choice
  if([string]::IsNullOrWhiteSpace($choice)){return Complete-ESAFReconciliation $r UNKNOWN 'Configured Microsoft choice is missing.' $OutputPath $TestFixtureRoot}
  $encodedDefinitionId=[Uri]::EscapeDataString($settingDefinitionId)
  $definitionUri='https://graph.microsoft.com/beta/deviceManagement/configurationSettings/'+$encodedDefinitionId
  $d=& $GraphGet $definitionUri
  if($null -eq $d){return Complete-ESAFReconciliation $r UNKNOWN 'Microsoft setting definition could not be retrieved.' $OutputPath $TestFixtureRoot}
  if([string](Get-ESAFObjectProperty $d 'id') -ne $script:DefinitionId){return Complete-ESAFReconciliation $r UNKNOWN 'Microsoft setting definition identity is unexpected.' $OutputPath $TestFixtureRoot}
  $r.setting.displayName=[string](Get-ESAFObjectProperty $d 'displayName')
  $definitionOptions=Get-ESAFObjectProperty $d 'options'
  if($null -eq $definitionOptions){return Complete-ESAFReconciliation $r UNKNOWN 'Microsoft setting definition has no choice options.' $OutputPath $TestFixtureRoot}
  $options=@($definitionOptions|Where-Object{[string](Get-ESAFObjectProperty $_ 'itemId') -eq $choice})
  if($options.Count -ne 1){return Complete-ESAFReconciliation $r UNKNOWN 'Configured choice is not present in the retrieved Microsoft setting definition.' $OutputPath $TestFixtureRoot}
  $r.setting.selectedDisplayName=[string]$options[0].displayName
  $optionValue=Get-ESAFObjectProperty $options[0] 'optionValue'
  $normalizedOptionValue=[string](Get-ESAFObjectProperty $optionValue 'value')
  if($normalizedOptionValue -eq '1'){$r.setting.normalizedIntent='Enabled'}
  elseif($normalizedOptionValue -eq '0'){$r.setting.normalizedIntent='Disabled'}
  else{return Complete-ESAFReconciliation $r UNKNOWN 'Configured Microsoft choice has no approved ESAF normalization.' $OutputPath $TestFixtureRoot}
  if($r.setting.normalizedIntent -eq $r.probe.observed){$r=Set-ESAFOutcome $r MATCH 'Assigned Microsoft intent matches the normalized ESAF-AV-002 observation.'}
  else{$r=Set-ESAFOutcome $r MISMATCH 'Assigned Microsoft intent differs from the normalized ESAF-AV-002 observation.'}
 }catch{$r=Set-ESAFOutcome $r ERROR 'Microsoft Graph read or reconciliation processing failed.'}
 Write-ESAFReconciliationOutput $r $OutputPath $TestFixtureRoot
}
Export-ModuleMember -Function Invoke-ESAFPolicyReconciliation
