#Requires -Version 5.1
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$PolicyId,
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$DeviceName,
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$EvidencePath,
 [string]$OutputPath
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ESAF.PolicyAssurance.psm1') -Force
Invoke-ESAFPolicyReconciliation -PolicyId $PolicyId -DeviceName $DeviceName -EvidencePath $EvidencePath -OutputPath $OutputPath
