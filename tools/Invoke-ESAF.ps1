#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$BaselinePath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'baselines/Corporate-W11.json'),
    [string]$OutputPath = (Join-Path $env:ProgramData 'ESAF'),
    [switch]$Provisioning
)
$ErrorActionPreference = 'Stop'
try {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'src/ESAF.psd1') -Force
    $r = Invoke-ESAFValidation -BaselinePath $BaselinePath -OutputPath $OutputPath -Provisioning:$Provisioning
    Write-Host "Endpoint Security Assurance Framework`nDevice: $($r.device)`nProfile: $($r.baseline.name)`nBaseline: $($r.baseline.version)`nRun: $($r.runId)"
    foreach ($c in $r.controls) { Write-Host ('{0,-16} {1}' -f $c.id,$c.status) }
    Write-Host "Passed: $($r.summary.passed) Failed: $($r.summary.failed) Errors: $($r.summary.errors)`nResult: $($r.status)`nDetailed evidence: $(Join-Path $OutputPath 'result.json')"
    exit 0
} catch { Write-Error 'ESAF execution failed. Check deployment, input files, permissions, and storage.' -ErrorAction Continue; exit 1 }
