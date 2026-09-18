function New-ESAFTestResult {
    param([ValidateSet('PASS','FAIL','REVIEW','PENDING')][string]$Status='PASS')
    . (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'src/Utility/ResultContract.ps1')
    $controls=@(Get-ESAFCertificationControls | ForEach-Object { [pscustomobject]@{id=$_.id;required=$_.required;severity=$_.severity;category=$_.category;expected=$_.expected;observed=$_.expected;evidenceProvider=$_.provider;status='PASS'} })
    $summary=[pscustomobject]@{passed=14;failed=0;review=0;pending=0;notApplicable=0;errors=0;criticalFailures=0;highFailures=0}
    if ($Status -ne 'PASS') {
        $controls[0].status=$Status; $summary.passed=13
        switch ($Status) {
            FAIL { $controls[0].observed='NotOnboarded';$summary.failed=1;$summary.criticalFailures=1 }
            REVIEW { $controls[0].observed='Unknown';$summary.review=1 }
            PENDING { $controls[0].observed='Unknown';$summary.pending=1 }
        }
    }
    [pscustomobject]@{schemaVersion='1.0';device='TEST-DEVICE';runId='ESAF-20260907-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';startedAt=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');completedAt=[DateTime]::UtcNow.ToString('o');provisioning=($Status -eq 'PENDING');status=$Status;engineVersion='0.3.0';baseline=[pscustomobject]@{name='Corporate-W11';version='1.1.0'};summary=$summary;controls=$controls}
}
function New-ESAFTestRegistry {
    param($Result)
    [pscustomobject]@{EngineVersion=$Result.engineVersion;BaselineName=$Result.baseline.name;BaselineVersion=$Result.baseline.version;LastRun=$Result.completedAt;LastRunId=$Result.runId;Status=$Result.status;CriticalFailures=$Result.summary.criticalFailures;HighFailures=$Result.summary.highFailures}
}
