function New-ESAFTestResult {
    param([ValidateSet('PASS','FAIL','REVIEW','PENDING')][string]$Status='PASS')
    $ids=@('ESAF-MDE-001','ESAF-MDE-002','ESAF-AV-001','ESAF-AV-002','ESAF-NET-001')
    $values=@('Onboarded','Running','Active','Enabled','Block')
    $categories=@('mde','mde','defender','defender','network')
    $controls=@(for ($i=0;$i -lt 5;$i++) { [pscustomobject]@{id=$ids[$i];required=$true;severity=$(if($i -eq 4){'high'}else{'critical'});category=$categories[$i];expected=$values[$i];observed=$values[$i];status='PASS'} })
    $summary=[pscustomobject]@{passed=5;failed=0;review=0;pending=0;notApplicable=0;errors=0;criticalFailures=0;highFailures=0}
    if ($Status -ne 'PASS') {
        $controls[0].status=$Status; $summary.passed=4
        switch ($Status) {
            FAIL { $controls[0].observed='NotOnboarded';$summary.failed=1;$summary.criticalFailures=1 }
            REVIEW { $controls[0].observed='Unknown';$summary.review=1 }
            PENDING { $controls[0].observed='Unknown';$summary.pending=1 }
        }
    }
    [pscustomobject]@{schemaVersion='1.0';device='TEST-DEVICE';runId='ESAF-20260907-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';startedAt=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');completedAt=[DateTime]::UtcNow.ToString('o');provisioning=($Status -eq 'PENDING');status=$Status;engineVersion='0.1.1';baseline=[pscustomobject]@{name='Corporate-W11';version='1.0.0'};summary=$summary;controls=$controls}
}
function New-ESAFTestRegistry {
    param($Result)
    [pscustomobject]@{EngineVersion=$Result.engineVersion;BaselineName=$Result.baseline.name;BaselineVersion=$Result.baseline.version;LastRun=$Result.completedAt;LastRunId=$Result.runId;Status=$Result.status;CriticalFailures=$Result.summary.criticalFailures;HighFailures=$Result.summary.highFailures}
}
