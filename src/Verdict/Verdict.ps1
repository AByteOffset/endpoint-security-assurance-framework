function Get-ESAFControlResult {
    param($Control, $Evidence, [bool]$Applicable, [bool]$Provisioning)
    $reason = 'Observed state matches desired state.'
    if (-not $Applicable) { $status='NOT_APPLICABLE'; $reason='Profile or Windows platform constraints do not match.' }
    elseif ($Evidence.status -eq 'ERROR') { $status='ERROR'; $reason='Evidence provider failed.' }
    elseif ($Evidence.observed -eq 'Unknown') {
        $status = if ($Provisioning) { 'PENDING' } else { 'REVIEW' }
        $reason='Effective state could not be established.'
    }
    elseif (-not $Control.required -and $Control.evidenceProvider -eq 'DefenderExclusions' -and $Evidence.observed -eq 'Present') { $status='REVIEW'; $reason='Visible exclusions require administrator assessment; no raw values are retained.' }
    elseif ($Evidence.observed -ceq $Control.expected.state) { $status='PASS' }
    else { $status='FAIL'; $reason='Observed state does not match desired state.' }
    if ($Control.id -in @('ESAF-AV-003','ESAF-AV-004','ESAF-AV-005','ESAF-NET-002','ESAF-DISK-001','ESAF-HW-001','ESAF-HW-002') -and $status -in @('PASS','FAIL')) { $reason='Local '+$Control.evidenceProvider+' reports '+$Evidence.observed+'; required state is '+$Control.expected.state+'. See protected evidence for safe details.' }
    if ($status -eq 'PASS' -and -not $Control.required) { $reason='Local assessment collected; no universal policy adequacy is asserted.' }
    [pscustomobject]@{ id=$Control.id; category=$Control.category; required=$Control.required; severity=$Control.severity; expected=$Control.expected.state; observed=$Evidence.observed; status=$status; reason=$reason; evidenceProvider=$Control.evidenceProvider; errorCategory=$Evidence.errorCategory; errorMessage=$Evidence.errorMessage; remediationGuidance=$Control.remediationGuidance; functionalStatus='NOT_IMPLEMENTED' }
}

function Get-ESAFVerdict {
    param([object[]]$Results)
    $summary = [ordered]@{ passed=0; failed=0; review=0; pending=0; notApplicable=0; errors=0; criticalFailures=0; highFailures=0 }
    $map = @{PASS='passed'; FAIL='failed'; REVIEW='review'; PENDING='pending'; NOT_APPLICABLE='notApplicable'; ERROR='errors'}
    foreach ($r in $Results) {
        $summary[$map[$r.status]]++
        if ($r.required -and $r.status -in @('FAIL','ERROR')) {
            if ($r.severity -eq 'critical') { $summary.criticalFailures++ }
            if ($r.severity -eq 'high') { $summary.highFailures++ }
        }
    }
    if ($summary.criticalFailures + $summary.highFailures -gt 0) { $status='FAIL' }
    elseif (@($Results | Where-Object { $_.required -and $_.status -eq 'PENDING' }).Count) { $status='PENDING' }
    elseif ($Results.Count -eq 0 -or @($Results | Where-Object { $_.status -in @('FAIL','ERROR','REVIEW','PENDING') -or ($_.required -and $_.status -eq 'NOT_APPLICABLE') }).Count) { $status='REVIEW' }
    else { $status='PASS' }
    [pscustomobject]@{ status=$status; summary=[pscustomobject]$summary }
}
