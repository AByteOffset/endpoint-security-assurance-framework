#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ResultPath = (Join-Path $env:ProgramData 'ESAF/result.json'),
    [int]$MaximumAgeHours = 168
)
$ErrorActionPreference = 'Stop'
$output = [ordered]@{ ESAFStatus='PENDING'; MDEAssurance='PENDING'; DefenderAssurance='PENDING'; NetworkAssurance='PENDING'; BaselineVersion='Unknown'; EngineVersion='Unknown' }
try {
    $r = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    $registry = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\ESAF'
    $date = [DateTimeOffset]::Parse($r.completedAt)
    if ($r.schemaVersion -ne '1.0' -or $r.runId -cnotmatch '^ESAF-\d{8}-[A-F0-9]{32}$' -or $registry.LastRunId -cne $r.runId -or $registry.Status -cne $r.status -or $registry.EngineVersion -cne $r.engineVersion -or $registry.BaselineVersion -cne $r.baseline.version) { throw 'Inconsistent result.' }
    if ($MaximumAgeHours -lt 1 -or $date -gt [DateTimeOffset]::UtcNow.AddMinutes(5) -or $date -lt [DateTimeOffset]::UtcNow.AddHours(-$MaximumAgeHours)) { throw 'Stale result.' }
    if ($r.baseline.name -cne 'Corporate-W11' -or $r.baseline.version -cne '1.0.0' -or $r.engineVersion -cne '0.1.0') { throw 'Unexpected certification version.' }
    $expectedIds = @('ESAF-MDE-001','ESAF-MDE-002','ESAF-AV-001','ESAF-AV-002','ESAF-NET-001')
    if (@($r.controls).Count -ne 5) { throw 'Incomplete result.' }
    foreach ($id in $expectedIds) {
        $c = @($r.controls | Where-Object { $_.id -ceq $id })
        if ($c.Count -ne 1 -or $c[0].required -ne $true -or $c[0].status -cnotin @('PASS','FAIL','REVIEW','PENDING','NOT_APPLICABLE','ERROR')) { throw 'Invalid control result.' }
    }
    if ($r.status -cnotin @('PASS','REVIEW','FAIL','PENDING')) { throw 'Invalid verdict.' }
    $output.ESAFStatus = $r.status
    $output.BaselineVersion = $r.baseline.version
    $output.EngineVersion = $r.engineVersion
    foreach ($pair in @(@('MDEAssurance','ESAF-MDE-*'),@('DefenderAssurance','ESAF-AV-*'),@('NetworkAssurance','ESAF-NET-*'))) {
        $controls = @($r.controls | Where-Object { $_.id -like $pair[1] })
        $output[$pair[0]] = if (@($controls | Where-Object { $_.status -ne 'PASS' }).Count -eq 0) { 'PASS' } else { 'REVIEW' }
    }
    if ($output.ESAFStatus -eq 'PASS' -and @($r.controls | Where-Object { $_.status -ne 'PASS' }).Count) { $output.ESAFStatus='REVIEW' }
} catch {
    foreach ($key in @('ESAFStatus','MDEAssurance','DefenderAssurance','NetworkAssurance')) { $output[$key]='PENDING' }
}
$output | ConvertTo-Json -Compress
