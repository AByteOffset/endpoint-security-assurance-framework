#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$RequiredEngineVersion='0.1.0',
    [string]$RequiredBaselineVersion='1.0.0',
    [string]$InstallPath=(Join-Path $env:ProgramFiles 'ESAF'),
    [string]$ResultPath=(Join-Path $env:ProgramData 'ESAF/result.json')
)
$ErrorActionPreference='Stop'
try {
    if (-not [Environment]::Is64BitProcess) { exit 1 }
    $manifest = Import-PowerShellDataFile (Join-Path $InstallPath 'src/ESAF.psd1')
    $baseline = Get-Content (Join-Path $InstallPath 'baselines/Corporate-W11.json') -Raw | ConvertFrom-Json
    $r = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    $s = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\ESAF'
    if ($manifest.ModuleVersion -ne $RequiredEngineVersion -or $baseline.version -ne $RequiredBaselineVersion -or $r.engineVersion -ne $RequiredEngineVersion -or $s.EngineVersion -ne $RequiredEngineVersion -or $r.baseline.version -ne $RequiredBaselineVersion -or $s.BaselineVersion -ne $RequiredBaselineVersion -or $r.baseline.name -ne 'Corporate-W11') { exit 1 }
    if ($r.schemaVersion -ne '1.0' -or $r.runId -cnotmatch '^ESAF-\d{8}-[A-F0-9]{32}$' -or $s.LastRunId -ne $r.runId -or $s.Status -ne $r.status -or $r.status -notin @('PASS','FAIL','REVIEW','PENDING')) { exit 1 }
    $ids=@('ESAF-MDE-001','ESAF-MDE-002','ESAF-AV-001','ESAF-AV-002','ESAF-NET-001')
    if (@($r.controls).Count -ne $ids.Count) { exit 1 }
    foreach ($id in $ids) {
        $control=@($r.controls | Where-Object { $_.id -ceq $id })
        if ($control.Count -ne 1 -or $control[0].status -cnotin @('PASS','FAIL','REVIEW','PENDING','NOT_APPLICABLE','ERROR')) { exit 1 }
    }
    $date = [DateTimeOffset]::Parse($r.completedAt)
    if ($date -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) { exit 1 }
    Write-Output 'ESAF installed and certification versions current.'
    exit 0
} catch { exit 1 }
