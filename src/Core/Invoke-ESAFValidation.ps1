function Invoke-ESAFValidation {
    [CmdletBinding()]
    param(
        [string]$BaselinePath = (Join-Path $script:RepositoryRoot 'baselines/Corporate-W11.json'),
        [string]$ControlsPath = (Join-Path $script:RepositoryRoot 'controls'),
        [string]$OutputPath = (Join-Path $env:ProgramData 'ESAF'),
        [switch]$Provisioning,
        [ValidateRange(0,600)][int]$LockTimeoutSeconds=30
    )
    $ErrorActionPreference = 'Stop'
    if (-not [Environment]::Is64BitProcess) { throw 'Run ESAF in 64-bit Windows PowerShell.' }
    $executionLock=Enter-ESAFExecutionLock -TimeoutSeconds $LockTimeoutSeconds
    try {
    $started = [DateTime]::UtcNow.ToString('o')
    $runId = New-ESAFRunId
    $baseline = Get-ESAFBaseline $BaselinePath
    $controls = @(Get-ESAFControls $baseline $ControlsPath)
    $platform = Get-ESAFPlatform
    Assert-ESAFStoragePath $OutputPath
    $null = New-Item -ItemType Directory -Path $OutputPath -Force
    Set-ESAFStoragePermissions $OutputPath
    $lock = $null
    try {
        # Exclusive file handle serializes runs, including registry publication.
        $lock = [IO.File]::Open((Join-Path $OutputPath 'run.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $evidence = @(); $results = @()
        foreach ($control in $controls) {
            $applicable = Test-ESAFApplicability $control $baseline $platform
            if ($applicable) { $item = Get-ESAFEvidence $control.evidenceProvider -Policy $baseline }
            else { $item = [pscustomobject]@{ evidenceProvider=$control.evidenceProvider; observed='Unknown'; status='NotCollected'; errorCategory=$null; errorMessage=$null } }
            $evidence += [pscustomobject]@{ id=$control.id; evidence=$item }
            $results += Get-ESAFControlResult $control $item $applicable ([bool]$Provisioning)
        }
        $verdict = Get-ESAFVerdict $results
        $result = [pscustomobject]@{
            schemaVersion='1.0'; runId=$runId; device=$env:COMPUTERNAME; engineVersion=$script:EngineVersion
            baseline=[pscustomobject]@{ name=$baseline.name; version=$baseline.version }
            startedAt=$started; completedAt=[DateTime]::UtcNow.ToString('o'); provisioning=[bool]$Provisioning
            status=$verdict.status; summary=$verdict.summary; controls=$results
        }
        $bundle = [pscustomobject]@{ schemaVersion='1.0'; runId=$runId; device=$env:COMPUTERNAME; controls=$evidence }
        Write-ESAFReport $result $bundle $OutputPath
        $supportStatus='Failed';$transportStatus='NotAttempted'
        try {
            $support=Export-ESAFSupportEvidence -EvidencePath (Join-Path $OutputPath ('history/'+$runId+'/evidence.json')) -SupportPath (Join-Path $OutputPath 'support/latest-assurance.json') -IntuneLogDirectory (Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs')
            $supportStatus='Complete';$transportStatus=$support.intuneTransportStatus
        } catch { Write-Warning 'ESAF support evidence export failed; canonical assessment remains valid.' }
        try {
            Add-Content -LiteralPath (Join-Path $OutputPath 'ESAF.log') -Value ('{0} Run={1} SupportExport={2} IntuneTransport={3}' -f [DateTime]::UtcNow.ToString('o'),$runId,$supportStatus,$transportStatus) -Encoding UTF8 -ErrorAction Stop
        } catch { Write-Warning 'ESAF support export status could not be recorded.' }
        $result
    } finally { if ($null -ne $lock) { $lock.Dispose() } }
    } finally { Exit-ESAFExecutionLock $executionLock }
}
