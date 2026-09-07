function Invoke-ESAFValidation {
    [CmdletBinding()]
    param(
        [string]$BaselinePath = (Join-Path $script:RepositoryRoot 'baselines/Corporate-W11.json'),
        [string]$ControlsPath = (Join-Path $script:RepositoryRoot 'controls'),
        [string]$OutputPath = (Join-Path $env:ProgramData 'ESAF'),
        [switch]$Provisioning
    )
    $ErrorActionPreference = 'Stop'
    if (-not [Environment]::Is64BitProcess) { throw 'Run ESAF in 64-bit Windows PowerShell.' }
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
            if ($applicable) { $item = Get-ESAFEvidence $control.evidenceProvider }
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
        $result
    } finally { if ($null -ne $lock) { $lock.Dispose() } }
}
