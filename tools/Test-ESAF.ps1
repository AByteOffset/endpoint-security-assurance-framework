#Requires -Version 5.1
$ErrorActionPreference='Stop'
$root = Split-Path $PSScriptRoot -Parent
$files = Get-ChildItem $root -Recurse -File | Where-Object { $_.FullName -notmatch '[\\/](\.git|\.tools|artifacts)[\\/]' }
foreach ($file in $files | Where-Object { $_.Extension -in @('.ps1','.psm1','.psd1') }) {
    $tokens=$null; $errors=$null
    $null = [Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw ($errors | Out-String) }
}
foreach ($file in $files | Where-Object Extension -eq '.json') { $null = Get-Content $file.FullName -Raw | ConvertFrom-Json }
Import-Module (Join-Path $root 'src/ESAF.psd1') -Force
& (Get-Module ESAF) { param($root) $b=Get-ESAFBaseline (Join-Path $root 'baselines/Corporate-W11.json'); $null=@(Get-ESAFControls $b (Join-Path $root 'controls')) } $root
Import-Module Pester -MinimumVersion 5.6.1 -ErrorAction Stop
$configuration = New-PesterConfiguration
$configuration.Run.Path = Join-Path $root 'tests/Pester'
$configuration.Run.PassThru = $true
$configuration.Output.Verbosity = 'Detailed'
$result = Invoke-Pester -Configuration $configuration
if ($result.FailedCount -gt 0 -or $result.PassedCount -eq 0) { throw 'Pester tests failed or no tests executed.' }
