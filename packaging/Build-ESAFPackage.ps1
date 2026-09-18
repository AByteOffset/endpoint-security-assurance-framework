#Requires -Version 5.1
[CmdletBinding()]
param([string]$OutputRoot, [string]$ContentPrepToolPath)
$ErrorActionPreference='Stop'
$source=Split-Path $PSScriptRoot -Parent
$moduleManifest=Test-ModuleManifest (Join-Path $source 'src/ESAF.psd1') -ErrorAction Stop
$engineVersion=$moduleManifest.Version.ToString()
if (-not $OutputRoot) { $OutputRoot=Join-Path $source 'artifacts' }
$output=[IO.Path]::GetFullPath($OutputRoot).TrimEnd('\')
$stage=Join-Path $output 'ESAF-Package'
. (Join-Path $PSScriptRoot 'PackageSupport.ps1')
Import-Module (Join-Path $source 'src/ESAF.psd1') -Force
$module=Get-Module ESAF
# Never clean the caller's output root; only our fixed marked staging child.
if ($stage -eq $source -or $source.StartsWith($stage+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe staging target.' }
& $module { param($path) Assert-ESAFStoragePath $path } $stage
if (Test-Path -LiteralPath $stage) {
    if (-not (Test-Path -LiteralPath (Join-Path $stage 'package-manifest.json'))) { throw 'Refusing to clean an unmarked staging directory.' }
    $old=Get-Content (Join-Path $stage 'package-manifest.json') -Raw | ConvertFrom-Json
    if ($old.entryPoint -cne 'Install-ESAF.ps1' -or $old.baseline.name -cne 'Corporate-W11') { throw 'Unrecognized staging directory.' }
    if ([IO.Path]::GetFullPath($stage) -ne (Join-Path $output 'ESAF-Package')) { throw 'Unsafe cleanup target.' }
    Remove-Item -LiteralPath $stage -Recurse -Force
}
$null=New-Item -ItemType Directory -Path $stage -Force
try {
$paths=@('src/ESAF.psd1','src/ESAF.psm1','baselines/Corporate-W11.json','tools/Invoke-ESAF.ps1','tools/Test-ESAFInstallation.ps1','tools/Test-ESAFSystemContext.ps1')
$paths+=@('src/Core/Invoke-ESAFValidation.ps1','src/Controls/Definitions.ps1','src/Evidence/Normalization.ps1','src/Evidence/Providers.ps1','src/Evidence/ExpandedProviders.ps1','src/Verdict/Verdict.ps1','src/Reporting/Reporting.ps1','src/Utility/Utility.ps1','src/Utility/Installation.ps1','src/Utility/ExecutionLock.ps1','src/Utility/ResultContract.ps1')
# Only the fourteen reviewed baseline definitions are staged.
$paths+=@('controls/mde/ESAF-MDE-001.json','controls/mde/ESAF-MDE-002.json','controls/defender/ESAF-AV-001.json','controls/defender/ESAF-AV-002.json','controls/network/ESAF-NET-001.json')
$paths+=@('controls/defender/ESAF-AV-003.json','controls/defender/ESAF-AV-004.json','controls/defender/ESAF-AV-005.json','controls/defender/ESAF-AV-006.json','controls/network/ESAF-NET-002.json','controls/disk/ESAF-DISK-001.json','controls/hardware/ESAF-HW-001.json','controls/hardware/ESAF-HW-002.json','controls/asr/ESAF-ASR-001.json')
foreach ($relative in $paths) {
    $destination=Join-Path $stage ('payload/'+$relative)
    $null=New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force
    Copy-Item -LiteralPath (Join-Path $source $relative) -Destination $destination
}
foreach ($name in @('Install-ESAF.ps1','Detect-ESAF.ps1','Uninstall-ESAF.ps1','Uninstall-ESAF.cmd')) { Copy-Item -LiteralPath (Join-Path $source ('intune/package/'+$name)) -Destination $stage }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'PackageSupport.ps1') -Destination $stage
Copy-Item -LiteralPath (Join-Path $source 'src/Utility/ExecutionLock.ps1') -Destination $stage
foreach ($file in Get-ChildItem $stage -Recurse -File) {
    if ($file.Extension -in @('.ps1','.psm1','.psd1')) {
        $tokens=$null; $errors=$null
        $null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
        if ($errors.Count) { throw 'Staged PowerShell syntax error.' }
    }
    if ($file.Extension -eq '.json') { $null=Get-Content $file.FullName -Raw | ConvertFrom-Json }
}
& $module { param($stage) $b=Get-ESAFBaseline (Join-Path $stage 'payload/baselines/Corporate-W11.json'); $null=@(Get-ESAFControls $b (Join-Path $stage 'payload/controls')) } $stage
$files=@(Get-ChildItem $stage -Recurse -File | Sort-Object FullName | ForEach-Object { [ordered]@{path=$_.FullName.Substring($stage.Length+1).Replace('\','/');sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash} })
$manifest=[ordered]@{schemaVersion='1.0';engineVersion=$engineVersion;baseline=@{name='Corporate-W11';version='1.1.0'};buildTime=[DateTime]::UtcNow.ToString('o');entryPoint='Install-ESAF.ps1';detectionScript='Detect-ESAF.ps1';files=$files}
$manifest | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $stage 'package-manifest.json') -Encoding UTF8
$null=Assert-ESAFPackage $stage
} catch {
    # An incomplete build must not leave an unmarked directory blocking a safe retry.
    if ([IO.Path]::GetFullPath($stage) -ne (Join-Path $output 'ESAF-Package')) { throw 'Unsafe failed-build cleanup target.' }
    & $module { param($path) Assert-ESAFStoragePath $path } $stage
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    throw
}
$intunewin=$null
if ($ContentPrepToolPath) {
    $tool=(Get-Item -LiteralPath $ContentPrepToolPath -ErrorAction Stop).FullName
    if ($tool.StartsWith($stage+'\',[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetExtension($tool) -ne '.exe') { throw 'Provide an approved external Content Prep executable.' }
    $binaryOut=Join-Path $output 'intunewin'
    & $tool -c $stage -s 'Install-ESAF.ps1' -o $binaryOut -q
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path (Join-Path $binaryOut 'Install-ESAF.intunewin'))) { throw 'Content Prep Tool did not produce a successful package.' }
    $intunewin=Join-Path $binaryOut 'Install-ESAF.intunewin'
}
[pscustomobject]@{stagingPath=$stage;manifestPath=(Join-Path $stage 'package-manifest.json');fileCount=$files.Count;intunewinPath=$intunewin}
