function Assert-ESAFPackage {
    param([string]$PackageRoot)
    $root=[IO.Path]::GetFullPath($PackageRoot).TrimEnd('\')
    $all=@(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop)
    foreach ($item in @((Get-Item -LiteralPath $root -Force))+$all) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Package reparse points are forbidden.' }
    }
    $manifest=Get-Content -LiteralPath (Join-Path $root 'package-manifest.json') -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($manifest.schemaVersion -cne '1.0' -or $manifest.engineVersion -cne '0.3.0' -or $manifest.baseline.name -cne 'Corporate-W11' -or $manifest.baseline.version -cne '1.1.0' -or $manifest.entryPoint -cne 'Install-ESAF.ps1' -or $manifest.detectionScript -cne 'Detect-ESAF.ps1') { throw 'Unsupported package metadata.' }
    $null=[DateTimeOffset]::Parse($manifest.buildTime)
    $required=@('Install-ESAF.ps1','Detect-ESAF.ps1','Uninstall-ESAF.ps1','Uninstall-ESAF.cmd','PackageSupport.ps1','ExecutionLock.ps1','payload/src/ESAF.psd1','payload/src/ESAF.psm1','payload/baselines/Corporate-W11.json','payload/tools/Invoke-ESAF.ps1','payload/src/Utility/ResultContract.ps1')
    $seen=@{}
    if ($manifest.files -isnot [array] -or $manifest.files.Count -eq 0) { throw 'Empty package manifest.' }
    foreach ($entry in $manifest.files) {
        if ($entry.path -isnot [string] -or $entry.path -cnotmatch '^(payload/(src|controls|baselines|tools)/[A-Za-z0-9_./-]+\.(ps1|psm1|psd1|json)|Install-ESAF\.ps1|Detect-ESAF\.ps1|Uninstall-ESAF\.(ps1|cmd)|PackageSupport\.ps1|ExecutionLock\.ps1)$' -or $entry.path.Contains('..') -or $entry.sha256 -cnotmatch '^[A-F0-9]{64}$' -or $seen.ContainsKey($entry.path)) { throw 'Invalid package file entry.' }
        $path=Join-Path $root $entry.path
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $entry.sha256) { throw 'Package hash mismatch or missing file.' }
        $seen[$entry.path]=$true
    }
    foreach ($path in $required) { if (-not $seen.ContainsKey($path)) { throw 'Required package file missing.' } }
    foreach ($file in $all | Where-Object { -not $_.PSIsContainer }) {
        $relative=$file.FullName.Substring($root.Length+1).Replace('\','/')
        if ($relative -ne 'package-manifest.json' -and -not $seen.ContainsKey($relative)) { throw 'Unlisted package file.' }
    }
    $module=Import-PowerShellDataFile (Join-Path $root 'payload/src/ESAF.psd1')
    $baseline=Get-Content (Join-Path $root 'payload/baselines/Corporate-W11.json') -Raw | ConvertFrom-Json
    if ($module.ModuleVersion -ne $manifest.engineVersion -or $baseline.name -ne $manifest.baseline.name -or $baseline.version -ne $manifest.baseline.version) { throw 'Package version mismatch.' }
    $manifest
}
