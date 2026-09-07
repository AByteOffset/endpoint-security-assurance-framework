function Copy-ESAFPayload {
    param([string]$SourceRoot, [string]$Destination)
    $source=[IO.Path]::GetFullPath($SourceRoot).TrimEnd('\')
    $target=[IO.Path]::GetFullPath($Destination).TrimEnd('\')
    if ($source -eq $target -or $source.StartsWith($target+'\',[StringComparison]::OrdinalIgnoreCase) -or $target.StartsWith($source+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Source and installation paths must be separate.' }
    Assert-ESAFStoragePath $source
    Assert-ESAFStoragePath $target
    foreach ($folder in @('src','controls','baselines','tools')) {
        $from=Join-Path $source $folder
        $to=Join-Path $target $folder
        if (-not (Test-Path -LiteralPath $from -PathType Container)) { throw 'Incomplete ESAF payload.' }
    }
    $null=New-Item -ItemType Directory -Path $target -Force -ErrorAction Stop
    Set-ESAFStoragePermissions $target
    foreach ($folder in @('src','controls','baselines','tools')) {
        $from=Join-Path $source $folder
        $to=Join-Path $target $folder
        $null=New-Item -ItemType Directory -Path $to -Force -ErrorAction Stop
        $wanted=@{}
        foreach ($file in Get-ChildItem -LiteralPath $from -Recurse -File -Force -ErrorAction Stop) {
            $relative=$file.FullName.Substring($from.Length).TrimStart('\')
            $destFile=Join-Path $to $relative
            $wanted[$destFile]=$true
            $null=New-Item -ItemType Directory -Path (Split-Path $destFile -Parent) -Force -ErrorAction Stop
            Copy-Item -LiteralPath $file.FullName -Destination $destFile -Force -ErrorAction Stop
        }
        # Remove obsolete files only within the four owned payload directories.
        foreach ($file in Get-ChildItem -LiteralPath $to -Recurse -File -Force -ErrorAction Stop) {
            if (-not $file.FullName.StartsWith($target+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected payload path.' }
            if (-not $wanted.ContainsKey($file.FullName)) { Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop }
        }
    }
    Set-ESAFStoragePermissions $target
}
