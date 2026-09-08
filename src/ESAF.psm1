Set-StrictMode -Version Latest
$script:EngineVersion = '0.2.0'
$script:RepositoryRoot = Split-Path $PSScriptRoot -Parent
foreach ($folder in @('Utility','Controls','Evidence','Verdict','Reporting','Core')) {
    foreach ($file in Get-ChildItem (Join-Path $PSScriptRoot $folder) -Filter *.ps1 | Sort-Object Name) {
        . $file.FullName
    }
}
Export-ModuleMember -Function Invoke-ESAFValidation
