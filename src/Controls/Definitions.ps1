function Get-ESAFBaseline {
    param([string]$Path)
    $b = Read-ESAFJson $Path
    Assert-ESAFFields $b @('schemaVersion','name','version','engineCompatibility','platform','minimumBuild','controls')
    foreach ($field in @('schemaVersion','name','version','engineCompatibility','platform')) { Assert-ESAFString $b.$field }
    if ($b.schemaVersion -cne '1.0' -or $b.name -notmatch '^[A-Za-z0-9-]+$' -or $b.version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid baseline identity.' }
    if ($b.engineCompatibility -notmatch '^>= (\d+\.\d+\.\d+)$') { throw 'Unsupported engine compatibility expression.' }
    if ([version]$script:EngineVersion -lt [version]$Matches[1]) { throw 'Engine is older than the baseline requirement.' }
    if ($b.platform -cne 'Windows' -or $b.minimumBuild -isnot [long] -and $b.minimumBuild -isnot [int] -or $b.minimumBuild -lt 1) { throw 'Invalid platform constraints.' }
    if ($b.controls -isnot [array] -or $b.controls.Count -eq 0) { throw 'Baseline requires controls.' }
    $seen = @{}
    foreach ($id in $b.controls) {
        if ($id -isnot [string] -or $id -cnotmatch '^ESAF-(MDE|AV|NET)-\d{3}$' -or $seen.ContainsKey($id)) { throw 'Invalid or duplicate control ID.' }
        $seen[$id] = $true
    }
    $b
}

function Get-ESAFControls {
    param($Baseline, [string]$ControlsPath)
    $providers = Get-ESAFProviderRegistry
    $categories = @{ MDE='mde'; AV='defender'; NET='network' }
    foreach ($id in $Baseline.controls) {
        if ($id -cnotmatch '^ESAF-(MDE|AV|NET)-\d{3}$') { throw 'Invalid control ID.' }
        $category = $categories[$Matches[1]]
        $c = Read-ESAFJson (Join-Path $ControlsPath ($category + '/' + $id + '.json'))
        Assert-ESAFFields $c @('id','title','description','category','severity','profiles','required','expected','evidenceProvider','functionalTest','remediationGuidance','references')
        foreach ($field in @('id','title','description','category','severity','evidenceProvider','remediationGuidance')) { Assert-ESAFString $c.$field }
        if ($c.id -cne $id -or $c.category -cne $category -or @($providers.Keys) -cnotcontains $c.evidenceProvider) { throw 'Invalid control/provider binding.' }
        $binding = $providers[$c.evidenceProvider]
        if ($c.category -cne $binding.Category) { throw 'Invalid provider category.' }
        if ($c.severity -cnotin @('critical','high','medium','informational') -or $c.required -isnot [bool]) { throw 'Invalid severity or required flag.' }
        foreach ($field in @('profiles','references')) {
            if ($c.$field -isnot [array] -or $c.$field.Count -eq 0) { throw 'Expected nonempty array.' }
            foreach ($value in $c.$field) { Assert-ESAFString $value }
        }
        Assert-ESAFFields $c.expected @('state')
        Assert-ESAFString $c.expected.state
        if ($binding.ExpectedStates -cnotcontains $c.expected.state) { throw 'Unsupported expected state for provider.' }
        Assert-ESAFFields $c.functionalTest @('supported')
        if ($c.functionalTest.supported -isnot [bool] -or $c.functionalTest.supported) { throw 'Functional execution is not implemented.' }
        $c
    }
}

function Test-ESAFApplicability {
    param($Control, $Baseline, $Platform)
    ($Control.profiles -contains $Baseline.name -and $Platform.platform -eq $Baseline.platform -and $Platform.build -ge $Baseline.minimumBuild -and $Platform.productType -eq 1)
}
