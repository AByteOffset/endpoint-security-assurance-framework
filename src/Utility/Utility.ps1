function New-ESAFRunId {
    $bytes = New-Object byte[] 16
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    'ESAF-{0}-{1}' -f [DateTime]::UtcNow.ToString('yyyyMMdd'), ([BitConverter]::ToString($bytes).Replace('-',''))
}

function Read-ESAFJson {
    param([string]$Path)
    try { Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Unable to read valid ESAF JSON.' }
}

function Assert-ESAFFields {
    param($Object, [string[]]$Fields)
    if ($null -eq $Object -or $Object -isnot [pscustomobject]) { throw 'Expected a JSON object.' }
    $actual = @($Object.PSObject.Properties.Name)
    foreach ($field in $Fields) { if ($actual -cnotcontains $field) { throw "Missing field: $field" } }
    foreach ($field in $actual) { if ($Fields -cnotcontains $field) { throw "Unsupported field: $field" } }
}

function Assert-ESAFString {
    param($Value)
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)) { throw 'Expected a nonempty string.' }
}

function Get-ESAFPlatform {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    [pscustomobject]@{ platform = 'Windows'; build = [int]$os.BuildNumber; productType = [int]$os.ProductType }
}
