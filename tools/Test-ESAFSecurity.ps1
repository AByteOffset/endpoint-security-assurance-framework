#Requires -Version 5.1
[CmdletBinding()]
param([string]$RepositoryRoot)
$ErrorActionPreference='Stop'
if (-not $PSBoundParameters.ContainsKey('RepositoryRoot')) { $RepositoryRoot=Split-Path $PSScriptRoot -Parent }
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { throw 'Unable to resolve repository root for security scan.' }
$forbidden=@('Set-MpPreference','Add-MpPreference','Remove-MpPreference','Set-NetFirewallProfile','Set-NetFirewallRule','New-NetFirewallRule','Disable-NetFirewallRule','Stop-Service','Start-Service','Set-Service','Invoke-Expression','iex','Set-ExecutionPolicy','Enable-BitLocker','Disable-BitLocker','Suspend-BitLocker','Resume-BitLocker','Add-BitLockerKeyProtector','Remove-BitLockerKeyProtector','Clear-Tpm','Initialize-Tpm','Set-TpmOwnerAuth','Set-SecureBootUEFI')
$scanPaths=@('src','intune','packaging','tools','policy-assurance')
foreach ($folder in $scanPaths) {
    foreach ($file in Get-ChildItem (Join-Path $RepositoryRoot $folder) -Recurse -File | Where-Object { $_.Extension -in @('.ps1','.psm1','.psd1','.json') }) {
        $content=Get-Content $file.FullName -Raw
        if ($content -match '(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|C:\\Users\\[^\s''"\\]+\\)') { throw 'Potential secret or user-specific path in production source.' }
        if ($file.Extension -in @('.ps1','.psm1')) {
            $tokens=$null;$errors=$null
            $ast=[Management.Automation.Language.Parser]::ParseInput($content,[ref]$tokens,[ref]$errors)
            foreach ($command in $ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)) {
                if ($command.GetCommandName() -in $forbidden) { throw 'Prohibited production command detected.' }
                if ($file.FullName -match '[\\/]policy-assurance[\\/]') {
                    $name=$command.GetCommandName()
                    if ($name -match '-Mg' -and $name -notin @('Get-MgContext','Invoke-MgGraphRequest')) { throw 'Graph write or unsupported Graph cmdlet detected.' }
                    if ($name -eq 'Invoke-MgGraphRequest' -and $command.Extent.Text -notmatch '(?i)-Method\s+GET\b') { throw 'Graph request without an explicit GET method detected.' }
                }
            }
        }
    }
}
Write-Output 'ESAF production security scan passed.'
