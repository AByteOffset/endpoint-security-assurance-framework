#Requires -Version 5.1
[CmdletBinding()]
param([string]$RepositoryRoot=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop'
$forbidden=@('Set-MpPreference','Add-MpPreference','Remove-MpPreference','Set-NetFirewallProfile','Set-NetFirewallRule','New-NetFirewallRule','Disable-NetFirewallRule','Stop-Service','Start-Service','Set-Service','Invoke-Expression','iex','Set-ExecutionPolicy')
$scanPaths=@('src','intune','packaging','tools')
foreach ($folder in $scanPaths) {
    foreach ($file in Get-ChildItem (Join-Path $RepositoryRoot $folder) -Recurse -File | Where-Object { $_.Extension -in @('.ps1','.psm1','.psd1','.json') }) {
        $content=Get-Content $file.FullName -Raw
        if ($content -match '(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|C:\\Users\\[^\s''"\\]+\\)') { throw 'Potential secret or user-specific path in production source.' }
        if ($file.Extension -in @('.ps1','.psm1')) {
            $tokens=$null;$errors=$null
            $ast=[Management.Automation.Language.Parser]::ParseInput($content,[ref]$tokens,[ref]$errors)
            foreach ($command in $ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)) {
                if ($command.GetCommandName() -in $forbidden) { throw 'Prohibited production command detected.' }
            }
        }
    }
}
Write-Output 'ESAF production security scan passed.'
