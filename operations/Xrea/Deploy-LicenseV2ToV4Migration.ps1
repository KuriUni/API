#requires -Version 7.0
[CmdletBinding()]
param([ValidateSet('Both','Primary','Backup')][string] $Target = 'Both')
$ErrorActionPreference = 'Stop'
$base = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$source = Join-Path $base 'xrea-source'
. (Join-Path $PSScriptRoot 'Xrea-DeployTargets.ps1')
$install = Join-Path $env:LOCALAPPDATA 'Programs\WinSCP'
Add-Type -Path (Join-Path $install 'netstandard2.0\WinSCPnet.dll')
$credentials = Import-Clixml -LiteralPath (Join-Path $env:LOCALAPPDATA 'XreaDeploy\credentials.xml')
$files = @('native_v4.py','v4_crypto.py','openapi-catalog.json','api-catalog/openapi.json','routes.json','api/v4/activate.html')
foreach ($file in $files) {
    if (-not (Test-Path -LiteralPath (Join-Path $source $file) -PathType Leaf)) { throw "Missing source: $file" }
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupRoot = Join-Path $base "deploy-backups\license-v2-v4-migration-$stamp"
$targets = @(Get-XreaDeployTargets | Where-Object { $Target -eq 'Both' -or $_.Name -eq $Target } | Sort-Object Name)
$sessions = @{}
$backups = @{}
$uploaded = [Collections.Generic.List[string]]::new()
$localHashes = @{}
foreach ($file in $files) { $localHashes[$file] = (Get-FileHash -LiteralPath (Join-Path $source $file) -Algorithm SHA256).Hash }
try {
    foreach ($destination in $targets) {
        $credential = if ($credentials -is [Collections.IDictionary]) { $credentials[$destination.Name] } else { $credentials.($destination.Name) }
        if ($credential -isnot [pscredential] -or $credential.UserName -ne $destination.User) { throw "Saved credential missing for $($destination.Name)." }
        $session = [WinSCP.Session]::new()
        $session.ExecutablePath = Join-Path $install 'WinSCP.exe'
        $session.SessionLogPath = Join-Path $env:TEMP "license-v2-v4-migration-$($destination.Name)-$stamp.log"
        $session.Open([WinSCP.SessionOptions]@{
            Protocol=[WinSCP.Protocol]::Ftp; FtpSecure=[WinSCP.FtpSecure]::Explicit
            FtpMode=[WinSCP.FtpMode]::Passive; HostName=$destination.Host; PortNumber=21
            UserName=$destination.User; SecurePassword=$credential.Password
            TlsHostCertificateFingerprint='9c:fb:c9:21:d2:6f:de:43:43:bc:cb:e2:65:b0:99:e4:20:11:e1:72:bb:26:16:48:d1:3e:30:89:68:6d:d4:c7'
        })
        $sessions[$destination.Name] = $session
        $targetBackup = Join-Path $backupRoot $destination.Name
        New-Item -ItemType Directory -Path $targetBackup -Force | Out-Null
        foreach ($file in $files) {
            $remote = $destination.Remote + '/' + $file
            if (-not $session.FileExists($remote)) { throw "Remote file missing: $($destination.Name):$file" }
            $localBackup = Join-Path $targetBackup $file
            New-Item -ItemType Directory -Path (Split-Path $localBackup -Parent) -Force | Out-Null
            $session.GetFiles($remote,$localBackup,$false).Check()
            $backups["$($destination.Name)|$file"] = $localBackup
        }
    }
    foreach ($destination in $targets) {
        $session = $sessions[$destination.Name]
        foreach ($file in $files) {
            $remote = $destination.Remote + '/' + $file
            $backup = $backups["$($destination.Name)|$file"]
            if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -eq $localHashes[$file]) { continue }
            $uploaded.Add("$($destination.Name)|$file")
            $session.PutFiles((Join-Path $source $file),$remote,$false).Check()
            $verify = $backup + '.verify'
            $session.GetFiles($remote,$verify,$false).Check()
            if ((Get-FileHash -LiteralPath $verify -Algorithm SHA256).Hash -ne $localHashes[$file]) { throw "SHA-256 mismatch: $($destination.Name):$file" }
        }
        Write-Host "$($destination.Name): V2-to-V4 migration files verified."
    }
    Write-Host "Pre-deployment backups: $backupRoot"
} catch {
    $reason = $_.Exception.Message
    $rollbackErrors = @()
    for ($index=$uploaded.Count-1; $index -ge 0; $index--) {
        $parts = $uploaded[$index] -split '\|',2
        $destination = $targets | Where-Object Name -eq $parts[0] | Select-Object -First 1
        $session = $sessions[$parts[0]]
        $file = $parts[1]
        try {
            $backup = $backups["$($destination.Name)|$file"]
            $remote = $destination.Remote + '/' + $file
            $session.PutFiles($backup,$remote,$false).Check()
            $check = $backup + '.rollback'
            $session.GetFiles($remote,$check,$false).Check()
            if ((Get-FileHash -LiteralPath $check -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash) { throw 'Rollback hash mismatch.' }
        } catch { $rollbackErrors += $uploaded[$index] }
    }
    if ($rollbackErrors.Count) { throw "Deployment failed ($reason); rollback needs attention: $($rollbackErrors -join ', '). Backup: $backupRoot" }
    throw "Deployment failed ($reason); uploaded files restored. Backup: $backupRoot"
} finally {
    foreach ($session in $sessions.Values) { $session.Dispose() }
}
