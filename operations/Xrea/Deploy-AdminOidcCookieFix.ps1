$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\xrea-source\admin_oidc.py')).Path
$credMap = Import-Clixml -LiteralPath (Join-Path $env:LOCALAPPDATA 'XreaDeploy\credentials.xml')
$credential = $credMap.Primary
if ($credential.UserName -ne 'backup1tkmpc') { throw 'Unexpected Primary credential identity.' }
Add-Type -Path (Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCPnet.dll')
$remote = '/public_html/2415.jp/license/admin_oidc.py'
$fingerprint = '9c:fb:c9:21:d2:6f:de:43:43:bc:cb:e2:65:b0:99:e4:20:11:e1:72:bb:26:16:48:d1:3e:30:89:68:6d:d4:c7'
$backupRoot = Join-Path (Join-Path $PSScriptRoot '..\..') ('deploy-backups\admin-oidc-cookie-fix-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
$options = New-Object WinSCP.SessionOptions -Property @{
    Protocol = [WinSCP.Protocol]::Ftp
    FtpSecure = [WinSCP.FtpSecure]::Explicit
    FtpMode = [WinSCP.FtpMode]::Passive
    HostName = 's1004.xrea.com'
    PortNumber = 21
    UserName = $credential.UserName
    SecurePassword = $credential.Password
    TlsHostCertificateFingerprint = $fingerprint
}
$session = New-Object WinSCP.Session
$changed = $false
try {
    $session.Open($options)
    if (-not $session.FileExists($remote)) { throw 'Remote admin_oidc.py was not found.' }
    $backup = Join-Path $backupRoot 'admin_oidc.py'
    $session.GetFiles($remote, $backup, $false).Check()
    $oldHash = (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash.ToLowerInvariant()
    $session.PutFiles($source, $remote, $false).Check()
    $changed = $true
    $verify = Join-Path $backupRoot 'verify.py'
    $session.GetFiles($remote, $verify, $false).Check()
    $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    $remoteHash = (Get-FileHash -LiteralPath $verify -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sourceHash -ne $remoteHash) { throw 'Remote SHA-256 mismatch.' }
    $health = Invoke-WebRequest -Uri 'https://2415.jp/license/_fastapi/health' -TimeoutSec 30 -UseBasicParsing
    if ([int]$health.StatusCode -ne 200) { throw 'Primary health check failed.' }
    [pscustomobject]@{ node='Primary'; file='admin_oidc.py'; source_sha256=$sourceHash; previous_sha256=$oldHash; remote_sha256=$remoteHash; health_status=[int]$health.StatusCode; backup=$backupRoot }
}
catch {
    $failure = $_.Exception.Message
    if ($changed) {
        try {
            $session.PutFiles((Join-Path $backupRoot 'admin_oidc.py'), $remote, $false).Check()
            $rollbackVerify = Join-Path $backupRoot 'rollback-verify.py'
            $session.GetFiles($remote, $rollbackVerify, $false).Check()
            if ((Get-FileHash -LiteralPath $rollbackVerify -Algorithm SHA256).Hash.ToLowerInvariant() -ne $oldHash) { throw 'Rollback hash mismatch.' }
        } catch { throw "Deployment failed and rollback verification failed. Backup: $backupRoot" }
    }
    throw "Deployment failed: $failure. Backup: $backupRoot"
}
finally {
    $session.Dispose()
    $credential.Password.Dispose()
}

try { & (Join-Path $PSScriptRoot '..\Prune-DeployBackups.ps1') } catch { Write-Warning "Deployment succeeded, but backup retention cleanup failed: $($_.Exception.Message)" }
