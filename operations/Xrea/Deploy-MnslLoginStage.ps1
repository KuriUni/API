[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$source = Join-Path $projectRoot 'xrea-source\mnsl_app_sso.py'
$backupRoot = Join-Path $projectRoot ('deploy-backups\mnsl-login-stage-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$credentialPath = Join-Path $env:LOCALAPPDATA 'XreaDeploy\credentials.xml'
$targets = @(
    [pscustomobject]@{ Name='Primary'; Host='s1004.xrea.com'; User='backup1tkmpc'; Remote='/public_html/2415.jp/license'; Health='https://2415.jp/license/_fastapi/health' },
    [pscustomobject]@{ Name='Backup'; Host='s1006.xrea.com'; User='tkm10pc4rds'; Remote='/public_html/backup.2415.jp/license'; Health='https://backup.2415.jp/license/_fastapi/health' }
)
$fingerprint = '9c:fb:c9:21:d2:6f:de:43:43:bc:cb:e2:65:b0:99:e4:20:11:e1:72:bb:26:16:48:d1:3e:30:89:68:6d:d4:c7'
$dll = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCPnet.dll'),
    (Join-Path $env:ProgramFiles 'WinSCP\WinSCPnet.dll'),
    (Join-Path ${env:ProgramFiles(x86)} 'WinSCP\WinSCPnet.dll')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
if (-not $dll) { throw 'WinSCP .NET library was not found.' }
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Source mnsl_app_sso.py is missing.' }
Add-Type -Path $dll
$saved = Import-Clixml -LiteralPath $credentialPath
$credentialMap = @{}
foreach ($target in $targets) {
    $credential = if ($saved -is [System.Collections.IDictionary]) { $saved[$target.Name] } else { $saved.($target.Name) }
    if ($credential -isnot [System.Management.Automation.PSCredential] -or $credential.UserName -ne $target.User) {
        throw "Saved deployment credential for $($target.Name) is unavailable."
    }
    $credentialMap[$target.Name] = $credential
}

$sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
$changed = [System.Collections.Generic.List[object]]::new()
$backups = @{}
try {
    foreach ($target in $targets) {
        $nodeBackup = Join-Path $backupRoot $target.Name
        New-Item -ItemType Directory -Path $nodeBackup -Force | Out-Null
        $session = New-Object WinSCP.Session
        try {
            $options = New-Object WinSCP.SessionOptions -Property @{
                Protocol=[WinSCP.Protocol]::Ftp; FtpSecure=[WinSCP.FtpSecure]::Explicit
                FtpMode=[WinSCP.FtpMode]::Passive; HostName=$target.Host; PortNumber=21
                UserName=$target.User; SecurePassword=$credentialMap[$target.Name].Password
                TlsHostCertificateFingerprint=$fingerprint
            }
            $session.Open($options)
            $remote = $target.Remote.TrimEnd('/') + '/mnsl_app_sso.py'
            $backup = Join-Path $nodeBackup 'mnsl_app_sso.py'
            $session.GetFiles($remote, $backup, $false).Check()
            $backups[$target.Name] = $backup
            $session.PutFiles($source, $remote, $false).Check()
            $changed.Add($target)
            $verify = Join-Path $nodeBackup 'verify.py'
            $session.GetFiles($remote, $verify, $false).Check()
            $remoteHash = (Get-FileHash -LiteralPath $verify -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($remoteHash -ne $sourceHash) { throw "Remote hash mismatch on $($target.Name)." }
            Write-Host "Verified $($target.Name): $remoteHash"
        } finally { $session.Dispose() }
    }

    foreach ($target in $targets) {
        $response = Invoke-WebRequest -Uri $target.Health -Method Get -TimeoutSec 25 -UseBasicParsing
        $health = $response.Content | ConvertFrom-Json
        if ([int]$response.StatusCode -ne 200 -or $health.success -ne $true) { throw "Health check failed on $($target.Name)." }
        Write-Host "$($target.Name) FastAPI health: 200"
    }
    [pscustomobject]@{ status='deployed'; source_sha256=$sourceHash; backup=$backupRoot }
} catch {
    $failure = $_.Exception.Message
    $rollbackErrors = [System.Collections.Generic.List[string]]::new()
    for ($i = $changed.Count - 1; $i -ge 0; $i--) {
        $target = $changed[$i]
        $session = New-Object WinSCP.Session
        try {
            $options = New-Object WinSCP.SessionOptions -Property @{
                Protocol=[WinSCP.Protocol]::Ftp; FtpSecure=[WinSCP.FtpSecure]::Explicit
                FtpMode=[WinSCP.FtpMode]::Passive; HostName=$target.Host; PortNumber=21
                UserName=$target.User; SecurePassword=$credentialMap[$target.Name].Password
                TlsHostCertificateFingerprint=$fingerprint
            }
            $session.Open($options)
            $remote = $target.Remote.TrimEnd('/') + '/mnsl_app_sso.py'
            $session.PutFiles($backups[$target.Name], $remote, $false).Check()
            $verify = Join-Path (Join-Path $backupRoot $target.Name) 'rollback-verify.py'
            $session.GetFiles($remote, $verify, $false).Check()
            if ((Get-FileHash -LiteralPath $verify -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $backups[$target.Name] -Algorithm SHA256).Hash) {
                throw 'Rollback hash mismatch.'
            }
        } catch { $rollbackErrors.Add($target.Name) }
        finally { $session.Dispose() }
    }
    if ($rollbackErrors.Count) { throw "Deploy failed ($failure); rollback failed: $($rollbackErrors -join ', '). Backup: $backupRoot" }
    throw "Deploy failed ($failure); changed files were restored. Backup: $backupRoot"
} finally {
    foreach ($credential in $credentialMap.Values) { $credential.Password.Dispose() }
}
