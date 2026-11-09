[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$credentialPath = Join-Path $env:LOCALAPPDATA 'XreaDeploy\credentials.xml'
$targets = @(
    [pscustomobject]@{ Name='Primary'; Host='s1004.xrea.com'; User='backup1tkmpc'; Site='2415.jp'; Remote='/public_html/2415.jp/license' },
    [pscustomobject]@{ Name='Backup'; Host='s1006.xrea.com'; User='tkm10pc4rds'; Site='backup.2415.jp'; Remote='/public_html/backup.2415.jp/license' }
)
$files = @('admin_oidc.py', 'admin_api_handlers.py', 'tenant_sso_contracts.py', 'mnsl_app_sso.py', 'baas_handlers.py', 'ha_export.py', 'ha_snapshot.py')
$fingerprint = '9c:fb:c9:21:d2:6f:de:43:43:bc:cb:e2:65:b0:99:e4:20:11:e1:72:bb:26:16:48:d1:3e:30:89:68:6d:d4:c7'
$assembly = Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCPnet.dll'
if (-not (Test-Path -LiteralPath $assembly -PathType Leaf)) { throw 'WinSCP .NET library was not found.' }
Add-Type -Path $assembly
$saved = Import-Clixml -LiteralPath $credentialPath
$credentials = @{}
foreach ($target in $targets) {
    $credential = $saved[$target.Name]
    if ($credential -isnot [System.Management.Automation.PSCredential] -or $credential.UserName -ne $target.User) {
        throw "Saved deployment credential for $($target.Name) is unavailable."
    }
    $credentials[$target.Name] = $credential
}
$backupRoot = Join-Path $projectRoot ('deploy-backups\one-time-issuance-grant-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
$sourceHashes = @{}
foreach ($name in $files) {
    $path = Join-Path $projectRoot ('xrea-source\' + $name)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Source file missing: $name" }
    $sourceHashes[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
$changed = [System.Collections.Generic.List[object]]::new()
$backups = @{}

function New-SessionOptions($target) {
    return New-Object WinSCP.SessionOptions -Property @{
        Protocol=[WinSCP.Protocol]::Ftp; FtpSecure=[WinSCP.FtpSecure]::Explicit
        FtpMode=[WinSCP.FtpMode]::Passive; HostName=$target.Host; PortNumber=21
        UserName=$target.User; SecurePassword=$credentials[$target.Name].Password
        TlsHostCertificateFingerprint=$fingerprint
    }
}

try {
    foreach ($target in $targets) {
        $session = New-Object WinSCP.Session
        try {
            $session.Open((New-SessionOptions $target))
            foreach ($name in $files) {
                $remote = $target.Remote.TrimEnd('/') + '/' + $name
                if (-not $session.FileExists($remote)) { throw "$($target.Name): remote file missing: $name" }
                $backupDir = Join-Path $backupRoot $target.Name
                New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
                $backup = Join-Path $backupDir $name
                $session.GetFiles($remote, $backup, $false).Check()
                $backups[($target.Name + ':' + $name)] = $backup
                $source = Join-Path $projectRoot ('xrea-source\' + $name)
                $session.PutFiles($source, $remote, $false).Check()
                $changed.Add([pscustomobject]@{ Target=$target; Remote=$remote; Name=$name })
                $verify = Join-Path $backupDir ($name + '.remote-verify')
                $session.GetFiles($remote, $verify, $false).Check()
                if ((Get-FileHash -LiteralPath $verify -Algorithm SHA256).Hash.ToLowerInvariant() -ne $sourceHashes[$name]) {
                    throw "$($target.Name): deployed file hash mismatch: $name"
                }
            }
            Write-Host "Verified $($target.Name): $($files -join ', ')"
        } finally { $session.Dispose() }
    }
    foreach ($target in $targets) {
        $health = Invoke-WebRequest -Uri ("https://{0}/license/_fastapi/health" -f $target.Site) -TimeoutSec 30 -UseBasicParsing
        if ([int]$health.StatusCode -ne 200) { throw "$($target.Name): health check failed." }
        Write-Host "$($target.Name) FastAPI health: 200"
    }
    [pscustomobject]@{ status='deployed'; files=$files; source_sha256=$sourceHashes; backup=$backupRoot }
} catch {
    $failure = $_.Exception.Message
    $rollbackErrors = [System.Collections.Generic.List[string]]::new()
    for ($i = $changed.Count - 1; $i -ge 0; $i--) {
        $item = $changed[$i]
        $session = New-Object WinSCP.Session
        try {
            $session.Open((New-SessionOptions $item.Target))
            $backup = $backups[($item.Target.Name + ':' + $item.Name)]
            $session.PutFiles($backup, $item.Remote, $false).Check()
            $verify = Join-Path $backupRoot ($item.Target.Name + '-' + $item.Name + '.rollback-verify')
            $session.GetFiles($item.Remote, $verify, $false).Check()
            if ((Get-FileHash -LiteralPath $verify -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash) {
                throw 'Rollback hash mismatch.'
            }
        } catch { $rollbackErrors.Add($item.Target.Name + ':' + $item.Name) }
        finally { $session.Dispose() }
    }
    if ($rollbackErrors.Count) { throw "Deployment failed ($failure); rollback verification failed for $($rollbackErrors -join ', '). Backup: $backupRoot" }
    throw "Deployment failed ($failure); all changed files were restored. Backup: $backupRoot"
} finally {
    foreach ($credential in $credentials.Values) { $credential.Password.Dispose() }
}
