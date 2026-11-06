[CmdletBinding()]
param(
    [ValidateSet('Primary','Backup')]
    [string] $Node = 'Backup',
    [string] $DownloadRoot = (Join-Path $env:TEMP 'xrea-backup-diagnostic')
)

$ErrorActionPreference = 'Stop'
$credentialPath = Join-Path $env:LOCALAPPDATA 'XreaDeploy\credentials.xml'
$saved = Import-Clixml -LiteralPath $credentialPath
$credential = $saved[$Node]
$expectedUser = if ($Node -eq 'Primary') { 'backup1tkmpc' } else { 'tkm10pc4rds' }
if ($credential.UserName -ne $expectedUser) { throw "Unexpected saved $Node credential identity." }
$site = if ($Node -eq 'Primary') { '2415.jp' } else { 'backup.2415.jp' }
$privateName = if ($Node -eq 'Primary') { '.tuti-license-ha-2415.jp' } else { '.tuti-license-ha-backup.2415.jp' }
$publicRoot = "/public_html/$site/license"

$assembly = Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCPnet.dll'
Add-Type -Path $assembly
$options = New-Object WinSCP.SessionOptions -Property @{
    Protocol = [WinSCP.Protocol]::Ftp
    FtpSecure = [WinSCP.FtpSecure]::Explicit
    FtpMode = [WinSCP.FtpMode]::Passive
    HostName = if ($Node -eq 'Primary') { 's1004.xrea.com' } else { 's1006.xrea.com' }
    PortNumber = 21
    UserName = $credential.UserName
    SecurePassword = $credential.Password
    TlsHostCertificateFingerprint = '9c:fb:c9:21:d2:6f:de:43:43:bc:cb:e2:65:b0:99:e4:20:11:e1:72:bb:26:16:48:d1:3e:30:89:68:6d:d4:c7'
}

$root = [System.IO.Path]::GetFullPath($DownloadRoot)
New-Item -ItemType Directory -Path $root -Force | Out-Null
$session = New-Object WinSCP.Session
try {
    $session.Open($options)
    foreach ($remote in @($publicRoot, "/public_html/$site")) {
        Write-Host "Listing $remote"
        $entries = $session.ListDirectory($remote).Files
        foreach ($entry in $entries | Where-Object { -not $_.IsDirectory -and $_.Name -match '^(\.htaccess|index\.cgi|.*config.*|.*runtime.*)$' }) {
            Write-Host ("{0} {1} bytes" -f $entry.Name, $entry.Length)
        }
    }
    foreach ($remote in @(
        '/.tuti-fastapi/20261028T153637Z-27a2f0ad/vendor',
        '/.tuti-fastapi-latest/20261026T162420Z-4b7d208e/vendor'
    )) {
        try {
            $entries = $session.ListDirectory($remote).Files | Where-Object { $_.Name -notin @('.', '..') }
            $matching = $entries | Where-Object { $_.Name -match '^(a2wsgi|cryptography|bcrypt|pymysql|cffi|fastapi|starlette)(-|$)' }
            Write-Host ("Vendor path {0}: {1} entries; relevant: {2}" -f $remote, $entries.Count, (($matching | ForEach-Object Name) -join ', '))
        } catch {
            Write-Host ("Vendor path unavailable: {0}" -f $remote)
        }
    }
    try {
        $packagePath = '/.tuti-fastapi-latest/20261026T162420Z-4b7d208e/vendor/a2wsgi'
        $packageFiles = $session.ListDirectory($packagePath).Files | Where-Object { $_.Name -notin @('.', '..') }
        Write-Host ("a2wsgi package files: {0}" -f (($packageFiles | ForEach-Object { $_.Name + ':' + $_.Length }) -join ', '))
    } catch {
        Write-Host 'a2wsgi package directory could not be inspected.'
    }
    foreach ($remote in @("/$privateName", "/$privateName/runtime", '/', '/.tuti-fastapi', '/.tuti-fastapi-latest')) {
        try {
            $entries = $session.ListDirectory($remote).Files | Where-Object { $_.IsDirectory -and $_.Name -notin @('.', '..') }
            Write-Host ("Directory {0}: {1}" -f $remote, (($entries | ForEach-Object Name) -join ', '))
        } catch {
            Write-Host ("Directory could not be listed: {0}" -f $remote)
        }
    }
    $privateCandidates = @(
        "/$privateName/runtime/root-fastapi-error.json",
        "/public_html/../$privateName/runtime/root-fastapi-error.json",
        "/public_html/$privateName/runtime/root-fastapi-error.json"
    )
    foreach ($source in $privateCandidates) {
        if ($session.FileExists($source)) {
            $errorInfo = $session.GetFileInfo($source)
            $destination = Join-Path $root 'root-fastapi-error.json'
            $session.GetFiles($source, $destination, $false).Check()
            Write-Host ("Downloaded sanitized FastAPI traceback metadata (modified {0})." -f $errorInfo.LastWriteTime)
            break
        }
    }
    $metricsCandidates = @(
        "/$privateName/runtime/request-metrics.jsonl",
        "/public_html/../$privateName/runtime/request-metrics.jsonl",
        "/public_html/$privateName/runtime/request-metrics.jsonl"
    )
    foreach ($source in $metricsCandidates) {
        if ($session.FileExists($source)) {
            $destination = Join-Path $root 'request-metrics.jsonl'
            $session.GetFiles($source, $destination, $false).Check()
            Write-Host 'Downloaded bounded request metrics (metadata only).'
            break
        }
    }
    foreach ($remote in @($publicRoot, "/public_html/$site")) {
        $local = Join-Path $root (($remote -replace '/', '_').Trim('_'))
        New-Item -ItemType Directory -Path $local -Force | Out-Null
        foreach ($name in @('.htaccess', 'index.cgi', 'fastapi-runtime.json', 'migration_config.py', 'mobile_admin_auth.py', 'mnsl_app_sso.py', 'native_routes.py', 'native_http.py', 'app_sso.py', 'file_locking.py')) {
            $source = $remote.TrimEnd('/') + '/' + $name
            if ($session.FileExists($source)) {
                $destination = Join-Path $local $name
                $session.GetFiles($source, $destination, $false).Check()
                Write-Host "Downloaded diagnostic file: $name"
            }
        }
    }
    Write-Host "Diagnostic files are in $root"
}
finally {
    $session.Dispose()
    $credential.Password.Dispose()
}
