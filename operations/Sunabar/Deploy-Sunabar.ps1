[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$base = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$source = Join-Path $base 'xrea-source'
$credentialFile = Join-Path $env:LOCALAPPDATA 'XreaDeploy\credentials.xml'
$remoteRoot = '/public_html/2415.jp/license'
$fingerprint = '9c:fb:c9:21:d2:6f:de:43:43:bc:cb:e2:65:b0:99:e4:20:11:e1:72:bb:26:16:48:d1:3e:30:89:68:6d:d4:c7'
$files = @(
    'native_routes.py',
    'routes.json',
    'sunabar_api.py',
    'sunabar/index.html',
    'sunabar/sunabar.css',
    'sunabar/sunabar.js'
)

foreach ($name in $files) {
    $path = Join-Path $source ($name.Replace('/', '\'))
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Sunabar relay source not found: $path" }
}
if (-not (Test-Path -LiteralPath $credentialFile -PathType Leaf)) { throw 'Saved DPAPI XREA credentials were not found.' }
$credentials = Import-Clixml -LiteralPath $credentialFile
$credential = if ($credentials -is [System.Collections.IDictionary]) { $credentials['Primary'] } else { $credentials.Primary }
if (-not ($credential -is [System.Management.Automation.PSCredential]) -or $credential.UserName -ne 'backup1tkmpc') {
    throw 'The saved Primary credential is missing or does not match the configured FTP account.'
}

$assemblyCandidates = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCPnet.dll'),
    (Join-Path $env:ProgramFiles 'WinSCP\WinSCPnet.dll'),
    (Join-Path ${env:ProgramFiles(x86)} 'WinSCP\WinSCPnet.dll')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
if (-not $assemblyCandidates) { throw 'WinSCP .NET library was not found.' }
Add-Type -Path ($assemblyCandidates | Select-Object -First 1)

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupDirectory = Join-Path $base "deploy-backups\sunabar-relay-$stamp"
$verifyDirectory = Join-Path $env:TEMP "sunabar-relay-verify-$stamp"
New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $verifyDirectory -Force | Out-Null
$session = New-Object WinSCP.Session
try {
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
    $session.Open($options)

    foreach ($name in $files) {
        $remoteFile = "$remoteRoot/$name"
        $localRelative = $name.Replace('/', '\')
        if ($session.FileExists($remoteFile)) {
            $target = Join-Path $backupDirectory $localRelative
            $targetParent = Split-Path -Path $target -Parent
            if (-not (Test-Path -LiteralPath $targetParent)) { New-Item -ItemType Directory -Path $targetParent -Force | Out-Null }
            $backup = $session.GetFiles($remoteFile, $target, $false)
            $backup.Check()
        }
    }

    $transferOptions = New-Object WinSCP.TransferOptions
    $transferOptions.TransferMode = [WinSCP.TransferMode]::Binary
    $transferOptions.ResumeSupport.State = [WinSCP.TransferResumeSupportState]::On
    foreach ($name in $files) {
        $localFile = Join-Path $source ($name.Replace('/', '\'))
        $remoteDirectory = if ($name.Contains('/')) { "$remoteRoot/sunabar/" } else { "$remoteRoot/" }
        $upload = $session.PutFiles($localFile, $remoteDirectory, $false, $transferOptions)
        $upload.Check()
    }

    foreach ($name in $files) {
        $remoteFile = "$remoteRoot/$name"
        $target = Join-Path $verifyDirectory ($name.Replace('/', '\'))
        $targetParent = Split-Path -Path $target -Parent
        if (-not (Test-Path -LiteralPath $targetParent)) { New-Item -ItemType Directory -Path $targetParent -Force | Out-Null }
        $download = $session.GetFiles($remoteFile, $target, $false)
        $download.Check()
        $localHash = (Get-FileHash -LiteralPath (Join-Path $source ($name.Replace('/', '\'))) -Algorithm SHA256).Hash
        $remoteHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
        if ($localHash -ne $remoteHash) { throw "Remote content verification failed: $name" }
        Write-Host "Verified $name (SHA-256 matched)"
    }
    Write-Host "XREA relay deployed. Existing versions backed up under: $backupDirectory"
}
finally {
    $session.Dispose()
    $credential = $null
    $credentials = $null
}

try {
    $page = Invoke-WebRequest -Uri 'https://2415.jp/license/sunabar/' -UseBasicParsing -TimeoutSec 20
    if ([int]$page.StatusCode -ne 200 -or $page.Content -notmatch 'Sunabar') { throw 'Sunabar page check failed.' }
    $healthResponse = Invoke-WebRequest -Uri 'https://2415.jp/license/api/sunabar/v1/health.php' -UseBasicParsing -TimeoutSec 20
    $health = $healthResponse.Content | ConvertFrom-Json
    if (-not $health.ok -or $health.dependencies.database -ne 'ok') { throw 'The Core Server health response did not confirm database readiness.' }
    Write-Host 'Public page returned HTTP 200; the relayed Core Server API and database are ready.'
}
catch {
    throw "Files were transferred and hash-verified, but the public relay check failed: $($_.Exception.Message)"
}
