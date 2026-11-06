[CmdletBinding()]
param(
    [string] $StageRoot = (Join-Path $env:TEMP 'xrea-backup-fastapi-vendor')
)

$ErrorActionPreference = 'Stop'
$sourceVendor = '/.tuti-fastapi/20261028T153637Z-27a2f0ad/vendor'
$targetVendor = '/.tuti-fastapi/20261028T153637Z-27a2f0ad/vendor'
$fingerprint = '9c:fb:c9:21:d2:6f:de:43:43:bc:cb:e2:65:b0:99:e4:20:11:e1:72:bb:26:16:48:d1:3e:30:89:68:6d:d4:c7'
$credentialFile = Join-Path $env:LOCALAPPDATA 'XreaDeploy\credentials.xml'
$credentials = Import-Clixml -LiteralPath $credentialFile
$primaryCredential = $credentials.Primary
$backupCredential = $credentials.Backup
if ($primaryCredential.UserName -ne 'backup1tkmpc' -or $backupCredential.UserName -ne 'tkm10pc4rds') {
    throw 'Saved XREA credential identities do not match the expected hosts.'
}

Add-Type -Path (Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCPnet.dll')
function New-FtpsOptions([string] $hostName, [System.Management.Automation.PSCredential] $credential) {
    New-Object WinSCP.SessionOptions -Property @{
        Protocol = [WinSCP.Protocol]::Ftp
        FtpSecure = [WinSCP.FtpSecure]::Explicit
        FtpMode = [WinSCP.FtpMode]::Passive
        HostName = $hostName
        PortNumber = 21
        UserName = $credential.UserName
        SecurePassword = $credential.Password
        TlsHostCertificateFingerprint = $fingerprint
        Timeout = [TimeSpan]::FromSeconds(20)
    }
}

function Get-RemoteFiles($Session, [string] $RemoteDirectory, [string] $RelativeDirectory) {
    foreach ($entry in $Session.ListDirectory($RemoteDirectory).Files) {
        if ($entry.Name -in @('.', '..')) { continue }
        if ($entry.Name -match '[/\\]' -or [System.IO.Path]::GetFileName($entry.Name) -ne $entry.Name) {
            throw 'Unexpected path component in Primary vendor directory.'
        }
        $remotePath = $RemoteDirectory.TrimEnd('/') + '/' + $entry.Name
        $relativePath = if ($RelativeDirectory) { $RelativeDirectory + '/' + $entry.Name } else { $entry.Name }
        if ($entry.IsSymbolicLink) { throw "Symbolic link is not allowed in Primary vendor: $relativePath" }
        if ($entry.IsDirectory) {
            Get-RemoteFiles $Session $remotePath $relativePath
        } else {
            [pscustomobject]@{ remote=$remotePath; relative=$relativePath; length=[long]$entry.Length }
        }
    }
}

$stage = [System.IO.Path]::GetFullPath($StageRoot)
$sourceTree = Join-Path $stage 'primary-vendor'
$verifyTree = Join-Path $stage 'backup-verify'
New-Item -ItemType Directory -Path $sourceTree -Force | Out-Null
New-Item -ItemType Directory -Path $verifyTree -Force | Out-Null
$sourceSession = New-Object WinSCP.Session
$targetSession = New-Object WinSCP.Session
try {
    $sourceSession.Open((New-FtpsOptions 's1004.xrea.com' $primaryCredential))
    $targetSession.Open((New-FtpsOptions 's1006.xrea.com' $backupCredential))

    $targetParent = '/.tuti-fastapi/20261028T153637Z-27a2f0ad'
    if ($targetSession.FileExists($targetVendor)) {
        throw 'Backup vendor directory already exists; refusing to overwrite it.'
    }
    if (-not $targetSession.FileExists('/.tuti-fastapi')) {
        throw 'Expected FastAPI release root is missing on Backup.'
    }
    if (-not $sourceSession.FileExists($sourceVendor)) {
        throw 'The verified Primary vendor directory is missing.'
    }

    $localTransfer = New-Object WinSCP.TransferOptions
    $localTransfer.TransferMode = [WinSCP.TransferMode]::Binary
    $remoteFiles = @(Get-RemoteFiles $sourceSession $sourceVendor '')
    if ($remoteFiles.Count -eq 0) { throw 'Primary vendor directory returned no files.' }
    $index = 0
    foreach ($item in $remoteFiles) {
        $index++
        $localFile = Join-Path $sourceTree ($item.relative -replace '/', '\\')
        New-Item -ItemType Directory -Path (Split-Path -Parent $localFile) -Force | Out-Null
        $sourceSession.GetFiles($item.remote, $localFile, $false).Check()
        if ((Get-Item -LiteralPath $localFile).Length -ne $item.length) { throw "Primary download size mismatch for $($item.relative)" }
        if (($index % 50) -eq 0) { Write-Host "Downloaded $index / $($remoteFiles.Count) dependency files." }
    }
    $sourceFiles = @(Get-ChildItem -LiteralPath $sourceTree -File -Recurse -Force)
    $requiredPackages = @('a2wsgi', 'cryptography', 'cffi', 'pymysql', 'bcrypt')
    $names = @(Get-ChildItem -LiteralPath $sourceTree -Directory -Force | ForEach-Object Name)
    foreach ($package in $requiredPackages) {
        if ($package -notin $names) { throw "Primary vendor is missing required package: $package" }
    }
    $manifest = foreach ($file in $sourceFiles) {
        [pscustomobject]@{
            path = $file.FullName.Substring($sourceTree.Length).TrimStart('\') -replace '\\','/'
            length = $file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $manifestPath = Join-Path $stage 'vendor-manifest.json'
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding utf8

    $targetSession.CreateDirectory($targetVendor)
    $createdDirectories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $index = 0
    foreach ($file in $sourceFiles) {
        $index++
        $relative = $file.FullName.Substring($sourceTree.Length).TrimStart('\') -replace '\\','/'
        $parts = $relative.Split('/')
        $remoteDirectory = $targetVendor
        for ($partIndex = 0; $partIndex -lt ($parts.Length - 1); $partIndex++) {
            $remoteDirectory += '/' + $parts[$partIndex]
            if ($createdDirectories.Add($remoteDirectory)) { $targetSession.CreateDirectory($remoteDirectory) }
        }
        $targetSession.PutFiles($file.FullName, $remoteDirectory + '/', $false).Check()
        if (($index % 50) -eq 0) { Write-Host "Uploaded $index / $($sourceFiles.Count) dependency files." }
    }

    $targetFiles = @(Get-RemoteFiles $targetSession $targetVendor '')
    if ($targetFiles.Count -ne $sourceFiles.Count) { throw 'Backup vendor file count does not match Primary.' }
    $index = 0
    foreach ($item in $targetFiles) {
        $index++
        $localFile = Join-Path $verifyTree ($item.relative -replace '/', '\\')
        New-Item -ItemType Directory -Path (Split-Path -Parent $localFile) -Force | Out-Null
        $targetSession.GetFiles($item.remote, $localFile, $false).Check()
        if ((Get-Item -LiteralPath $localFile).Length -ne $item.length) { throw "Backup verification size mismatch for $($item.relative)" }
        if (($index % 50) -eq 0) { Write-Host "Verified $index / $($targetFiles.Count) dependency files." }
    }
    $verifiedFiles = @(Get-ChildItem -LiteralPath $verifyTree -File -Recurse -Force)
    if ($verifiedFiles.Count -ne $sourceFiles.Count) { throw 'Backup vendor file count does not match Primary.' }
    foreach ($file in $verifiedFiles) {
        $relative = $file.FullName.Substring($verifyTree.Length).TrimStart('\') -replace '\\','/'
        $expected = $manifest | Where-Object path -eq $relative | Select-Object -First 1
        $actualHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if (-not $expected -or $expected.length -ne $file.Length -or $expected.sha256 -ne $actualHash) {
            throw "Backup vendor verification failed for $relative"
        }
    }
    Write-Host ("Restored and verified {0} dependency files in Backup vendor." -f $verifiedFiles.Count)
}
finally {
    $sourceSession.Dispose()
    $targetSession.Dispose()
    $primaryCredential.Password.Dispose()
    $backupCredential.Password.Dispose()
}
