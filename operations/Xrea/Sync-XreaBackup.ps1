<#
.SYNOPSIS
  Synchronize the downloaded XREA site source to the prepared backup server.

.EXAMPLE
  .\operations\Xrea\Sync-XreaBackup.ps1
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $LocalPath,

    [Parameter()]
    [string] $RemotePath = "/public_html/backup.2415.jp/license",

    [Parameter()]
    [string] $HostName = "s1006.xrea.com",

    [Parameter()]
    [string] $UserName = "tkm10pc4rds",

    [Parameter()]
    [switch] $PreflightOnly
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($LocalPath)) {
    $scriptDirectory = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
    if ([string]::IsNullOrWhiteSpace($scriptDirectory)) {
        throw "Could not determine the folder containing Sync-XreaBackup.ps1. Pass -LocalPath explicitly."
    }
    $LocalPath = [System.IO.Path]::GetFullPath((Join-Path $scriptDirectory '..\..\xrea-source'))
}
$resolvedLocalPath = [System.IO.Path]::GetFullPath($LocalPath)
if (-not (Test-Path -LiteralPath $resolvedLocalPath -PathType Container)) {
    throw "LocalPath must be a folder: $resolvedLocalPath"
}
if ([string]::IsNullOrWhiteSpace($UserName)) {
    $UserName = Read-Host "s1006.xrea.com FTP username"
}
if ([string]::IsNullOrWhiteSpace($UserName)) {
    throw "An FTP username for s1006.xrea.com is required."
}

$assemblyCandidates = @(
    (Join-Path $env:LOCALAPPDATA "Programs\WinSCP\WinSCPnet.dll"),
    (Join-Path $env:ProgramFiles "WinSCP\WinSCPnet.dll"),
    (Join-Path ${env:ProgramFiles(x86)} "WinSCP\WinSCPnet.dll")
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
if (-not $assemblyCandidates) {
    throw "WinSCP was not found. Install WinSCP, then run this script again."
}
$assemblyPath = $assemblyCandidates | Select-Object -First 1
if ($PreflightOnly) {
    Write-Host "Preflight OK. Source: $resolvedLocalPath"
    Write-Host "WinSCP: $assemblyPath"
    Write-Host "Destination: ${HostName}:$RemotePath"
    exit 0
}
Add-Type -Path $assemblyPath

$securePassword = Read-Host "s1006.xrea.com FTP password" -AsSecureString
if ($securePassword.Length -eq 0) {
    throw "An FTP password for s1006.xrea.com is required."
}

$sessionOptions = New-Object WinSCP.SessionOptions -Property @{
    Protocol = [WinSCP.Protocol]::Ftp
    FtpSecure = [WinSCP.FtpSecure]::Explicit
    FtpMode = [WinSCP.FtpMode]::Passive
    HostName = $HostName
    PortNumber = 21
    UserName = $UserName
    SecurePassword = $securePassword
}

$sessionOptions.TlsHostCertificateFingerprint = "9c:fb:c9:21:d2:6f:de:43:43:bc:cb:e2:65:b0:99:e4:20:11:e1:72:bb:26:16:48:d1:3e:30:89:68:6d:d4:c7"

$session = New-Object WinSCP.Session
try {
    Write-Host "Source:      $resolvedLocalPath"
    Write-Host "Destination: ${HostName}:$RemotePath"
    Write-Host "Connecting with explicit FTPS (port 21)..."
    $session.Open($sessionOptions)

    $transferOptions = New-Object WinSCP.TransferOptions
    $transferOptions.TransferMode = [WinSCP.TransferMode]::Binary
    $transferOptions.ResumeSupport.State = [WinSCP.TransferResumeSupportState]::On
    $transferOptions.FileMask = '| fastapi-runtime.json; __pycache__/; *.pyc; *.pyo; .tuti-deploy-backup-*/; .tuti-deploy-stage-*/'
    Write-Host "Synchronizing new and changed files. Remote-only files will be kept."
    $result = $session.SynchronizeDirectories(
        [WinSCP.SynchronizationMode]::Remote,
        $resolvedLocalPath,
        $RemotePath,
        $false,
        $false,
        [WinSCP.SynchronizationCriteria]::Time,
        $transferOptions
    )
    $result.Check()
    Write-Host "Synchronization complete. Files uploaded: $($result.Uploads.Count)"
}
finally {
    $session.Dispose()
    $securePassword.Dispose()
}
