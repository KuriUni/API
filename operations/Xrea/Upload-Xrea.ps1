<#
.SYNOPSIS
  Uploads a local site folder to XREA using explicit FTPS (TLS on FTP port 21).

.EXAMPLE
  .\operations\Xrea\Upload-Xrea.ps1 -LocalPath .\public -RemotePath /public_html
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $LocalPath = (Get-Location).Path,

    [Parameter()]
    [string] $RemotePath = "/public_html",

    [Parameter()]
    [string] $HostName = "s1004.xrea.com",

    [Parameter()]
    [string] $UserName
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot 'Invoke-XreaDifferentialUpload.ps1')

$resolvedLocalPath = (Resolve-Path -LiteralPath $LocalPath).Path
if (-not (Test-Path -LiteralPath $resolvedLocalPath -PathType Container)) {
    throw "LocalPath must be a folder: $resolvedLocalPath"
}
if ([string]::IsNullOrWhiteSpace($UserName)) {
    $UserName = Read-Host "XREA FTP username"
}
if ([string]::IsNullOrWhiteSpace($UserName)) {
    throw "An XREA FTP username is required."
}

# WinSCP's .NET assembly is installed with WinSCP. The script does not store credentials.
$assemblyCandidates = @(
    (Join-Path $env:ProgramFiles "WinSCP\WinSCPnet.dll"),
    (Join-Path ${env:ProgramFiles(x86)} "WinSCP\WinSCPnet.dll")
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
if (-not $assemblyCandidates) {
    throw "WinSCP was not found. Install WinSCP, then run this script again."
}
Add-Type -Path $assemblyCandidates[0]

$securePassword = Read-Host "XREA FTP password" -AsSecureString
if ($securePassword.Length -eq 0) {
    throw "An XREA FTP password is required."
}

# XREA's published WinSCP instructions use FTP with explicit TLS/SSL on port 21.
$sessionOptions = New-Object WinSCP.SessionOptions -Property @{
    Protocol = [WinSCP.Protocol]::Ftp
    FtpSecure = [WinSCP.FtpSecure]::Explicit
    FtpMode = [WinSCP.FtpMode]::Passive
    HostName = $HostName
    PortNumber = 21
    UserName = $UserName
    SecurePassword = $securePassword
}

$fingerprint = Read-Host "TLS certificate SHA-256 fingerprint (from a trusted WinSCP connection)"
if ([string]::IsNullOrWhiteSpace($fingerprint)) {
    throw "A TLS certificate fingerprint is required to verify the server securely."
}
$sessionOptions.TlsHostCertificateFingerprint = $fingerprint.Trim()

$session = New-Object WinSCP.Session
try {
    Write-Host "Connecting to $HostName using explicit FTPS..."
    $session.Open($sessionOptions)

    $transferOptions = New-Object WinSCP.TransferOptions
    $transferOptions.TransferMode = [WinSCP.TransferMode]::Binary
    $transferOptions.ResumeSupport.State = [WinSCP.TransferResumeSupportState]::On
    $remote = $RemotePath.TrimEnd('/') + '/'

    Write-Host "Uploading changed files from '$resolvedLocalPath' to '$remote'..."
    $result = Invoke-XreaDifferentialUpload -Session $session -LocalRoot $resolvedLocalPath -RemoteRoot $remote -StateKey "$HostName|$UserName|$remote" -TransferOptions $transferOptions
    Write-Host "Differential upload complete. Files uploaded: $($result.Uploaded); local files checked: $($result.CheckedLocal). Remote directory listings were not scanned."
}
finally {
    $session.Dispose()
    $securePassword.Dispose()
}
