<#
.SYNOPSIS
  Downloads the existing XREA site recursively over explicit FTPS using .NET built into Windows.

.EXAMPLE
  .\Download-Xrea.ps1
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $LocalPath = (Join-Path (Get-Location).Path "xrea-source"),

    [Parameter()]
    [string] $RemotePath = "/public_html/2415.jp/license",

    [Parameter()]
    [string] $HostName = "s1004.xrea.com",

    [Parameter()]
    [string] $UserName = "backup1tkmpc"
)

$ErrorActionPreference = "Stop"

if (-not $UserName) { $UserName = Read-Host "XREA FTP username" }
if (-not $UserName) { throw "An XREA FTP username is required." }

$localRoot = [System.IO.Path]::GetFullPath($LocalPath)
if (Test-Path -LiteralPath $localRoot -PathType Leaf) {
    throw "LocalPath exists as a file: $localRoot"
}
New-Item -ItemType Directory -Path $localRoot -Force | Out-Null

$securePassword = Read-Host "XREA FTP password" -AsSecureString
if ($securePassword.Length -eq 0) { throw "An XREA FTP password is required." }
$credential = [System.Net.NetworkCredential]::new($UserName, $securePassword)

function ConvertTo-FtpUri([string] $Path) {
    $segments = $Path.Trim('/').Split('/') | ForEach-Object { [Uri]::EscapeDataString($_) }
    return "ftp://${HostName}/$($segments -join '/')"
}

function New-XreaRequest([string] $Path, [string] $Method) {
    $request = [System.Net.FtpWebRequest]::Create((ConvertTo-FtpUri $Path))
    $request.Method = $Method
    $request.Credentials = $credential
    $request.EnableSsl = $true
    $request.UsePassive = $true
    $request.UseBinary = $true
    $request.KeepAlive = $false
    $request.Timeout = 60000
    $request.ReadWriteTimeout = 60000
    return $request
}

$downloadCount = 0
function Receive-XreaDirectory([string] $RemoteDirectory, [string] $LocalDirectory) {
    New-Item -ItemType Directory -Path $LocalDirectory -Force | Out-Null
    $request = New-XreaRequest $RemoteDirectory ([System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails)
    $response = $request.GetResponse()
    try {
        $reader = [System.IO.StreamReader]::new($response.GetResponseStream())
        try { $lines = $reader.ReadToEnd() -split "`r?`n" } finally { $reader.Dispose() }
    } finally { $response.Dispose() }

    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        # XREA returns Unix-style LIST rows. Split into nine columns so names may contain spaces.
        $columns = $line.Trim() -split '\s+', 9
        if ($columns.Count -lt 9 -or $columns[0].Length -eq 0) {
            Write-Warning "Skipping an unrecognized FTP listing row: $line"
            continue
        }
        $kind = $columns[0][0]
        $name = $columns[8]
        if ($name -eq '.' -or $name -eq '..' -or $kind -eq 'l') { continue }

        $remoteChild = $RemoteDirectory.TrimEnd('/') + '/' + $name
        $localChild = Join-Path $LocalDirectory $name
        if ($kind -eq 'd') {
            Receive-XreaDirectory $remoteChild $localChild
            continue
        }

        $fileRequest = New-XreaRequest $remoteChild ([System.Net.WebRequestMethods+Ftp]::DownloadFile)
        $fileResponse = $fileRequest.GetResponse()
        try {
            $inputStream = $fileResponse.GetResponseStream()
            $outputStream = [System.IO.File]::Create($localChild)
            try { $inputStream.CopyTo($outputStream) } finally { $outputStream.Dispose(); $inputStream.Dispose() }
        } finally { $fileResponse.Dispose() }
        $script:downloadCount++
        Write-Host "Downloaded $remoteChild"
    }
}

try {
    Write-Host "Connecting to $HostName with explicit FTPS (port 21)..."
    Receive-XreaDirectory $RemotePath $localRoot
    Write-Host "Download complete. Files transferred: $downloadCount"
    Write-Host "Local source: $localRoot"
} finally {
    $securePassword.Dispose()
}
