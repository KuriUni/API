<#
.SYNOPSIS
  Downloads the existing XREA site recursively over explicit FTPS using .NET built into Windows.

.EXAMPLE
  .\operations\Xrea\Download-Xrea.ps1
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $LocalPath,

    [Parameter()]
    [string] $RemotePath = "/public_html/2415.jp/license",

    [Parameter()]
    [string] $HostName = "s1004.xrea.com",

    [Parameter()]
    [string] $UserName = "backup1tkmpc"
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($LocalPath)) {
    $LocalPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\xrea-source'))
}

if (-not $UserName) { $UserName = Read-Host "XREA FTP username" }
if (-not $UserName) { throw "An XREA FTP username is required." }

$localRoot = [System.IO.Path]::GetFullPath($LocalPath)
if (Test-Path -LiteralPath $localRoot -PathType Leaf) {
    throw "LocalPath exists as a file: $localRoot"
}
New-Item -ItemType Directory -Path $localRoot -Force | Out-Null
$localRoot = [System.IO.Path]::GetFullPath($localRoot)

function Assert-XreaLocalPathSafe([string] $Path) {
    $root = [System.IO.Path]::GetFullPath($script:localRoot)
    $rootPrefix = if ($root.EndsWith([string][System.IO.Path]::DirectorySeparatorChar)) { $root } else { $root + [System.IO.Path]::DirectorySeparatorChar }
    $current = [System.IO.Path]::GetFullPath($Path)
    if ($current -ne $root -and -not $current.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Remote FTP entry escapes LocalPath: $Path"
    }
    while ($true) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing to download through a link or junction: $current"
            }
        }
        if ($current -eq $root) { break }
        $parent = [System.IO.Directory]::GetParent($current)
        if ($null -eq $parent) { throw "Could not validate LocalPath boundary: $Path" }
        $current = $parent.FullName
    }
}

function Get-XreaLocalChild([string] $BaseDirectory, [string] $Name) {
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name -in @('.', '..') -or $Name -match '[\\/:\x00-\x1f]' -or $Name.EndsWith(' ') -or $Name.EndsWith('.') -or $Name -match '(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$') {
        throw "Refusing unsafe remote FTP filename."
    }
    $child = [System.IO.Path]::GetFullPath((Join-Path $BaseDirectory $Name))
    Assert-XreaLocalPathSafe $child
    return $child
}

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
    $request.KeepAlive = $true
    $request.Timeout = 60000
    $request.ReadWriteTimeout = 60000
    return $request
}

$downloadCount = 0
function Receive-XreaDirectory([string] $RemoteDirectory, [string] $LocalDirectory) {
    Assert-XreaLocalPathSafe $LocalDirectory
    New-Item -ItemType Directory -Path $LocalDirectory -Force | Out-Null
    Assert-XreaLocalPathSafe $LocalDirectory
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
        if ($kind -eq 'd' -and ($name -eq '__pycache__' -or $name -like '.tuti-deploy-backup-*' -or $name -like '.tuti-deploy-stage-*')) { continue }
        if ($kind -ne 'd' -and ($name -eq 'fastapi-runtime.json' -or $name -like '*.pyc' -or $name -like '*.pyo')) { continue }

        $remoteChild = $RemoteDirectory.TrimEnd('/') + '/' + $name
        try { $localChild = Get-XreaLocalChild $LocalDirectory $name }
        catch {
            Write-Warning "Skipping an unsafe FTP filename in $RemoteDirectory."
            continue
        }
        if ($kind -eq 'd') {
            if (Test-Path -LiteralPath $localChild -PathType Leaf) { throw "Remote directory conflicts with a local file: $localChild" }
            Receive-XreaDirectory $remoteChild $localChild
            continue
        }
        if (Test-Path -LiteralPath $localChild -PathType Container) { throw "Remote file conflicts with a local directory: $localChild" }

        $fileRequest = New-XreaRequest $remoteChild ([System.Net.WebRequestMethods+Ftp]::DownloadFile)
        $fileResponse = $fileRequest.GetResponse()
        $temporaryPath = Join-Path $LocalDirectory ('.tuti-download-' + [Guid]::NewGuid().ToString('N') + '.tmp')
        try {
            $inputStream = $fileResponse.GetResponseStream()
            $outputStream = [System.IO.File]::Open($temporaryPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try { $inputStream.CopyTo($outputStream) } finally { $outputStream.Dispose(); $inputStream.Dispose() }
            Assert-XreaLocalPathSafe $localChild
            Move-Item -LiteralPath $temporaryPath -Destination $localChild -Force
        } finally {
            $fileResponse.Dispose()
            if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue }
        }
        $script:downloadCount++
        Write-Verbose "Downloaded $remoteChild"
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
