[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$base = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$source = Join-Path $base 'TUTI-Help.html'
$credentialFile = Join-Path $env:LOCALAPPDATA 'XreaDeploy\credentials.xml'
$remoteDirectory = '/public_html/2415.jp'
$remoteFile = "$remoteDirectory/TUTI-Help.html"
$fingerprint = '9c:fb:c9:21:d2:6f:de:43:43:bc:cb:e2:65:b0:99:e4:20:11:e1:72:bb:26:16:48:d1:3e:30:89:68:6d:d4:c7'

if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Help file not found: $source" }
if (-not (Test-Path -LiteralPath $credentialFile -PathType Leaf)) { throw 'Saved DPAPI XREA credentials were not found. Run Deploy-Xrea.ps1 once to save the Primary credential.' }
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

$backupDirectory = Join-Path $base ('deploy-backups\help-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
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
    if (-not $session.FileExists($remoteFile)) { throw "Published help page was not found: $remoteFile" }

    $backupTransfer = $session.GetFiles($remoteFile, $backupDirectory + '\', $false)
    $backupTransfer.Check()
    $backupFile = Join-Path $backupDirectory 'TUTI-Help.html'
    if (-not (Test-Path -LiteralPath $backupFile -PathType Leaf)) { throw 'Could not save the previous published help page.' }

    $transferOptions = New-Object WinSCP.TransferOptions
    $transferOptions.TransferMode = [WinSCP.TransferMode]::Binary
    $transferOptions.ResumeSupport.State = [WinSCP.TransferResumeSupportState]::On
    $upload = $session.PutFiles($source, $remoteDirectory + '/', $false, $transferOptions)
    $upload.Check()

    $remoteInfo = $session.GetFileInfo($remoteFile)
    $localLength = (Get-Item -LiteralPath $source).Length
    if ($remoteInfo.Length -ne $localLength) {
        throw "Uploaded file size does not match. Local=$localLength Remote=$($remoteInfo.Length)"
    }
    Write-Host "Deployed: https://2415.jp/TUTI-Help.html"
    Write-Host "Bytes verified: $localLength"
    Write-Host "Previous version backup: $backupFile"
}
finally {
    $session.Dispose()
    $credential = $null
    $credentials = $null
}

try { & (Join-Path $PSScriptRoot '..\Prune-DeployBackups.ps1') -Keep 3 } catch { Write-Warning "Deployment succeeded, but backup retention cleanup failed: $($_.Exception.Message)" }
