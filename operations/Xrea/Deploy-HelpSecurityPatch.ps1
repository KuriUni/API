[CmdletBinding()]
param(
    [ValidateSet('Both', 'Primary', 'Backup')]
    [string] $Target = 'Both'
)

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$credentialFile = Join-Path $env:LOCALAPPDATA 'XreaDeploy\credentials.xml'
$backupRoot = Join-Path $projectRoot ('deploy-backups\help-security-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$fingerprint = '9c:fb:c9:21:d2:6f:de:43:43:bc:cb:e2:65:b0:99:e4:20:11:e1:72:bb:26:16:48:d1:3e:30:89:68:6d:d4:c7'

if (-not (Test-Path -LiteralPath $credentialFile -PathType Leaf)) { throw 'Saved DPAPI XREA credentials were not found.' }
$localFiles = @(
    [pscustomobject]@{ Name = 'admin-help-content.json'; Path = (Join-Path $projectRoot 'xrea-source\admin-help-content.json'); RemoteSubdir = 'license'; RequiredRemote = $false },
    [pscustomobject]@{ Name = 'admin_api_handlers.py'; Path = (Join-Path $projectRoot 'xrea-source\admin_api_handlers.py'); RemoteSubdir = 'license'; RequiredRemote = $true },
    [pscustomobject]@{ Name = 'TUTI-Help.html'; Path = (Join-Path $projectRoot 'TUTI-Help.html'); RemoteSubdir = ''; RequiredRemote = $false }
)
foreach ($file in $localFiles) {
    if (-not (Test-Path -LiteralPath $file.Path -PathType Leaf)) { throw "Required deployment file not found: $($file.Path)" }
}

$assemblyCandidates = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCPnet.dll'),
    (Join-Path $env:ProgramFiles 'WinSCP\WinSCPnet.dll'),
    (Join-Path ${env:ProgramFiles(x86)} 'WinSCP\WinSCPnet.dll')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
if (-not $assemblyCandidates) { throw 'WinSCP .NET library was not found.' }
Add-Type -Path ($assemblyCandidates | Select-Object -First 1)

$allCredentials = Import-Clixml -LiteralPath $credentialFile
$targets = @(
    [pscustomobject]@{ Name = 'Primary'; Host = 's1004.xrea.com'; User = 'backup1tkmpc'; WebRoot = '/public_html/2415.jp'; LicenseRoot = '/public_html/2415.jp/license' },
    [pscustomobject]@{ Name = 'Backup'; Host = 's1006.xrea.com'; User = 'tkm10pc4rds'; WebRoot = '/public_html/backup.2415.jp'; LicenseRoot = '/public_html/backup.2415.jp/license' }
) | Where-Object { $Target -eq 'Both' -or $_.Name -eq $Target }

function Get-SavedCredential($node) {
    if ($allCredentials -is [System.Collections.IDictionary]) { $credential = $allCredentials[$node.Name] }
    else { $credential = $allCredentials.($node.Name) }
    if (-not ($credential -is [System.Management.Automation.PSCredential]) -or $credential.UserName -ne $node.User) {
        throw "Saved DPAPI credential is missing or has the wrong FTP user for $($node.Name)."
    }
    return $credential
}

function Get-RemotePath($node, $file) {
    if ($file.RemoteSubdir) { return $node.LicenseRoot + '/' + $file.Name }
    return $node.WebRoot + '/' + $file.Name
}

$transferOptions = New-Object WinSCP.TransferOptions
$transferOptions.TransferMode = [WinSCP.TransferMode]::Binary
$transferOptions.ResumeSupport.State = [WinSCP.TransferResumeSupportState]::On
$sessionId = [guid]::NewGuid().ToString('N')
$deploymentPlan = @()
$completedNodes = @()

try {
    # Connect and back up every existing target before changing either server.
    foreach ($node in $targets) {
        $credential = Get-SavedCredential $node
        $session = New-Object WinSCP.Session
        try {
            $options = New-Object WinSCP.SessionOptions -Property @{
                Protocol = [WinSCP.Protocol]::Ftp
                FtpSecure = [WinSCP.FtpSecure]::Explicit
                FtpMode = [WinSCP.FtpMode]::Passive
                HostName = $node.Host
                PortNumber = 21
                UserName = $credential.UserName
                SecurePassword = $credential.Password
                TlsHostCertificateFingerprint = $fingerprint
            }
            $session.Open($options)
            foreach ($file in $localFiles) {
                $remotePath = Get-RemotePath $node $file
                $exists = $session.FileExists($remotePath)
                if ($file.RequiredRemote -and -not $exists) { throw "Expected live file is missing: $($node.Name):$remotePath" }
                if ($file.RemoteSubdir -eq '' -and -not $exists) { continue }
                $deploymentPlan += [pscustomobject]@{ Node = $node; File = $file; RemotePath = $remotePath; Exists = $exists }
                if ($exists) {
                    $nodeBackup = Join-Path $backupRoot $node.Name
                    New-Item -ItemType Directory -Path $nodeBackup -Force | Out-Null
                    $download = $session.GetFiles($remotePath, $nodeBackup + '\', $false)
                    $download.Check()
                    if (-not (Test-Path -LiteralPath (Join-Path $nodeBackup $file.Name) -PathType Leaf)) {
                        throw "Could not back up $($node.Name):$($file.Name)"
                    }
                }
            }
        }
        finally { $session.Dispose(); $credential = $null }
    }

    foreach ($node in $targets) {
        $credential = Get-SavedCredential $node
        $session = New-Object WinSCP.Session
        $staged = @()
        try {
            $options = New-Object WinSCP.SessionOptions -Property @{
                Protocol = [WinSCP.Protocol]::Ftp
                FtpSecure = [WinSCP.FtpSecure]::Explicit
                FtpMode = [WinSCP.FtpMode]::Passive
                HostName = $node.Host
                PortNumber = 21
                UserName = $credential.UserName
                SecurePassword = $credential.Password
                TlsHostCertificateFingerprint = $fingerprint
            }
            $session.Open($options)
            $nodePlan = @($deploymentPlan | Where-Object { $_.Node.Name -eq $node.Name })
            # Place private data first, then its authenticated server handler, and publish the link last.
            $orderedPlan = @($nodePlan | Sort-Object @{ Expression = { if ($_.File.Name -eq 'admin-help-content.json') { 0 } elseif ($_.File.Name -eq 'admin_api_handlers.py') { 1 } else { 2 } } })
            foreach ($item in $orderedPlan) {
                $remoteDirectory = [System.IO.Path]::GetDirectoryName($item.RemotePath.Replace('/', '\')).Replace('\', '/')
                $stagePath = $remoteDirectory + '/.tuti-stage-' + $sessionId + '-' + $item.File.Name
                $upload = $session.PutFiles($item.File.Path, $stagePath, $false, $transferOptions)
                $upload.Check()
                $staged += [pscustomobject]@{ Stage = $stagePath; Final = $item.RemotePath; Item = $item }
            }
            foreach ($item in $staged) {
                if ($session.FileExists($item.Final)) { $session.RemoveFile($item.Final) }
                $session.MoveFile($item.Stage, $item.Final)
                $remoteInfo = $session.GetFileInfo($item.Final)
                $localLength = (Get-Item -LiteralPath $item.Item.File.Path).Length
                if ($remoteInfo.Length -ne $localLength) { throw "Size verification failed for $($node.Name):$($item.Item.File.Name)" }
            }
            Write-Host "$($node.Name): updated $($staged.Count) files; local backups: $(Join-Path $backupRoot $node.Name)"
        }
        catch {
            foreach ($item in $staged) {
                try { if ($session.FileExists($item.Stage)) { $session.RemoveFile($item.Stage) } } catch {}
                try {
                    $backupFile = Join-Path (Join-Path $backupRoot $node.Name) $item.Item.File.Name
                    if ($item.Item.Exists -and (Test-Path -LiteralPath $backupFile -PathType Leaf)) {
                        if ($session.FileExists($item.Final)) { $session.RemoveFile($item.Final) }
                        $restore = $session.PutFiles($backupFile, $item.Final, $false, $transferOptions)
                        $restore.Check()
                    } elseif (-not $item.Item.Exists -and $session.FileExists($item.Final)) {
                        $session.RemoveFile($item.Final)
                    }
                } catch {
                    Write-Warning "Could not automatically restore $($node.Name):$($item.Item.File.Name): $($_.Exception.Message)"
                }
            }
            throw
        }
        finally { $session.Dispose(); $credential = $null }
        $completedNodes += $node.Name
    }

    Write-Host "Deployment complete. Backups are in: $backupRoot"
}
catch {
    foreach ($nodeName in $completedNodes) {
        $node = $targets | Where-Object { $_.Name -eq $nodeName } | Select-Object -First 1
        $credential = Get-SavedCredential $node
        $session = New-Object WinSCP.Session
        try {
            $options = New-Object WinSCP.SessionOptions -Property @{
                Protocol = [WinSCP.Protocol]::Ftp
                FtpSecure = [WinSCP.FtpSecure]::Explicit
                FtpMode = [WinSCP.FtpMode]::Passive
                HostName = $node.Host
                PortNumber = 21
                UserName = $credential.UserName
                SecurePassword = $credential.Password
                TlsHostCertificateFingerprint = $fingerprint
            }
            $session.Open($options)
            foreach ($item in @($deploymentPlan | Where-Object { $_.Node.Name -eq $node.Name })) {
                $backupFile = Join-Path (Join-Path $backupRoot $node.Name) $item.File.Name
                if ($item.Exists -and (Test-Path -LiteralPath $backupFile -PathType Leaf)) {
                    if ($session.FileExists($item.RemotePath)) { $session.RemoveFile($item.RemotePath) }
                    $restore = $session.PutFiles($backupFile, $item.RemotePath, $false, $transferOptions)
                    $restore.Check()
                } elseif (-not $item.Exists -and $session.FileExists($item.RemotePath)) {
                    $session.RemoveFile($item.RemotePath)
                }
            }
            Write-Warning "Rolled back previously completed node $nodeName after a later deployment error."
        }
        catch { Write-Warning "Automatic rollback failed for ${nodeName}: $($_.Exception.Message)" }
        finally { $session.Dispose(); $credential = $null }
    }
    throw
}
finally {
    $allCredentials = $null
    $credential = $null
}

try { & (Join-Path $PSScriptRoot '..\Prune-DeployBackups.ps1') } catch { Write-Warning "Deployment succeeded, but backup retention cleanup failed: $($_.Exception.Message)" }
