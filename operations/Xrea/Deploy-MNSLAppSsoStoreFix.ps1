[CmdletBinding()]
param(
    [string] $SourceFile,
    [string] $BackupRoot,
    [ValidateSet('All','XreaOnly')]
    [string] $DeploymentScope = 'All'
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($SourceFile)) {
    $projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $SourceFile = Join-Path $projectRoot 'xrea-source\app_sso.py'
}
if ([string]::IsNullOrWhiteSpace($BackupRoot)) {
    $projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $BackupRoot = Join-Path $projectRoot ('deploy-backups\mnsl-app-sso-store-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$source = (Resolve-Path -LiteralPath $SourceFile).Path
$sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
$winscpCandidates = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCPnet.dll'),
    (Join-Path $env:ProgramFiles 'WinSCP\WinSCPnet.dll'),
    (Join-Path ${env:ProgramFiles(x86)} 'WinSCP\WinSCPnet.dll')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
if (-not $winscpCandidates) { throw 'WinSCP .NET library was not found.' }
Add-Type -Path ($winscpCandidates | Select-Object -First 1)

$targets = @(
    [pscustomobject]@{ Name='Primary'; Host='s1004.xrea.com'; User='backup1tkmpc'; Remote='/public_html/2415.jp/license'; Fingerprint='9c:fb:c9:21:d2:6f:de:43:43:bc:cb:e2:65:b0:99:e4:20:11:e1:72:bb:26:16:48:d1:3e:30:89:68:6d:d4:c7'; Health='https://2415.jp/license/_fastapi/health' },
    [pscustomobject]@{ Name='Backup'; Host='s1006.xrea.com'; User='tkm10pc4rds'; Remote='/public_html/backup.2415.jp/license'; Fingerprint='9c:fb:c9:21:d2:6f:de:43:43:bc:cb:e2:65:b0:99:e4:20:11:e1:72:bb:26:16:48:d1:3e:30:89:68:6d:d4:c7'; Health='https://backup.2415.jp/license/_fastapi/health' },
    [pscustomobject]@{ Name='Main'; Host='v2006.coreserver.jp'; User='main@sso.2415.jp'; Remote='/'; Fingerprint='20:9c:38:e5:92:50:52:0f:d1:9b:6c:69:e3:2d:5f:cb:b6:14:28:ed:bf:5f:34:f3:74:93:69:8d:46:a1:b3:f4'; Health='https://main.2415.jp/license/_fastapi/health' }
)
if ($DeploymentScope -eq 'XreaOnly') { $targets = @($targets | Where-Object Name -In @('Primary','Backup')) }

function New-ManualCredential([string] $UserName, [string] $HostName) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "FTPS deployment credential - $HostName"
    $form.StartPosition = 'CenterScreen'; $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false; $form.MinimizeBox = $false; $form.TopMost = $true
    $form.ClientSize = New-Object System.Drawing.Size(460, 150)
    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Enter the FTP password for $UserName at $HostName. It will not be saved."
    $label.Location = New-Object System.Drawing.Point(16, 16); $label.Size = New-Object System.Drawing.Size(430, 40)
    $form.Controls.Add($label)
    $box = New-Object System.Windows.Forms.TextBox
    $box.Location = New-Object System.Drawing.Point(18, 62); $box.Size = New-Object System.Drawing.Size(424, 25)
    $box.UseSystemPasswordChar = $true; $form.Controls.Add($box)
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'Continue'; $ok.Location = New-Object System.Drawing.Point(260, 105); $ok.Size = New-Object System.Drawing.Size(86, 28)
    $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK; $form.Controls.Add($ok)
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(356, 105); $cancel.Size = New-Object System.Drawing.Size(86, 28)
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $form.Controls.Add($cancel)
    $form.AcceptButton = $ok; $form.CancelButton = $cancel
    try {
        if ($form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK -or [string]::IsNullOrEmpty($box.Text)) { throw 'FTPS credential entry cancelled.' }
        $secure = ConvertTo-SecureString -String $box.Text -AsPlainText -Force
        return New-Object System.Management.Automation.PSCredential($UserName, $secure)
    } finally { $box.Clear(); $form.Dispose() }
}

function New-SessionOptions($Target, $Credential) {
    return New-Object WinSCP.SessionOptions -Property @{
        Protocol=[WinSCP.Protocol]::Ftp; FtpSecure=[WinSCP.FtpSecure]::Explicit
        FtpMode=[WinSCP.FtpMode]::Passive; HostName=$Target.Host; PortNumber=21
        UserName=$Target.User; SecurePassword=$Credential.Password
        TlsHostCertificateFingerprint=$Target.Fingerprint
    }
}

$credentialMap = @{}
$credentialPath = Join-Path $env:LOCALAPPDATA 'XreaDeploy\credentials.xml'
if (Test-Path -LiteralPath $credentialPath -PathType Leaf) {
    try {
        $saved = Import-Clixml -LiteralPath $credentialPath
        foreach ($name in @('Primary','Backup')) {
            $entry = if ($saved -is [System.Collections.IDictionary]) { $saved[$name] } else { $saved.$name }
            if ($entry -is [System.Management.Automation.PSCredential]) { $credentialMap[$name] = $entry }
        }
    } catch { throw 'Could not read the current-user DPAPI XREA deployment credentials.' }
}
foreach ($target in $targets | Where-Object Name -In @('Primary','Backup')) {
    if (-not $credentialMap.ContainsKey($target.Name) -or $credentialMap[$target.Name].UserName -ne $target.User) {
        $credentialMap[$target.Name] = New-ManualCredential $target.User $target.Host
    }
}
if ($DeploymentScope -eq 'All') { $credentialMap['Main'] = New-ManualCredential $targets[2].User $targets[2].Host }

New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
$backupRootResolved = (Resolve-Path -LiteralPath $BackupRoot).Path
$backups = @{}
$uploaded = [System.Collections.Generic.List[object]]::new()
$records = [System.Collections.Generic.List[object]]::new()

try {
    # Back up and verify every live copy before changing any node.
    foreach ($target in $targets) {
        $remoteFile = $target.Remote.TrimEnd('/') + '/app_sso.py'
        $localDir = Join-Path $backupRootResolved $target.Name
        New-Item -ItemType Directory -Path $localDir -Force | Out-Null
        $localBackup = Join-Path $localDir 'app_sso.py'
        $session = New-Object WinSCP.Session
        try {
            $session.Open((New-SessionOptions $target $credentialMap[$target.Name]))
            if (-not $session.FileExists($remoteFile)) { throw "Remote source file is missing on $($target.Name)." }
            $result = $session.GetFiles($remoteFile, $localDir + '\', $false)
            $result.Check()
        } finally { $session.Dispose() }
        if (-not (Test-Path -LiteralPath $localBackup -PathType Leaf)) { throw "Backup download failed for $($target.Name)." }
        $backupHash = (Get-FileHash -LiteralPath $localBackup -Algorithm SHA256).Hash.ToLowerInvariant()
        $backups[$target.Name] = $localBackup
        $records.Add([pscustomobject]@{ node=$target.Name; backup_sha256=$backupHash; deployed_sha256=$sourceHash; verified=$false })
        Write-Host "Backed up $($target.Name) app_sso.py ($backupHash)"
    }

    foreach ($target in $targets) {
        $remoteFile = $target.Remote.TrimEnd('/') + '/app_sso.py'
        $session = New-Object WinSCP.Session
        $verifyDir = Join-Path (Join-Path $backupRootResolved $target.Name) 'verify'
        New-Item -ItemType Directory -Path $verifyDir -Force | Out-Null
        try {
            $session.Open((New-SessionOptions $target $credentialMap[$target.Name]))
            $uploaded.Add($target)
            $result = $session.PutFiles($source, $target.Remote.TrimEnd('/') + '/', $false)
            $result.Check()
            $result = $session.GetFiles($remoteFile, $verifyDir + '\', $false)
            $result.Check()
            $downloaded = Join-Path $verifyDir 'app_sso.py'
            $remoteHash = (Get-FileHash -LiteralPath $downloaded -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($remoteHash -ne $sourceHash) { throw "Uploaded file hash mismatch on $($target.Name)." }
            $record = $records | Where-Object node -eq $target.Name | Select-Object -First 1
            $record.verified = $true
            Write-Host "Verified $($target.Name) app_sso.py ($remoteHash)"
        } finally { $session.Dispose() }
    }

    $health = foreach ($target in $targets) {
        $response = Invoke-WebRequest -Uri $target.Health -Method Get -TimeoutSec 20 -UseBasicParsing
        $payload = $null
        try { $payload = $response.Content | ConvertFrom-Json } catch {}
        [pscustomobject]@{ node=$target.Name; status=[int]$response.StatusCode; ready=([int]$response.StatusCode -eq 200 -and $payload.success -eq $true) }
    }
    if (@($health | Where-Object { -not $_.ready }).Count -gt 0) { throw 'Post-deployment health check failed.' }
    $manifest = [pscustomobject]@{ created_utc=[DateTime]::UtcNow.ToString('o'); source_sha256=$sourceHash; nodes=$records; health=$health }
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $backupRootResolved 'deployment-manifest.json') -Encoding utf8
    Write-Host "All selected nodes are healthy and have the same verified source hash."
} catch {
    $failure = $_.Exception.Message
    $rollbackErrors = [System.Collections.Generic.List[string]]::new()
    for ($index = $uploaded.Count - 1; $index -ge 0; $index--) {
        $target = $uploaded[$index]
        try {
            $session = New-Object WinSCP.Session
            try {
                $session.Open((New-SessionOptions $target $credentialMap[$target.Name]))
                $result = $session.PutFiles($backups[$target.Name], $target.Remote.TrimEnd('/') + '/', $false)
                $result.Check()
                $rollbackVerify = Join-Path (Join-Path $backupRootResolved $target.Name) 'rollback-verify'
                New-Item -ItemType Directory -Path $rollbackVerify -Force | Out-Null
                $result = $session.GetFiles($target.Remote.TrimEnd('/') + '/app_sso.py', $rollbackVerify + '\', $false)
                $result.Check()
                $restored = Join-Path $rollbackVerify 'app_sso.py'
                $expected = (Get-FileHash -LiteralPath $backups[$target.Name] -Algorithm SHA256).Hash
                $actual = (Get-FileHash -LiteralPath $restored -Algorithm SHA256).Hash
                if ($actual -ne $expected) { throw 'Rollback verification hash mismatch.' }
            } finally { $session.Dispose() }
        } catch { $rollbackErrors.Add($target.Name) }
    }
    if ($rollbackErrors.Count) { throw "Deployment failed ($failure); rollback also failed for: $($rollbackErrors -join ', '). Backups are at $backupRootResolved" }
    if ($uploaded.Count -eq 0) { throw "Deployment failed before changing any node: $failure. No remote files were changed." }
    throw "Deployment failed and changed nodes were rolled back: $failure. Backups are at $backupRootResolved"
} finally {
    foreach ($credential in $credentialMap.Values) { if ($credential.Password) { $credential.Password.Dispose() } }
}

try { & (Join-Path $PSScriptRoot '..\Prune-DeployBackups.ps1') } catch { Write-Warning "Deployment succeeded, but backup retention cleanup failed: $($_.Exception.Message)" }
