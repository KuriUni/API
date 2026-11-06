[CmdletBinding()]
param([switch] $ResetCredential)

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$sourceRoot = Join-Path $projectRoot 'sso-ftp-source-20261103-002438'
$hostName = 'v2006.coreserver.jp'
$userName = 'main@sso.2415.jp'
$fingerprint = '20:9c:38:e5:92:50:52:0f:d1:9b:6c:69:e3:2d:5f:cb:b6:14:28:ed:bf:5f:34:f3:74:93:69:8d:46:a1:b3:f4'
$healthUrl = 'https://sso.2415.jp/healthz'
$credentialPath = Join-Path $env:LOCALAPPDATA 'XreaDeploy\credentials.xml'
$backupRoot = Join-Path $projectRoot ('deploy-backups\sso-onboarding-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$files = @(
    [pscustomobject]@{ Name='server.py'; Local=(Join-Path $sourceRoot 'server.py'); Remote='/server.py' },
    [pscustomobject]@{ Name='.htaccess'; Local=(Join-Path $sourceRoot '.htaccess'); Remote='/.htaccess' }
)

foreach ($file in $files) { if (-not (Test-Path -LiteralPath $file.Local -PathType Leaf)) { throw "SSO source missing: $($file.Name)" } }
$dll = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCPnet.dll'),
    (Join-Path $env:ProgramFiles 'WinSCP\WinSCPnet.dll'),
    (Join-Path ${env:ProgramFiles(x86)} 'WinSCP\WinSCPnet.dll')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
if (-not $dll) { throw 'WinSCP .NET library was not found.' }
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -Path $dll

$credentialMap = @{}
if (Test-Path -LiteralPath $credentialPath -PathType Leaf) {
    try {
        $saved = Import-Clixml -LiteralPath $credentialPath
        foreach ($name in @('Primary','Backup','Main')) {
            $entry = if ($saved -is [System.Collections.IDictionary]) { $saved[$name] } else { $saved.$name }
            if ($entry -is [System.Management.Automation.PSCredential]) { $credentialMap[$name] = $entry }
        }
    } catch { throw 'Could not read the current-user DPAPI credential file.' }
}
if ($ResetCredential) { $credentialMap.Remove('Main') }
$credential = $credentialMap['Main']
if (-not $credential -or $credential.UserName -ne $userName) {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'SSO FTPS credential'; $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'; $form.MaximizeBox = $false; $form.MinimizeBox = $false
    $form.TopMost = $true; $form.ClientSize = New-Object System.Drawing.Size(500, 170)
    $label = New-Object System.Windows.Forms.Label
    $label.Text = "FTPS: $hostName`r`nFTP user: $userName`r`nPassword is saved encrypted with Windows DPAPI for this Windows user."
    $label.Location = New-Object System.Drawing.Point(16, 12); $label.Size = New-Object System.Drawing.Size(468, 55); $form.Controls.Add($label)
    $box = New-Object System.Windows.Forms.TextBox
    $box.Location = New-Object System.Drawing.Point(18, 75); $box.Size = New-Object System.Drawing.Size(466, 25)
    $box.UseSystemPasswordChar = $true; $form.Controls.Add($box)
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'Save and deploy'; $ok.Location = New-Object System.Drawing.Point(350, 120); $ok.Size = New-Object System.Drawing.Size(134, 30)
    $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK; $form.Controls.Add($ok)
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(260, 120); $cancel.Size = New-Object System.Drawing.Size(80, 30)
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $form.Controls.Add($cancel)
    $form.AcceptButton = $ok; $form.CancelButton = $cancel
    try {
        if ($form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK -or [string]::IsNullOrEmpty($box.Text)) { throw 'Credential entry cancelled.' }
        $secure = ConvertTo-SecureString -String $box.Text -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($userName, $secure)
        $credentialMap['Main'] = $credential
        $directory = Split-Path -Parent $credentialPath
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
        # Export-Clixml protects SecureString with Windows DPAPI for this user/profile.
        $credentialMap | Export-Clixml -LiteralPath $credentialPath -Force
    } finally { $box.Clear(); $form.Dispose() }
}

New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
$sourceHashes = @{}
foreach ($file in $files) { $sourceHashes[$file.Name] = (Get-FileHash -LiteralPath $file.Local -Algorithm SHA256).Hash.ToLowerInvariant() }
$session = New-Object WinSCP.Session
$backups = @{}
$uploaded = [System.Collections.Generic.List[object]]::new()
try {
    $options = New-Object WinSCP.SessionOptions -Property @{
        Protocol=[WinSCP.Protocol]::Ftp; FtpSecure=[WinSCP.FtpSecure]::Explicit
        FtpMode=[WinSCP.FtpMode]::Passive; HostName=$hostName; PortNumber=21
        UserName=$userName; SecurePassword=$credential.Password
        TlsHostCertificateFingerprint=$fingerprint
    }
    $session.Open($options)
    foreach ($file in $files) {
        $localBackup = Join-Path $backupRoot $file.Name
        $session.GetFiles($file.Remote, $localBackup, $false).Check()
        $backups[$file.Name] = $localBackup
    }
    foreach ($file in $files) {
        $session.PutFiles($file.Local, $file.Remote, $false).Check()
        $uploaded.Add($file)
        $verifyPath = Join-Path $backupRoot ('verify-' + $file.Name.TrimStart('.'))
        $session.GetFiles($file.Remote, $verifyPath, $false).Check()
        $remoteHash = (Get-FileHash -LiteralPath $verifyPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($remoteHash -ne $sourceHashes[$file.Name]) { throw "Remote SHA-256 mismatch for $($file.Name)." }
    }
    $health = Invoke-WebRequest -Uri $healthUrl -TimeoutSec 30 -UseBasicParsing
    if ([int]$health.StatusCode -ne 200 -or -not ($health.Content | ConvertFrom-Json).ok) { throw 'SSO health check did not report ready.' }
    [pscustomobject]@{ status='deployed'; server_py_sha256=$sourceHashes['server.py']; htaccess_sha256=$sourceHashes['.htaccess']; health_status=[int]$health.StatusCode; backup=$backupRoot }
}
catch {
    $failure = $_.Exception.Message
    $rollbackErrors = @()
    for ($index = $uploaded.Count - 1; $index -ge 0; $index--) {
        $file = $uploaded[$index]
        try {
            $session.PutFiles($backups[$file.Name], $file.Remote, $false).Check()
            $verifyPath = Join-Path $backupRoot ('rollback-' + $file.Name.TrimStart('.'))
            $session.GetFiles($file.Remote, $verifyPath, $false).Check()
            $expected = (Get-FileHash -LiteralPath $backups[$file.Name] -Algorithm SHA256).Hash.ToLowerInvariant()
            if ((Get-FileHash -LiteralPath $verifyPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Rollback SHA-256 mismatch.' }
        } catch { $rollbackErrors += $file.Name }
    }
    if ($rollbackErrors.Count) { throw "SSO deployment failed ($failure); rollback verification failed for: $($rollbackErrors -join ', '). Backup: $backupRoot" }
    throw "SSO deployment failed: $failure. Uploaded files were restored from backup. Backup: $backupRoot"
}
finally { $session.Dispose(); if ($null -ne $credential) { $credential.Password.Dispose() } }
