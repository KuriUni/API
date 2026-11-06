[CmdletBinding()]
param([switch] $ConsolePassword)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$hostName = 'v2006.coreserver.jp'
$userName = 'main@sso.2415.jp'
# The FTP account is jailed to its website's public_html. The server's physical
# /home/.../public_html path is therefore exposed as / within this FTP session.
$remoteRoot = '/'
$fingerprint = '20:9c:38:e5:92:50:52:0f:d1:9b:6c:69:e3:2d:5f:cb:b6:14:28:ed:bf:5f:34:f3:74:93:69:8d:46:a1:b3:f4'
$assemblyCandidates = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCPnet.dll'),
    (Join-Path $env:ProgramFiles 'WinSCP\WinSCPnet.dll'),
    (Join-Path ${env:ProgramFiles(x86)} 'WinSCP\WinSCPnet.dll')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
if (-not $assemblyCandidates) {
    [void][System.Windows.Forms.MessageBox]::Show('WinSCP .NET library was not found.', 'SSO FTP', 'OK', 'Error')
    exit 1
}
Add-Type -Path ($assemblyCandidates | Select-Object -First 1)

$credentialForm = New-Object System.Windows.Forms.Form
$credentialForm.Text = 'SSO FTP connection'
$credentialForm.StartPosition = 'CenterScreen'
$credentialForm.FormBorderStyle = 'FixedDialog'
$credentialForm.MaximizeBox = $false
$credentialForm.MinimizeBox = $false
$credentialForm.TopMost = $true
$credentialForm.ClientSize = New-Object System.Drawing.Size(480, 180)

$serverLabel = New-Object System.Windows.Forms.Label
$serverLabel.Text = "Explicit FTPS: $hostName`:21  |  $remoteRoot"
$serverLabel.Location = New-Object System.Drawing.Point(18, 18)
$serverLabel.Size = New-Object System.Drawing.Size(440, 24)
$credentialForm.Controls.Add($serverLabel)

$userLabel = New-Object System.Windows.Forms.Label
$userLabel.Text = "FTP user: $userName"
$userLabel.Location = New-Object System.Drawing.Point(18, 48)
$userLabel.Size = New-Object System.Drawing.Size(440, 24)
$credentialForm.Controls.Add($userLabel)

$passwordLabel = New-Object System.Windows.Forms.Label
$passwordLabel.Text = 'FTP password:'
$passwordLabel.Location = New-Object System.Drawing.Point(18, 84)
$passwordLabel.Size = New-Object System.Drawing.Size(105, 24)
$credentialForm.Controls.Add($passwordLabel)

$passwordBox = New-Object System.Windows.Forms.TextBox
$passwordBox.Location = New-Object System.Drawing.Point(125, 81)
$passwordBox.Size = New-Object System.Drawing.Size(333, 25)
$passwordBox.UseSystemPasswordChar = $true
$credentialForm.Controls.Add($passwordBox)

$noteLabel = New-Object System.Windows.Forms.Label
$noteLabel.Text = 'Password is used only for this connection and is not saved.'
$noteLabel.Location = New-Object System.Drawing.Point(18, 113)
$noteLabel.Size = New-Object System.Drawing.Size(440, 22)
$credentialForm.Controls.Add($noteLabel)

$connectButton = New-Object System.Windows.Forms.Button
$connectButton.Text = 'Connect and inspect'
$connectButton.Location = New-Object System.Drawing.Point(270, 142)
$connectButton.Size = New-Object System.Drawing.Size(130, 28)
$connectButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$credentialForm.Controls.Add($connectButton)
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = 'Cancel'
$cancelButton.Location = New-Object System.Drawing.Point(408, 142)
$cancelButton.Size = New-Object System.Drawing.Size(50, 28)
$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$credentialForm.Controls.Add($cancelButton)
$credentialForm.AcceptButton = $connectButton
$credentialForm.CancelButton = $cancelButton

if ($ConsolePassword) {
    $credentialForm.Dispose()
    $securePassword = Read-Host 'SSO FTP password (input hidden)' -AsSecureString
    if ($securePassword.Length -eq 0) { throw 'An FTP password is required.' }
}
else {
    try {
        if ($credentialForm.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { exit 0 }
        if ([string]::IsNullOrEmpty($passwordBox.Text)) {
            [void][System.Windows.Forms.MessageBox]::Show('Enter the FTP password in the password field.', 'SSO FTP', 'OK', 'Warning')
            exit 1
        }
        $securePassword = ConvertTo-SecureString -String $passwordBox.Text -AsPlainText -Force
        $passwordBox.Clear()
    }
    finally {
        $passwordBox.Clear()
        $credentialForm.Dispose()
    }
}

$statusForm = New-Object System.Windows.Forms.Form
$statusForm.Text = 'SSO FTP inspection'
$statusForm.StartPosition = 'CenterScreen'
$statusForm.FormBorderStyle = 'FixedDialog'
$statusForm.ControlBox = $false
$statusForm.TopMost = $true
$statusForm.ClientSize = New-Object System.Drawing.Size(470, 100)
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Connecting securely to $hostName ..."
$statusLabel.Location = New-Object System.Drawing.Point(16, 18)
$statusLabel.Size = New-Object System.Drawing.Size(438, 24)
$statusForm.Controls.Add($statusLabel)
$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Style = 'Marquee'
$progress.MarqueeAnimationSpeed = 25
$progress.Location = New-Object System.Drawing.Point(16, 52)
$progress.Size = New-Object System.Drawing.Size(438, 22)
$statusForm.Controls.Add($progress)
$statusForm.Show()
[System.Windows.Forms.Application]::DoEvents()

$session = New-Object WinSCP.Session
$downloaded = 0
$maxFiles = 5000
$skipDirectories = @('.git', 'vendor', 'node_modules', 'storage', 'data', 'uploads', 'logs', 'backup', 'cache', 'sessions', 'private', 'secrets')
$allowedExtensions = @('.php', '.phtml', '.php5', '.inc', '.py', '.cgi', '.pl', '.sh', '.html', '.htm', '.js', '.css', '.json', '.xml', '.txt')
$excludedNames = @('.env', '.env.local', 'config.php', 'config.local.php', 'secrets.php', 'credentials.php', 'composer.lock')
$excludedExtensions = @('.pem', '.key', '.sql', '.sqlite', '.db', '.log', '.bak', '.zip')
$sensitiveNameMarkers = @('secret', 'credential', 'password', 'private')
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$sourceRoot = Join-Path $projectRoot 'sso-ftp-source'
if (Test-Path -LiteralPath $sourceRoot) {
    $sourceRoot = Join-Path $projectRoot ('sso-ftp-source-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
New-Item -ItemType Directory -Path $sourceRoot -Force | Out-Null

function Get-RemoteSourceFiles {
    param([Parameter(Mandatory = $true)] $Session, [Parameter(Mandatory = $true)][string] $RemoteDirectory)
    $listing = $Session.ListDirectory($RemoteDirectory)
    foreach ($item in $listing.Files) {
        if ($item.Name -in @('.', '..')) { continue }
        $segments = $item.FullName -split '[\\/]'
        if (@($segments | Where-Object { $_ -in $skipDirectories }).Count -gt 0) { continue }
        if ($item.IsDirectory) {
            Get-RemoteSourceFiles -Session $Session -RemoteDirectory $item.FullName
            continue
        }
        $extension = [System.IO.Path]::GetExtension($item.Name).ToLowerInvariant()
        if ($extension -notin $allowedExtensions -and $item.Name -ne '.htaccess' -and $item.Name -ne 'robots.txt') { continue }
        $nameLower = $item.Name.ToLowerInvariant()
        $sensitiveName = @($sensitiveNameMarkers | Where-Object { $nameLower.Contains($_) }).Count -gt 0
        if ($nameLower -in $excludedNames -or $excludedExtensions -contains $extension -or $sensitiveName -or $nameLower.StartsWith('id_rsa')) { continue }
        $item
    }
}

try {
    $options = New-Object WinSCP.SessionOptions -Property @{
        Protocol = [WinSCP.Protocol]::Ftp
        FtpSecure = [WinSCP.FtpSecure]::Explicit
        FtpMode = [WinSCP.FtpMode]::Passive
        HostName = $hostName
        PortNumber = 21
        UserName = $userName
        SecurePassword = $securePassword
        TlsHostCertificateFingerprint = $fingerprint
    }
    $session.Open($options)
    $statusLabel.Text = 'Connected. Listing remote source files...'
    [System.Windows.Forms.Application]::DoEvents()
    $remoteFiles = @(Get-RemoteSourceFiles -Session $session -RemoteDirectory $remoteRoot)
    if ($remoteFiles.Count -gt $maxFiles) { throw "Remote listing exceeded safety limit ($maxFiles files). No download was started." }
    $statusLabel.Text = "Connected. Downloading $($remoteFiles.Count) source files..."
    [System.Windows.Forms.Application]::DoEvents()

    foreach ($remoteFile in $remoteFiles) {
        $remoteFullName = [string]$remoteFile.FullName
        $remotePrefix = $remoteRoot.TrimEnd('/') + '/'
        if (-not $remoteFullName.StartsWith($remotePrefix, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $relative = $remoteFullName.Substring($remotePrefix.Length) -replace '/', '\'
        $relativeSegments = $relative -split '[\\/]'
        if ([string]::IsNullOrWhiteSpace($relative) -or $relativeSegments -contains '..') { continue }
        $localFile = [System.IO.Path]::GetFullPath((Join-Path $sourceRoot $relative))
        if (-not $localFile.StartsWith($sourceRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $parent = [System.IO.Path]::GetDirectoryName($localFile)
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        $transfer = $session.GetFiles($remoteFile.FullName, $localFile, $false)
        $transfer.Check()
        $downloaded++
    }
    $session.Dispose()
    $statusForm.Close()
    [void][System.Windows.Forms.MessageBox]::Show("FTPS connection succeeded.`r`nSource files downloaded: $downloaded`r`nLocal folder: $sourceRoot", 'SSO FTP inspection complete', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}
catch {
    if ($null -ne $session) { $session.Dispose() }
    if ($statusForm -and -not $statusForm.IsDisposed) { $statusForm.Close() }
    [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'SSO FTP inspection failed', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}
finally {
    if ($null -ne $securePassword) { $securePassword.Dispose() }
}
