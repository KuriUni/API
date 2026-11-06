<#
.SYNOPSIS
  Deploy local XREA source to the live site and backup over pinned explicit FTPS.
.DESCRIPTION
  Uploads new and changed files; keeps remote-only files. Passwords can be saved
  with Windows DPAPI for the current Windows user. Credential entry is GUI-based.
#>
[CmdletBinding()]
param(
    [ValidateSet('Both', 'Primary', 'Backup')]
    [string] $Target = 'Both',
    [string] $LocalPath,
    [switch] $PreflightOnly,
    [switch] $ResetCredentials
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

if ([string]::IsNullOrWhiteSpace($LocalPath)) {
    $scriptDirectory = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
    if ([string]::IsNullOrWhiteSpace($scriptDirectory)) { throw 'Could not determine script folder.' }
    $LocalPath = [System.IO.Path]::GetFullPath((Join-Path $scriptDirectory '..\..\xrea-source'))
}
$resolvedLocalPath = [System.IO.Path]::GetFullPath($LocalPath)
if (-not (Test-Path -LiteralPath $resolvedLocalPath -PathType Container)) { throw "Source folder not found: $resolvedLocalPath" }

$assemblyCandidates = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCPnet.dll'),
    (Join-Path $env:ProgramFiles 'WinSCP\WinSCPnet.dll'),
    (Join-Path ${env:ProgramFiles(x86)} 'WinSCP\WinSCPnet.dll')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
if (-not $assemblyCandidates) { throw 'WinSCP was not found. Install WinSCP, then retry.' }
Add-Type -Path ($assemblyCandidates | Select-Object -First 1)
$assemblyPath = $assemblyCandidates | Select-Object -First 1
$fingerprint = '9c:fb:c9:21:d2:6f:de:43:43:bc:cb:e2:65:b0:99:e4:20:11:e1:72:bb:26:16:48:d1:3e:30:89:68:6d:d4:c7'
$targets = @(
    [pscustomobject]@{ Name = 'Primary'; Host = 's1004.xrea.com'; User = 'backup1tkmpc'; Remote = '/public_html/2415.jp/license' },
    [pscustomobject]@{ Name = 'Backup'; Host = 's1006.xrea.com'; User = 'tkm10pc4rds'; Remote = '/public_html/backup.2415.jp/license' }
) | Where-Object { $Target -eq 'Both' -or $_.Name -eq $Target }

if ($PreflightOnly) {
    Write-Host "Preflight OK. Source: $resolvedLocalPath"
    Write-Host "WinSCP: $assemblyPath"
    foreach ($destination in $targets) { Write-Host "Destination: $($destination.Host):$($destination.Remote)" }
    exit 0
}

$credentialDirectory = Join-Path $env:LOCALAPPDATA 'XreaDeploy'
$credentialFile = Join-Path $credentialDirectory 'credentials.xml'
if ($ResetCredentials -and (Test-Path -LiteralPath $credentialFile -PathType Leaf)) { Remove-Item -LiteralPath $credentialFile -Force }
if (-not (Test-Path -LiteralPath $credentialDirectory -PathType Container)) { New-Item -ItemType Directory -Path $credentialDirectory -Force | Out-Null }
$savedCredentials = @{}
if (Test-Path -LiteralPath $credentialFile -PathType Leaf) {
    try {
        $imported = Import-Clixml -LiteralPath $credentialFile
        foreach ($name in @('Primary', 'Backup')) {
            if ($imported -is [System.Collections.IDictionary]) { $entry = $imported[$name] } else { $entry = $imported.$name }
            if ($entry -is [System.Management.Automation.PSCredential]) { $savedCredentials[$name] = $entry }
        }
    }
    catch { throw "Could not read DPAPI credential file. Run with -ResetCredentials. $($_.Exception.Message)" }
}

function Save-DeployCredentials {
    # On Windows, Export-Clixml stores SecureString with DPAPI for this user/profile.
    $savedCredentials | Export-Clixml -LiteralPath $credentialFile -Force
}

function Get-DeployCredential {
    param([Parameter(Mandatory = $true)] $Destination, [switch] $ForcePassword)
    $hasSaved = $savedCredentials.ContainsKey($Destination.Name) -and $savedCredentials[$Destination.Name].UserName -eq $Destination.User

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "XREA FTP - $($Destination.Name)"
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.ClientSize = New-Object System.Drawing.Size(450, 215)
    $form.TopMost = $true

    $hostLabel = New-Object System.Windows.Forms.Label
    $hostLabel.Text = "$($Destination.Host)  |  $($Destination.Remote)"
    $hostLabel.Location = New-Object System.Drawing.Point(16, 15)
    $hostLabel.Size = New-Object System.Drawing.Size(418, 24)
    $form.Controls.Add($hostLabel)

    $userLabel = New-Object System.Windows.Forms.Label
    $userLabel.Text = "FTP user: $($Destination.User)"
    $userLabel.Location = New-Object System.Drawing.Point(16, 44)
    $userLabel.Size = New-Object System.Drawing.Size(418, 22)
    $form.Controls.Add($userLabel)

    $useSaved = New-Object System.Windows.Forms.CheckBox
    $useSaved.Text = 'Use saved DPAPI credential'
    $useSaved.Location = New-Object System.Drawing.Point(16, 72)
    $useSaved.Size = New-Object System.Drawing.Size(418, 24)
    $useSaved.Checked = [bool]($hasSaved -and -not $ForcePassword)
    $useSaved.Enabled = [bool]($hasSaved -and -not $ForcePassword)
    $form.Controls.Add($useSaved)

    $passwordLabel = New-Object System.Windows.Forms.Label
    $passwordLabel.Text = 'FTP password:'
    $passwordLabel.Location = New-Object System.Drawing.Point(16, 105)
    $passwordLabel.Size = New-Object System.Drawing.Size(95, 23)
    $form.Controls.Add($passwordLabel)

    $passwordBox = New-Object System.Windows.Forms.TextBox
    $passwordBox.Location = New-Object System.Drawing.Point(112, 102)
    $passwordBox.Size = New-Object System.Drawing.Size(322, 24)
    $passwordBox.UseSystemPasswordChar = $true
    $passwordBox.Enabled = -not $useSaved.Checked
    $form.Controls.Add($passwordBox)
    $useSaved.Add_CheckedChanged({ $passwordBox.Enabled = -not $useSaved.Checked })

    $remember = New-Object System.Windows.Forms.CheckBox
    $remember.Text = 'Save password encrypted with Windows DPAPI'
    $remember.Location = New-Object System.Drawing.Point(16, 135)
    $remember.Size = New-Object System.Drawing.Size(418, 24)
    $remember.Checked = $true
    $form.Controls.Add($remember)

    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'Continue'
    $ok.Location = New-Object System.Drawing.Point(256, 174)
    $ok.Size = New-Object System.Drawing.Size(84, 27)
    $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($ok)
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'
    $cancel.Location = New-Object System.Drawing.Point(350, 174)
    $cancel.Size = New-Object System.Drawing.Size(84, 27)
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($cancel)
    $form.AcceptButton = $ok
    $form.CancelButton = $cancel

    try {
        if ($form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { throw 'Deployment cancelled.' }
        if ($useSaved.Checked) { return $savedCredentials[$Destination.Name] }
        if ([string]::IsNullOrEmpty($passwordBox.Text)) { throw "Enter the FTP password for $($Destination.Host)." }
        $securePassword = ConvertTo-SecureString -String $passwordBox.Text -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($Destination.User, $securePassword)
        $passwordBox.Clear()
        if ($remember.Checked) { $savedCredentials[$Destination.Name] = $credential } else { $savedCredentials.Remove($Destination.Name) }
        Save-DeployCredentials
        return $credential
    }
    finally { $passwordBox.Clear(); $form.Dispose() }
}

try {
    foreach ($destination in $targets) {
        $credential = Get-DeployCredential -Destination $destination
        $session = $null
        try {
            $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
                Protocol = [WinSCP.Protocol]::Ftp
                FtpSecure = [WinSCP.FtpSecure]::Explicit
                FtpMode = [WinSCP.FtpMode]::Passive
                HostName = $destination.Host
                PortNumber = 21
                UserName = $destination.User
                SecurePassword = $credential.Password
                TlsHostCertificateFingerprint = $fingerprint
            }
            $session = New-Object WinSCP.Session
            $session.Open($sessionOptions)
        }
        catch {
            if ($_.Exception.Message -notmatch '(?i)auth|fail|denied|530|\u8A8D\u8A3C') { throw }
            [void][System.Windows.Forms.MessageBox]::Show("Authentication failed for $($destination.Host). Enter the corrected password.", 'XREA authentication', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            $credential = Get-DeployCredential -Destination $destination -ForcePassword
            if ($null -ne $session) { $session.Dispose() }
            $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
                Protocol = [WinSCP.Protocol]::Ftp
                FtpSecure = [WinSCP.FtpSecure]::Explicit
                FtpMode = [WinSCP.FtpMode]::Passive
                HostName = $destination.Host
                PortNumber = 21
                UserName = $destination.User
                SecurePassword = $credential.Password
                TlsHostCertificateFingerprint = $fingerprint
            }
            $session = New-Object WinSCP.Session
            try { $session.Open($sessionOptions) }
            catch {
                $savedCredentials.Remove($destination.Name)
                Save-DeployCredentials
                throw "Authentication failed again for $($destination.Host). Saved credential removed. Check the FTP username/password."
            }
        }

        try {
            $transferOptions = New-Object WinSCP.TransferOptions
            $transferOptions.TransferMode = [WinSCP.TransferMode]::Binary
            if ($destination.Name -eq 'Backup') {
                # The standby has a distinct runtime package and private data
                # directory. Never replace its per-node launcher settings with
                # the primary node's fastapi-runtime.json.
                $transferOptions.FileMask = '| fastapi-runtime.json'
            }
            $result = $session.SynchronizeDirectories(
                [WinSCP.SynchronizationMode]::Remote,
                $resolvedLocalPath,
                $destination.Remote,
                $false,
                $false,
                [WinSCP.SynchronizationCriteria]::Time,
                $transferOptions
            )
            $result.Check()
            Write-Host "Completed $($destination.Name). Files uploaded: $($result.Uploads.Count)"
        }
        finally { if ($null -ne $session) { $session.Dispose() } }
    }
    [void][System.Windows.Forms.MessageBox]::Show('Deployment synchronization completed for all selected destinations.', 'XREA deployment', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}
catch {
    [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'XREA deployment failed', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}
