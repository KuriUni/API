[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$base = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
$source = Join-Path $base 'sso-ftp-source-20261103-002438\server.py'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Source not found: $source" }
$dll = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCPnet.dll'),
    (Join-Path $env:ProgramFiles 'WinSCP\WinSCPnet.dll'),
    (Join-Path ${env:ProgramFiles(x86)} 'WinSCP\WinSCPnet.dll')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
if (-not $dll) { throw 'WinSCP .NET library was not found.' }
Add-Type -Path $dll

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Deploy SSO contractor tenant association'
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.ClientSize = New-Object System.Drawing.Size(470, 150)
$label = New-Object System.Windows.Forms.Label
$label.Text = 'Explicit FTPS ﾂｷ v2006.coreserver.jp ﾂｷ main@sso.2415.jp'
$label.Location = New-Object System.Drawing.Point(16, 16)
$label.Size = New-Object System.Drawing.Size(438, 24)
$form.Controls.Add($label)
$box = New-Object System.Windows.Forms.TextBox
$box.Location = New-Object System.Drawing.Point(18, 52)
$box.Size = New-Object System.Drawing.Size(436, 25)
$box.UseSystemPasswordChar = $true
$form.Controls.Add($box)
$button = New-Object System.Windows.Forms.Button
$button.Text = 'Upload server.py'
$button.Location = New-Object System.Drawing.Point(332, 94)
$button.Size = New-Object System.Drawing.Size(122, 32)
$button.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.Controls.Add($button)
$form.AcceptButton = $button
$form.add_Shown({ $box.Focus() })
if ($form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK -or [string]::IsNullOrWhiteSpace($box.Text)) { exit 2 }
$securePassword = ConvertTo-SecureString -String $box.Text -AsPlainText -Force
$box.Clear()
$form.Dispose()

$session = New-Object WinSCP.Session
try {
    $options = New-Object WinSCP.SessionOptions -Property @{
        Protocol = [WinSCP.Protocol]::Ftp
        FtpSecure = [WinSCP.FtpSecure]::Explicit
        FtpMode = [WinSCP.FtpMode]::Passive
        HostName = 'v2006.coreserver.jp'
        PortNumber = 21
        UserName = 'main@sso.2415.jp'
        SecurePassword = $securePassword
        TlsHostCertificateFingerprint = '20:9c:38:e5:92:50:52:0f:d1:9b:6c:69:e3:2d:5f:cb:b6:14:28:ed:bf:5f:34:f3:74:93:69:8d:46:a1:b3:f4'
    }
    $session.Open($options)
    $transfer = $session.PutFiles($source, '/server.py', $false)
    $transfer.Check()
    $session.Dispose()
    [void][System.Windows.Forms.MessageBox]::Show('SSO server.py deployed successfully.', 'SSO deployment', 'OK', 'Information')
}
catch {
    if ($null -ne $session) { $session.Dispose() }
    [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'SSO deployment failed', 'OK', 'Error')
    exit 1
}
finally {
    if ($null -ne $securePassword) { $securePassword.Dispose() }
}

