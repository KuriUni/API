<#
.SYNOPSIS
  Synchronizes xrea-source to the Core Server FTP root used by main.2415.jp.
.DESCRIPTION
  Uses explicit FTPS with a pinned certificate, preserves remote-only files,
  and stores the FTP credential only with Windows DPAPI for the current user.
#>
[CmdletBinding()]
param([switch] $ResetCredentials, [switch] $PreflightOnly)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\Xrea\Invoke-XreaDifferentialUpload.ps1')
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$source = Join-Path $projectRoot 'xrea-source'
$hostName = 'v2006.coreserver.jp'
# Suggested Core Server account from the existing FTP setup; the GUI allows changing it.
$userName = 'main@sso.2415.jp'
# Core Server FTP accounts are jailed at their site's public_html directory.
$remotePath = '/'
$fingerprint = '20:9c:38:e5:92:50:52:0f:d1:9b:6c:69:e3:2d:5f:cb:b6:14:28:ed:bf:5f:34:f3:74:93:69:8d:46:a1:b3:f4'

if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw "Deployment source not found: $source" }
$assemblyCandidates = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCPnet.dll'),
    (Join-Path $env:ProgramFiles 'WinSCP\WinSCPnet.dll'),
    (Join-Path ${env:ProgramFiles(x86)} 'WinSCP\WinSCPnet.dll')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
if (-not $assemblyCandidates) { throw 'WinSCP .NET library was not found. Install WinSCP, then retry.' }
Add-Type -Path ($assemblyCandidates | Select-Object -First 1)

if ($PreflightOnly) {
    Write-Host "Source:      $source"
    Write-Host "Destination: $hostName ($userName):$remotePath"
    Write-Host 'Protocol:    Explicit FTPS, port 21, certificate pinned'
    exit 0
}

$credentialDirectory = Join-Path $env:LOCALAPPDATA 'Main2415Deploy'
$credentialFile = Join-Path $credentialDirectory 'ftp-credential.xml'
if ($ResetCredentials -and (Test-Path -LiteralPath $credentialFile -PathType Leaf)) {
    Remove-Item -LiteralPath $credentialFile -Force
}

$storedCredential = $null
if (Test-Path -LiteralPath $credentialFile -PathType Leaf) {
    try {
        $candidate = Import-Clixml -LiteralPath $credentialFile
        if ($candidate -is [System.Management.Automation.PSCredential]) { $storedCredential = $candidate }
    } catch { $storedCredential = $null }
}

$credential = $null
$remember = $false
$usedSavedCredential = $false
$form = New-Object System.Windows.Forms.Form
$form.Text = 'main.2415.jp FTP deployment'
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.TopMost = $true
$form.ClientSize = New-Object System.Drawing.Size(520, 280)
$label = New-Object System.Windows.Forms.Label
$label.Text = "Explicit FTPS: $hostName`r`nTarget: main.2415.jp / FTP root ($remotePath)"
$label.Location = New-Object System.Drawing.Point(16, 12)
$label.Size = New-Object System.Drawing.Size(488, 42)
$form.Controls.Add($label)
$accountLabel = New-Object System.Windows.Forms.Label
$accountLabel.Text = 'FTP account:'
$accountLabel.Location = New-Object System.Drawing.Point(16, 62)
$accountLabel.Size = New-Object System.Drawing.Size(100, 24)
$form.Controls.Add($accountLabel)
$accountBox = New-Object System.Windows.Forms.TextBox
$accountBox.Location = New-Object System.Drawing.Point(120, 59)
$accountBox.Size = New-Object System.Drawing.Size(380, 26)
$accountBox.Text = $userName
$form.Controls.Add($accountBox)
$useSavedBox = New-Object System.Windows.Forms.CheckBox
$useSavedBox.Text = '保存済みのDPAPI資格情報を使う'
$useSavedBox.Location = New-Object System.Drawing.Point(18, 91)
$useSavedBox.Size = New-Object System.Drawing.Size(300, 24)
$useSavedBox.Enabled = [bool]($storedCredential -and $storedCredential.UserName -eq $userName)
$useSavedBox.Checked = $useSavedBox.Enabled
$form.Controls.Add($useSavedBox)
$passwordLabel = New-Object System.Windows.Forms.Label
$passwordLabel.Text = 'FTP password:'
$passwordLabel.Location = New-Object System.Drawing.Point(16, 124)
$passwordLabel.Size = New-Object System.Drawing.Size(100, 24)
$form.Controls.Add($passwordLabel)
$passwordBox = New-Object System.Windows.Forms.TextBox
$passwordBox.Location = New-Object System.Drawing.Point(120, 121)
$passwordBox.Size = New-Object System.Drawing.Size(380, 26)
$passwordBox.UseSystemPasswordChar = $true
$passwordBox.Enabled = -not $useSavedBox.Checked
$form.Controls.Add($passwordBox)
$useSavedBox.Add_CheckedChanged({ $passwordBox.Enabled = -not $useSavedBox.Checked })
$accountBox.Add_TextChanged({
    $matchesSaved = $storedCredential -and ($accountBox.Text -eq $storedCredential.UserName)
    $useSavedBox.Enabled = [bool]$matchesSaved
    if (-not $matchesSaved) { $useSavedBox.Checked = $false }
})
$saveBox = New-Object System.Windows.Forms.CheckBox
$saveBox.Text = 'このWindowsユーザーのDPAPIで保存'
$saveBox.Location = New-Object System.Drawing.Point(18, 153)
$saveBox.Size = New-Object System.Drawing.Size(300, 24)
$saveBox.Checked = $true
$form.Controls.Add($saveBox)
$note = New-Object System.Windows.Forms.Label
$note.Text = 'FTPアカウントの公開先が main.2415.jp の public_html であることを確認してください。'
$note.Location = New-Object System.Drawing.Point(18, 181)
$note.Size = New-Object System.Drawing.Size(484, 30)
$form.Controls.Add($note)
$ok = New-Object System.Windows.Forms.Button
$ok.Text = '接続して同期'
$ok.Location = New-Object System.Drawing.Point(292, 235)
$ok.Size = New-Object System.Drawing.Size(106, 28)
$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.Controls.Add($ok)
$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = 'キャンセル'
$cancel.Location = New-Object System.Drawing.Point(404, 235)
$cancel.Size = New-Object System.Drawing.Size(88, 28)
$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($cancel)
$form.AcceptButton = $ok
$form.CancelButton = $cancel
$form.add_Shown({ $passwordBox.Focus() })
try {
    if ($form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { throw 'Credential entry was cancelled.' }
    $userName = $accountBox.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($userName)) { throw 'Enter the FTP account name.' }
    if ($useSavedBox.Checked) {
        if (-not $storedCredential -or $storedCredential.UserName -ne $userName) { throw 'The saved credential does not match this FTP account.' }
        $credential = $storedCredential
        $usedSavedCredential = $true
    } else {
        if ([string]::IsNullOrWhiteSpace($passwordBox.Text)) { throw 'Enter the FTP password.' }
        $securePassword = ConvertTo-SecureString -String $passwordBox.Text -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($userName, $securePassword)
    }
    $remember = $saveBox.Checked
} finally {
    $passwordBox.Clear()
    $form.Dispose()
}

$confirm = [System.Windows.Forms.MessageBox]::Show(
    "Source:`r`n$source`r`n`r`nDestination:`r`nmain.2415.jp via $hostName`r`nFTP root: $remotePath`r`n`r`n新規・更新ファイルを同期します。サーバー側だけにあるファイルは削除しません。続行しますか？",
    'main.2415.jp deployment confirmation',
    [System.Windows.Forms.MessageBoxButtons]::YesNo,
    [System.Windows.Forms.MessageBoxIcon]::Warning,
    [System.Windows.Forms.MessageBoxDefaultButton]::Button2)
if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { $credential = $null; exit 2 }

$session = New-Object WinSCP.Session
try {
    $options = New-Object WinSCP.SessionOptions -Property @{
        Protocol = [WinSCP.Protocol]::Ftp
        FtpSecure = [WinSCP.FtpSecure]::Explicit
        FtpMode = [WinSCP.FtpMode]::Passive
        HostName = $hostName
        PortNumber = 21
        UserName = $userName
        SecurePassword = $credential.Password
        TlsHostCertificateFingerprint = $fingerprint
    }
    $session.Open($options)
    if ($remember) {
        if (-not (Test-Path -LiteralPath $credentialDirectory -PathType Container)) {
            New-Item -ItemType Directory -Path $credentialDirectory -Force | Out-Null
        }
        $credential | Export-Clixml -LiteralPath $credentialFile -Force
    }

    $transferOptions = New-Object WinSCP.TransferOptions
    $transferOptions.TransferMode = [WinSCP.TransferMode]::Binary
    $transferOptions.ResumeSupport.State = [WinSCP.TransferResumeSupportState]::On
    $transferOptions.FileMask = '| fastapi-runtime.json; __pycache__/; *.pyc; *.pyo; .tuti-deploy-backup-*/; .tuti-deploy-stage-*/'
    $result = Invoke-XreaDifferentialUpload -Session $session -LocalRoot $source -RemoteRoot $remotePath -StateKey "$hostName|$remotePath" -TransferOptions $transferOptions -ExcludePatterns @('(^|/)fastapi-runtime\.json$', '(^|/)__pycache__(/|$)', '\.py[co]$', '(^|/)\.tuti-deploy-(backup|stage)-')
    [void][System.Windows.Forms.MessageBox]::Show(
        "main.2415.jpへの差分アップロードが完了しました。`r`nアップロード数: $($result.Uploaded)`r`nローカルファイル確認数: $($result.CheckedLocal)`r`n整理した古い台帳項目: $($result.PrunedStateEntries)`r`nFTP側の全体スキャンは行っていません。`r`nローカル実行ファイルはサーバーへ配置していません。",
        'Deployment completed',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information)
} catch {
    $errorText = $_.Exception.Message
    if ($usedSavedCredential -and (Test-Path -LiteralPath $credentialFile -PathType Leaf) -and $errorText -match '(?i)authentication|auth failed|530|認証') {
        Remove-Item -LiteralPath $credentialFile -Force -ErrorAction SilentlyContinue
        $errorText += "`r`n保存済み資格情報を削除しました。ランチャーからもう一度実行し、新しいパスワードを入力してください。"
    }
    [void][System.Windows.Forms.MessageBox]::Show($errorText, 'main.2415.jp deployment failed', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
} finally {
    if ($null -ne $session) { $session.Dispose() }
    $credential = $null
}
