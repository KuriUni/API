#requires -Version 7.0
<#
.SYNOPSIS
  GUI for configuring the Stripe billing secrets on the XREA Primary/Backup nodes.

.DESCRIPTION
  Writes stripe_secret_key / stripe_webhook_secret / stripe_enable_live /
  stripe_return_base_url into the private runtime-secrets.json of each target,
  merging with the existing file. Secrets are never written to the repository or
  the log; a DPAPI-encrypted backup of the previous file is kept under
  %LOCALAPPDATA%\XreaDeploy\private-backups.

  Optionally calls POST /ha/migrate.php {"scope":"stripe"} so the
  stripe_invoice_payments / stripe_webhook_events tables exist.

.EXAMPLE
  pwsh -NoProfile -STA -File .\operations\Xrea\Configure-StripeBilling.ps1
#>
[CmdletBinding()]
param(
    [ValidateSet('Both', 'Primary', 'Backup')][string] $Target = 'Both',
    [switch] $ResetCredential
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
. (Join-Path $PSScriptRoot 'Xrea-DeployTargets.ps1')

$tlsFingerprint = '9c:fb:c9:21:d2:6f:de:43:43:bc:cb:e2:65:b0:99:e4:20:11:e1:72:bb:26:16:48:d1:3e:30:89:68:6d:d4:c7'
$credentialPath = Join-Path $env:LOCALAPPDATA 'XreaDeploy\credentials.xml'
$privateBackupRoot = Join-Path $env:LOCALAPPDATA 'XreaDeploy\private-backups'
$allTargets = @(Get-XreaDeployTargets)

$dll = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\netstandard2.0\WinSCPnet.dll'),
    (Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCPnet.dll'),
    (Join-Path $env:ProgramFiles 'WinSCP\WinSCPnet.dll'),
    (Join-Path ${env:ProgramFiles(x86)} 'WinSCP\WinSCPnet.dll')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
if (-not $dll) { throw 'WinSCP .NET library (WinSCPnet.dll) was not found.' }
$winscpExe = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCP.exe'),
    (Join-Path $env:ProgramFiles 'WinSCP\WinSCP.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'WinSCP\WinSCP.exe'),
    (Join-Path (Split-Path -Parent $dll) 'WinSCP.exe'),
    (Join-Path (Split-Path -Parent (Split-Path -Parent $dll)) 'WinSCP.exe')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
if (-not $winscpExe) { throw 'WinSCP.exe was not found. Install WinSCP (same version as WinSCPnet.dll) and run again.' }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Security.Cryptography.ProtectedData
Add-Type -Path $dll

function Get-DomainForTarget {
    param([string] $Name)
    if ($Name -eq 'Primary') { return '2415.jp' }
    if ($Name -eq 'Backup') { return 'backup.2415.jp' }
    throw "Unknown target: $Name"
}

function Get-RemoteSecretsPath {
    param([string] $Name)
    '/.tuti-license-ha-' + (Get-DomainForTarget $Name) + '/runtime/runtime-secrets.json'
}

# --- DPAPI credential store (shared with the other XREA scripts) -----------
$credentialMap = @{}
if (Test-Path -LiteralPath $credentialPath -PathType Leaf) {
    try {
        $saved = Import-Clixml -LiteralPath $credentialPath
        foreach ($name in @('Primary', 'Backup', 'Main')) {
            $entry = if ($saved -is [System.Collections.IDictionary]) { $saved[$name] } else { $saved.$name }
            if ($entry -is [System.Management.Automation.PSCredential]) { $credentialMap[$name] = $entry }
        }
    } catch { throw 'Could not read the current-user DPAPI credential file.' }
}
if ($ResetCredential) {
    foreach ($name in @('Primary', 'Backup')) { $credentialMap.Remove($name) }
}

function Save-CredentialMap {
    $directory = Split-Path -Parent $credentialPath
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $credentialMap | Export-Clixml -LiteralPath $credentialPath -Force
}

function Get-CredentialForTarget {
    param([Parameter(Mandatory)] $Destination)
    $saved = $credentialMap[$Destination.Name]
    if ($saved -is [System.Management.Automation.PSCredential] -and $saved.UserName -eq $Destination.User) { return $saved }

    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = "FTP password - $($Destination.Name)"
    $dialog.StartPosition = 'CenterParent'
    $dialog.FormBorderStyle = 'FixedDialog'
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false
    $dialog.TopMost = $true
    $dialog.ClientSize = New-Object System.Drawing.Size(480, 168)
    $info = New-Object System.Windows.Forms.Label
    $info.Text = "FTPS: $($Destination.Host)`r`nFTP user: $($Destination.User)`r`nThe password is saved with Windows DPAPI for this Windows user."
    $info.Location = New-Object System.Drawing.Point(16, 12)
    $info.Size = New-Object System.Drawing.Size(448, 56)
    $dialog.Controls.Add($info)
    $box = New-Object System.Windows.Forms.TextBox
    $box.Location = New-Object System.Drawing.Point(18, 74)
    $box.Size = New-Object System.Drawing.Size(444, 25)
    $box.UseSystemPasswordChar = $true
    $dialog.Controls.Add($box)
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'Connect'
    $ok.Location = New-Object System.Drawing.Point(340, 116)
    $ok.Size = New-Object System.Drawing.Size(120, 32)
    $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $dialog.Controls.Add($ok)
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'
    $cancel.Location = New-Object System.Drawing.Point(250, 116)
    $cancel.Size = New-Object System.Drawing.Size(80, 32)
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dialog.Controls.Add($cancel)
    $dialog.AcceptButton = $ok
    $dialog.CancelButton = $cancel
    try {
        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK -or [string]::IsNullOrWhiteSpace($box.Text)) {
            throw 'FTP credential entry was cancelled.'
        }
        $secure = ConvertTo-SecureString -String $box.Text -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($Destination.User, $secure)
        $credentialMap[$Destination.Name] = $credential
        Save-CredentialMap
        return $credential
    } finally {
        $box.Clear()
        $dialog.Dispose()
    }
}

# --- Stripe / remote helpers -------------------------------------------------
function Test-StripeKeyFormat {
    param([string] $Key)
    if ($Key -match '^sk_test_[A-Za-z0-9]{8,}$') { return 'test' }
    if ($Key -match '^sk_live_[A-Za-z0-9]{8,}$') { return 'live' }
    throw 'APIキーは sk_test_ または sk_live_ で始まるStripeシークレットキーを入力してください。'
}

function Invoke-StripeBalanceCheck {
    param([string] $Key)
    $headers = @{ Authorization = "Bearer $Key"; Accept = 'application/json' }
    return Invoke-RestMethod -Uri 'https://api.stripe.com/v1/balance' -Headers $headers -Method Get -TimeoutSec 25
}

function New-FtpSession {
    param($Destination, $Credential)
    $session = [WinSCP.Session]::new()
    $session.ExecutablePath = $winscpExe
    $session.Open([WinSCP.SessionOptions]@{
        Protocol                  = [WinSCP.Protocol]::Ftp
        FtpSecure                 = [WinSCP.FtpSecure]::Explicit
        FtpMode                   = [WinSCP.FtpMode]::Passive
        HostName                  = $Destination.Host
        PortNumber                = 21
        UserName                  = $Destination.User
        SecurePassword            = $Credential.Password
        TlsHostCertificateFingerprint = $tlsFingerprint
    })
    return $session
}

function Read-RemoteText {
    param($Session, [string] $Path)
    $stream = $Session.GetFile($Path)
    try {
        $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8)
        return $reader.ReadToEnd()
    } finally {
        if ($reader) { $reader.Dispose() }
        $stream.Dispose()
    }
}

function Protect-LocalBackup {
    param([string] $Text, [string] $Path)
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    $plain = [Text.Encoding]::UTF8.GetBytes($Text)
    try {
        $encrypted = [Security.Cryptography.ProtectedData]::Protect($plain, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes($Path, $encrypted)
    } finally { [Array]::Clear($plain, 0, $plain.Length) }
}

function ConvertTo-SecretHashtable {
    param([string] $Json)
    try { $value = $Json | ConvertFrom-Json -AsHashtable } catch { throw 'runtime-secrets.json をJSONとして読み取れませんでした。' }
    if ($value -isnot [System.Collections.IDictionary]) { throw 'runtime-secrets.json の形式が想定と異なります。' }
    return $value
}

function Update-RemoteSecrets {
    param($Destination, $Credential, [hashtable] $Updates, [string[]] $RemoveKeys)

    $remotePath = Get-RemoteSecretsPath $Destination.Name
    $session = New-FtpSession $Destination $Credential
    try {
        if (-not $session.FileExists($remotePath)) { throw "runtime-secrets.json was not found: $remotePath" }
        $originalText = Read-RemoteText $session $remotePath
        $secrets = ConvertTo-SecretHashtable $originalText

        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $backupPath = Join-Path $privateBackupRoot "stripe-config-$stamp\$($Destination.Name)-runtime-secrets.before.dpapi"
        Protect-LocalBackup $originalText $backupPath

        foreach ($key in $Updates.Keys) { $secrets[$key] = [string]$Updates[$key] }
        foreach ($key in $RemoveKeys) { [void]$secrets.Remove($key) }

        $json = $secrets | ConvertTo-Json -Compress -Depth 8
        $localTemp = Join-Path ([IO.Path]::GetTempPath()) ('stripe-secrets-' + [guid]::NewGuid().ToString('N') + '.json')
        [IO.File]::WriteAllText($localTemp, [string]$json, [Text.UTF8Encoding]::new($false))
        $remoteTemp = $remotePath + '.tmp-' + [guid]::NewGuid().ToString('N')
        try {
            $session.PutFiles($localTemp, $remoteTemp, $false).Check()
            $session.MoveFile($remoteTemp, $remotePath)
            $verify = ConvertTo-SecretHashtable (Read-RemoteText $session $remotePath)
            foreach ($key in $Updates.Keys) {
                if ([string]$verify[$key] -ne [string]$Updates[$key]) { throw "Remote verification failed for $key" }
            }
            foreach ($key in $RemoveKeys) {
                if ($verify.Contains($key)) { throw "Remote verification failed for removed $key" }
            }
        } catch {
            $failure = $_
            try {
                $restore = Join-Path ([IO.Path]::GetTempPath()) ('stripe-secrets-restore-' + [guid]::NewGuid().ToString('N') + '.json')
                [IO.File]::WriteAllText($restore, $originalText, [Text.UTF8Encoding]::new($false))
                $restoreRemote = $remotePath + '.restore-' + [guid]::NewGuid().ToString('N')
                $session.PutFiles($restore, $restoreRemote, $false).Check()
                $session.MoveFile($restoreRemote, $remotePath)
                Remove-Item -LiteralPath $restore -Force -ErrorAction SilentlyContinue
            } catch {
                throw "Upload failed and the previous secrets could not be restored automatically. DPAPI backup: $backupPath"
            }
            throw $failure
        } finally {
            Remove-Item -LiteralPath $localTemp -Force -ErrorAction SilentlyContinue
        }
        [pscustomobject]@{ Target = $Destination.Name; Secrets = $secrets; Backup = $backupPath; RemotePath = $remotePath }
    } finally {
        $session.Dispose()
    }
}

function Invoke-StripeSchemaMigration {
    param($Destination, $Secrets)
    $token = [string]$Secrets['ha_sync_token']
    if ($token.Length -lt 32) { return 'HAトークンが無いため scope=stripe の初期化を省略しました。' }
    $domain = Get-DomainForTarget $Destination.Name
    $url = "https://$domain/license/ha/migrate.php"
    try {
        $response = Invoke-WebRequest -Uri $url -Method Post -Headers @{ 'X-HA-Token' = $token; Accept = 'application/json' } -ContentType 'application/json' -Body '{"scope":"stripe"}' -TimeoutSec 90 -SkipHttpErrorCheck
    } catch {
        return "scope=stripe の初期化に接続できませんでした: $($_.Exception.Message)"
    }
    try { $payload = $response.Content | ConvertFrom-Json } catch { $payload = $null }
    if ([int]$response.StatusCode -ne 200 -or -not $payload.ok) {
        return "scope=stripe は未実行です（HTTP $([int]$response.StatusCode)）。Stripe対応コードを配備してから再実行してください。"
    }
    return 'scope=stripe を適用しました。'
}

# --- GUI ---------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Stripe請求設定（XREA Primary / Backup）'
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.ClientSize = New-Object System.Drawing.Size(600, 560)
$font = New-Object System.Drawing.Font('Yu Gothic UI', 9)
$form.Font = $font

function Add-Label([string] $Text, [int] $X, [int] $Y, [int] $Width, [int] $Height = 22) {
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Location = New-Object System.Drawing.Point($X, $Y)
    $label.Size = New-Object System.Drawing.Size($Width, $Height)
    $form.Controls.Add($label)
    return $label
}

Add-Label '対象ノード' 16 14 90 | Out-Null
$cboTarget = New-Object System.Windows.Forms.ComboBox
$cboTarget.DropDownStyle = 'DropDownList'
$cboTarget.Location = New-Object System.Drawing.Point(110, 12)
$cboTarget.Size = New-Object System.Drawing.Size(150, 25)
[void]$cboTarget.Items.AddRange(@('Both', 'Primary', 'Backup'))
$cboTarget.SelectedItem = $Target
$form.Controls.Add($cboTarget)

$lblHint = Add-Label '設定は非公開の runtime-secrets.json にだけ保存します。' 275 16 310

Add-Label 'Stripe シークレットキー' 16 50 170 | Out-Null
$txtKey = New-Object System.Windows.Forms.TextBox
$txtKey.Location = New-Object System.Drawing.Point(16, 72)
$txtKey.Size = New-Object System.Drawing.Size(500, 25)
$txtKey.UseSystemPasswordChar = $true
$form.Controls.Add($txtKey)
$chkShowKey = New-Object System.Windows.Forms.CheckBox
$chkShowKey.Text = '表示'
$chkShowKey.Location = New-Object System.Drawing.Point(524, 72)
$chkShowKey.Size = New-Object System.Drawing.Size(60, 24)
$form.Controls.Add($chkShowKey)

Add-Label 'Webhook 署名シークレット（whsec_…）' 16 106 300 | Out-Null
$txtWebhook = New-Object System.Windows.Forms.TextBox
$txtWebhook.Location = New-Object System.Drawing.Point(16, 128)
$txtWebhook.Size = New-Object System.Drawing.Size(500, 25)
$txtWebhook.UseSystemPasswordChar = $true
$form.Controls.Add($txtWebhook)
$chkShowWebhook = New-Object System.Windows.Forms.CheckBox
$chkShowWebhook.Text = '表示'
$chkShowWebhook.Location = New-Object System.Drawing.Point(524, 128)
$chkShowWebhook.Size = New-Object System.Drawing.Size(60, 24)
$form.Controls.Add($chkShowWebhook)

Add-Label '戻り先ベースURL（任意 / 例 https://2415.jp/license）' 16 162 400 | Out-Null
$txtReturn = New-Object System.Windows.Forms.TextBox
$txtReturn.Location = New-Object System.Drawing.Point(16, 184)
$txtReturn.Size = New-Object System.Drawing.Size(566, 25)
$form.Controls.Add($txtReturn)

$chkLive = New-Object System.Windows.Forms.CheckBox
$chkLive.Text = '本番キー（sk_live_）を有効化する'
$chkLive.Location = New-Object System.Drawing.Point(16, 220)
$chkLive.Size = New-Object System.Drawing.Size(300, 24)
$form.Controls.Add($chkLive)

$chkMigrate = New-Object System.Windows.Forms.CheckBox
$chkMigrate.Text = 'Stripe用テーブルを初期化する（scope=stripe）'
$chkMigrate.Location = New-Object System.Drawing.Point(16, 246)
$chkMigrate.Size = New-Object System.Drawing.Size(330, 24)
$chkMigrate.Checked = $true
$form.Controls.Add($chkMigrate)

$lblMode = New-Object System.Windows.Forms.Label
$lblMode.Text = 'モード: 未入力'
$lblMode.Location = New-Object System.Drawing.Point(16, 276)
$lblMode.Size = New-Object System.Drawing.Size(566, 22)
$form.Controls.Add($lblMode)

$btnTest = New-Object System.Windows.Forms.Button
$btnTest.Text = 'Stripe接続テスト'
$btnTest.Location = New-Object System.Drawing.Point(16, 306)
$btnTest.Size = New-Object System.Drawing.Size(140, 34)
$form.Controls.Add($btnTest)

$btnMigrateOnly = New-Object System.Windows.Forms.Button
$btnMigrateOnly.Text = 'テーブル初期化のみ'
$btnMigrateOnly.Location = New-Object System.Drawing.Point(164, 306)
$btnMigrateOnly.Size = New-Object System.Drawing.Size(150, 34)
$form.Controls.Add($btnMigrateOnly)

$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Text = '保存して適用'
$btnSave.Location = New-Object System.Drawing.Point(322, 306)
$btnSave.Size = New-Object System.Drawing.Size(140, 34)
$form.Controls.Add($btnSave)

$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = '閉じる'
$btnClose.Location = New-Object System.Drawing.Point(470, 306)
$btnClose.Size = New-Object System.Drawing.Size(112, 34)
$btnClose.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($btnClose)

$log = New-Object System.Windows.Forms.TextBox
$log.Location = New-Object System.Drawing.Point(16, 352)
$log.Size = New-Object System.Drawing.Size(566, 190)
$log.Multiline = $true
$log.ReadOnly = $true
$log.ScrollBars = 'Vertical'
$log.BackColor = [System.Drawing.Color]::White
$form.Controls.Add($log)

$form.AcceptButton = $btnSave
$form.CancelButton = $btnClose

function Write-Log([string] $Message) {
    $line = (Get-Date -Format 'HH:mm:ss') + ' ' + $Message
    $log.AppendText($line + "`r`n")
    $log.SelectionStart = $log.TextLength
    $log.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

function Set-Busy([bool] $Busy) {
    $btnTest.Enabled = -not $Busy
    $btnMigrateOnly.Enabled = -not $Busy
    $btnSave.Enabled = -not $Busy
    $cboTarget.Enabled = -not $Busy
    $form.UseWaitCursor = $Busy
    [System.Windows.Forms.Application]::DoEvents()
}

$chkShowKey.Add_CheckedChanged({ $txtKey.UseSystemPasswordChar = -not $chkShowKey.Checked })
$chkShowWebhook.Add_CheckedChanged({ $txtWebhook.UseSystemPasswordChar = -not $chkShowWebhook.Checked })
$txtKey.Add_TextChanged({
    if ($txtKey.Text -match '^sk_test_') { $lblMode.Text = 'モード: テスト（sk_test_）'; $chkLive.Checked = $false; $chkLive.Enabled = $false }
    elseif ($txtKey.Text -match '^sk_live_') { $lblMode.Text = 'モード: 本番（sk_live_）'; $chkLive.Enabled = $true }
    else { $lblMode.Text = 'モード: 未入力 / 形式エラー'; $chkLive.Enabled = $false; $chkLive.Checked = $false }
})

$btnTest.Add_Click({
    $btnTest.Enabled = $false
    try {
        $key = $txtKey.Text.Trim()
        $mode = Test-StripeKeyFormat $key
        Write-Log "Stripeへ接続確認しています（$mode モード）…"
        $balance = Invoke-StripeBalanceCheck $key
        $live = if ($null -ne $balance.livemode) { [bool]$balance.livemode } else { $mode -eq 'live' }
        Write-Log "接続OK: livemode=$live / available=$(@($balance.available).Count) currency bucket(s)"
        if ($mode -eq 'live' -and -not $live) { Write-Log '警告: 本番キーですが livemode=false が返りました。キーを確認してください。' }
    } catch {
        Write-Log ('接続テスト失敗: ' + $_.Exception.Message)
    } finally { $btnTest.Enabled = $true }
})

$btnSave.Add_Click({
    Set-Busy $true
    try {
        $key = $txtKey.Text.Trim().Trim('"').Trim("'")
        $webhook = $txtWebhook.Text.Trim().Trim('"').Trim("'")
        $returnBase = $txtReturn.Text.Trim()
        $mode = Test-StripeKeyFormat $key
        if ([string]::IsNullOrEmpty($webhook)) {
            throw 'Webhook署名シークレットが空です。Stripeダッシュボードの「Webhook」→対象エンドポイント→「Signing secret」（whsec_…）を入力してください。APIキーとは別の値です。'
        }
        if ($webhook -notmatch '^whsec_[A-Za-z0-9+/=_\-]{8,}$') {
            throw ("Webhook署名シークレットの形式を確認してください（whsec_ で始まる英数字・記号。引用符や空白は自動で除去します）。現在の文字数: " + $webhook.Length)
        }
        if ($returnBase -and $returnBase -notmatch '^https://[^\s]+$') { throw '戻り先ベースURLは https:// で始まるURLを入力してください。' }
        if ($mode -eq 'live' -and -not $chkLive.Checked) { throw '本番キーを保存するには「本番キーを有効化する」をチェックしてください。' }
        if ($mode -eq 'test' -and $chkLive.Checked) { throw 'テストキーでは本番有効化をチェックできません。' }

        if ($mode -eq 'live') {
            $answer = [System.Windows.Forms.MessageBox]::Show(
                "本番キー（sk_live_）で保存します。`r`n有効化すると実際のカード請求が発生します。続けますか？",
                '本番キーの確認', 'YesNo', 'Warning')
            if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { Write-Log '本番キーの保存を中止しました。'; return }
        }

        Write-Log "Stripe接続確認（$mode モード）…"
        $null = Invoke-StripeBalanceCheck $key

        $updates = @{
            stripe_secret_key     = $key
            stripe_webhook_secret = $webhook
        }
        $remove = @()
        if ($returnBase) { $updates['stripe_return_base_url'] = $returnBase } else { $remove += 'stripe_return_base_url' }
        if ($mode -eq 'live' -and $chkLive.Checked) { $updates['stripe_enable_live'] = '1' } else { $remove += 'stripe_enable_live' }

        $selected = @($allTargets | Where-Object { $cboTarget.SelectedItem -eq 'Both' -or $_.Name -eq $cboTarget.SelectedItem })
        $failures = @()
        foreach ($destination in $selected) {
            try {
                Write-Log "$($destination.Name): 設定を書き込みます…"
                $credential = Get-CredentialForTarget $destination
                $result = Update-RemoteSecrets $destination $credential $updates $remove
                Write-Log "$($destination.Name): 保存しました（DPAPIバックアップ: $($result.Backup)）"
                if ($chkMigrate.Checked) {
                    Write-Log "$($destination.Name): $((Invoke-StripeSchemaMigration $destination $result.Secrets))"
                }
            } catch {
                $failures += "$($destination.Name): $($_.Exception.Message)"
                Write-Log "$($destination.Name): 失敗しました - $($_.Exception.Message)"
            }
        }
        if ($failures.Count) { throw ("一部のノードで設定できませんでした。`r`n" + ($failures -join "`r`n")) }
        Write-Log '完了しました。StripeダッシュボードのWebhook送信先と署名シークレットが一致しているか確認してください。'
        [void][System.Windows.Forms.MessageBox]::Show('Stripe設定を保存しました。', 'Stripe請求設定', 'OK', 'Information')
        $txtKey.Clear()
        $txtWebhook.Clear()
    } catch {
        Write-Log ('保存できませんでした: ' + $_.Exception.Message)
        [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Stripe設定エラー', 'OK', 'Error')
    } finally { Set-Busy $false }
})

$btnMigrateOnly.Add_Click({
    Set-Busy $true
    try {
        $selected = @($allTargets | Where-Object { $cboTarget.SelectedItem -eq 'Both' -or $_.Name -eq $cboTarget.SelectedItem })
        $failures = @()
        foreach ($destination in $selected) {
            try {
                Write-Log "$($destination.Name): 非公開シークレットを読み取り、テーブルを初期化します…"
                $credential = Get-CredentialForTarget $destination
                $session = New-FtpSession $destination $credential
                try { $secrets = ConvertTo-SecretHashtable (Read-RemoteText $session (Get-RemoteSecretsPath $destination.Name)) }
                finally { $session.Dispose() }
                Write-Log "$($destination.Name): $((Invoke-StripeSchemaMigration $destination $secrets))"
            } catch {
                $failures += "$($destination.Name): $($_.Exception.Message)"
                Write-Log "$($destination.Name): 失敗しました - $($_.Exception.Message)"
            }
        }
        if ($failures.Count) { throw ("一部のノードで初期化できませんでした。`r`n" + ($failures -join "`r`n")) }
        [void][System.Windows.Forms.MessageBox]::Show('scope=stripe の初期化を実行しました。', 'Stripe請求設定', 'OK', 'Information')
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Stripe設定エラー', 'OK', 'Error')
    } finally { Set-Busy $false }
})

$btnClose.Add_Click({ $form.Close() })
$form.Add_FormClosed({ $form.Dispose() })
[void]$form.ShowDialog()
