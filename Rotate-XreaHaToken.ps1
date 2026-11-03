Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'

$form = New-Object System.Windows.Forms.Form
$form.Text = 'XREA HA token rotation'
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.TopMost = $true
$form.ClientSize = New-Object System.Drawing.Size(590, 280)

$label = New-Object System.Windows.Forms.Label
$label.Text = '現在のha:operateトークンを各サーバー分入力してください。値は表示・ログ出力しません。'
$label.Location = New-Object System.Drawing.Point(16, 14)
$label.Size = New-Object System.Drawing.Size(556, 34)
$form.Controls.Add($label)

$primaryLabel = New-Object System.Windows.Forms.Label
$primaryLabel.Text = 'Primary: 2415.jp'
$primaryLabel.Location = New-Object System.Drawing.Point(16, 56)
$primaryLabel.Size = New-Object System.Drawing.Size(150, 24)
$form.Controls.Add($primaryLabel)
$primaryBox = New-Object System.Windows.Forms.TextBox
$primaryBox.Location = New-Object System.Drawing.Point(174, 53)
$primaryBox.Size = New-Object System.Drawing.Size(396, 25)
$primaryBox.UseSystemPasswordChar = $true
$form.Controls.Add($primaryBox)

$backupLabel = New-Object System.Windows.Forms.Label
$backupLabel.Text = 'Backup: backup.2415.jp'
$backupLabel.Location = New-Object System.Drawing.Point(16, 91)
$backupLabel.Size = New-Object System.Drawing.Size(155, 24)
$form.Controls.Add($backupLabel)
$backupBox = New-Object System.Windows.Forms.TextBox
$backupBox.Location = New-Object System.Drawing.Point(174, 88)
$backupBox.Size = New-Object System.Drawing.Size(396, 25)
$backupBox.UseSystemPasswordChar = $true
$form.Controls.Add($backupBox)

$sameBox = New-Object System.Windows.Forms.CheckBox
$sameBox.Text = '両サーバーで同じ現在トークンを使用'
$sameBox.Location = New-Object System.Drawing.Point(174, 119)
$sameBox.Size = New-Object System.Drawing.Size(396, 24)
$sameBox.Checked = $true
$form.Controls.Add($sameBox)
$primaryBox.Add_TextChanged({ if ($sameBox.Checked) { $backupBox.Text = $primaryBox.Text } })
$sameBox.Add_CheckedChanged({ $backupBox.Enabled = -not $sameBox.Checked; if ($sameBox.Checked) { $backupBox.Text = $primaryBox.Text } })

$sessionBox = New-Object System.Windows.Forms.CheckBox
$sessionBox.Text = '入力値はHAトークンではなく管理者セッション'
$sessionBox.Location = New-Object System.Drawing.Point(174, 146)
$sessionBox.Size = New-Object System.Drawing.Size(396, 24)
$form.Controls.Add($sessionBox)

$hint = New-Object System.Windows.Forms.Label
$hint.Text = '新しい暗号学的乱数トークンを生成し、両サーバーを更新します。新トークンはこのWindowsユーザーのDPAPIで保存します。'
$hint.Location = New-Object System.Drawing.Point(16, 174)
$hint.Size = New-Object System.Drawing.Size(556, 39)
$form.Controls.Add($hint)

$ok = New-Object System.Windows.Forms.Button
$ok.Text = '両サーバーを更新'
$ok.Location = New-Object System.Drawing.Point(365, 235)
$ok.Size = New-Object System.Drawing.Size(120, 30)
$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.Controls.Add($ok)
$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = 'キャンセル'
$cancel.Location = New-Object System.Drawing.Point(490, 235)
$cancel.Size = New-Object System.Drawing.Size(80, 30)
$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($cancel)
$form.AcceptButton = $ok
$form.CancelButton = $cancel

function New-RotationToken {
    $bytes = New-Object byte[] 48
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$tokenPath = Join-Path $env:LOCALAPPDATA 'XreaDeploy\ha-sync-token.xml'
$primaryChanged = $false
$backupChanged = $false
$newToken = $null
try {
    if ($form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { Write-Host 'Cancelled.'; exit 2 }
    $primaryCurrent = $primaryBox.Text
    $backupCurrent = if ($sameBox.Checked) { $primaryCurrent } else { $backupBox.Text }
    if ([string]::IsNullOrWhiteSpace($primaryCurrent) -or [string]::IsNullOrWhiteSpace($backupCurrent)) { throw '現在のトークンを両方入力してください。' }

    $newToken = New-RotationToken
    $headerName = if ($sessionBox.Checked) { 'X-HA-Session' } else { 'X-HA-Token' }
    $targets = @(
        [pscustomobject]@{ Name = 'Primary'; Uri = 'https://2415.jp/license/ha/mode.php'; Token = $primaryCurrent },
        [pscustomobject]@{ Name = 'Backup'; Uri = 'https://backup.2415.jp/license/ha/mode.php'; Token = $backupCurrent }
    )
    $failures = @()
    foreach ($target in $targets) {
        try {
            $headers = @{ Accept = 'application/json' }
            $headers[$headerName] = $target.Token
            $result = Invoke-RestMethod -Uri $target.Uri -Method Post -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body @{ action = 'rotate-token'; new_token = $newToken } -TimeoutSec 30
            if ($result.ok -ne $true -or $result.rotated -ne $true) { throw 'API did not confirm rotation.' }
            if ($target.Name -eq 'Primary') { $primaryChanged = $true } else { $backupChanged = $true }
        }
        catch {
            $status = 'network/API error'
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) { $status = 'HTTP ' + [int]$_.Exception.Response.StatusCode }
            $failures += ($target.Name + ': ' + $status)
        }
    }

    if ($primaryChanged -or $backupChanged) {
        $tokenDirectory = Split-Path -Parent $tokenPath
        if (-not (Test-Path -LiteralPath $tokenDirectory -PathType Container)) { New-Item -ItemType Directory -Path $tokenDirectory -Force | Out-Null }
        $secureNew = ConvertTo-SecureString -String $newToken -AsPlainText -Force
        New-Object System.Management.Automation.PSCredential('ha-sync-token', $secureNew) | Export-Clixml -LiteralPath $tokenPath -Force
    }

    if ($failures.Count -eq 0) {
        [void][System.Windows.Forms.MessageBox]::Show("両サーバーのトークンを更新しました。`r`n新トークンはDPAPIで保存済みです。`r`n保存先: $tokenPath", 'HA token rotation', 'OK', 'Information')
        Write-Host 'Both XREA HA tokens rotated.'
    } else {
        $state = "Primary updated: $primaryChanged`r`nBackup updated: $backupChanged`r`n$($failures -join "`r`n")"
        [void][System.Windows.Forms.MessageBox]::Show("両サーバーの更新を確認できませんでした。`r`n$state", 'HA token rotation incomplete', 'OK', 'Warning')
        Write-Error 'Token rotation was not confirmed on both servers.'
        exit 1
    }
}
catch {
    [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'HA token rotation failed', 'OK', 'Error')
    Write-Error $_.Exception.Message
    exit 1
}
finally {
    $primaryBox.Clear(); $backupBox.Clear()
    $primaryCurrent = $null; $backupCurrent = $null; $newToken = $null; $secureNew = $null
    $form.Dispose()
}
