Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = 'Stop'
$form = New-Object System.Windows.Forms.Form
$form.Text = 'TUTI V8 database setup'
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.TopMost = $true
$form.ClientSize = New-Object System.Drawing.Size(520, 172)

$label = New-Object System.Windows.Forms.Label
$label.Text = 'HA運用トークンを入力してください。値は保存も表示もされません。'
$label.Location = New-Object System.Drawing.Point(16, 16)
$label.Size = New-Object System.Drawing.Size(485, 28)
$form.Controls.Add($label)

$box = New-Object System.Windows.Forms.TextBox
$box.Location = New-Object System.Drawing.Point(16, 50)
$box.Size = New-Object System.Drawing.Size(485, 26)
$box.UseSystemPasswordChar = $true
$form.Controls.Add($box)

$ok = New-Object System.Windows.Forms.Button
$ok.Text = '移行を実行'
$ok.Location = New-Object System.Drawing.Point(316, 112)
$ok.Size = New-Object System.Drawing.Size(90, 30)
$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.Controls.Add($ok)

$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = 'キャンセル'
$cancel.Location = New-Object System.Drawing.Point(411, 112)
$cancel.Size = New-Object System.Drawing.Size(90, 30)
$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($cancel)
$form.AcceptButton = $ok
$form.CancelButton = $cancel

$token = $null
try {
    if ($form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-Host 'Cancelled.'
        exit 2
    }
    if ([string]::IsNullOrWhiteSpace($box.Text)) {
        throw 'トークンが入力されていません。'
    }
    $token = $box.Text
    $box.Clear()
    $headers = @{ 'X-HA-Token' = $token; Accept = 'application/json' }

    $migration = Invoke-RestMethod -Uri 'https://2415.jp/license/ha/migrate.php' `
        -Method Post -Headers $headers -ContentType 'application/json' -Body '{}' -TimeoutSec 120
    if ($migration.ok -ne $true -or $migration.product_key_issuance_v8.ok -ne $true) {
        throw 'V8データベース移行が完了しませんでした。'
    }

    $workerBody = '{"budget_ms":20000,"max_jobs":8}'
    $worker = Invoke-RestMethod -Uri 'https://2415.jp/license/ha/product-key-v8-worker.php' `
        -Method Post -Headers $headers -ContentType 'application/json' -Body $workerBody -TimeoutSec 90
    if ($worker.ok -ne $true) {
        throw '移行は完了しましたが、V8ワーカーの起動確認に失敗しました。'
    }

    [void][System.Windows.Forms.MessageBox]::Show(
        "V8データベース移行とワーカー確認が完了しました。`r`n`r`n移行: $($migration.product_key_issuance_v8.migration)`r`nワーカー: $($worker.worker)",
        'TUTI V8 setup', [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information)
    Write-Host 'V8 migration and worker check completed.'
}
catch {
    $status = $null
    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
        $status = [int]$_.Exception.Response.StatusCode
    }
    $message = if ($status -eq 404) {
        'HA運用トークンが無効か、HA運用権限がありません。'
    } elseif ($status) {
        "HTTP $status : $($_.Exception.Message)"
    } else {
        $_.Exception.Message
    }
    [void][System.Windows.Forms.MessageBox]::Show(
        $message, 'TUTI V8 setup failed', [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error)
    Write-Error $message
    exit 1
}
finally {
    $box.Clear()
    $token = $null
    $headers = $null
    $form.Dispose()
}
