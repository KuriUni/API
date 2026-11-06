<#
.SYNOPSIS
  Unified Windows GUI launcher for the repository's operational PowerShell scripts.
.NOTES
  Run from Xrea-Operations.cmd. Credentials are entered by the individual task
  windows; this launcher never reads, saves, or writes credential material.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:OperationsRoot = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
$script:ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $script:OperationsRoot '..'))
$script:Tasks = @(
    [pscustomobject]@{ Group='サイト'; Name='XREAサイトを取得'; File='Xrea\Download-Xrea.ps1'; Description='s1004.xrea.com の公開ソースをローカルへダウンロードします。既定の保存先は xrea-source です。'; Risk='読み取り・ダウンロード' },
    [pscustomobject]@{ Group='サイト'; Name='XREA本番・バックアップへデプロイ'; File='Xrea\Deploy-Xrea.ps1'; Description='WinSCPとFTPSを使い、xrea-sourceを本番とバックアップへ同期します。キャッシュやローカルのバックアップ／ステージは転送しません。'; Risk='サーバー更新' },
    [pscustomobject]@{ Group='サイト'; Name='バックアップへ同期'; File='Xrea\Sync-XreaBackup.ps1'; Description='xrea-sourceをbackup.2415.jp側へ同期します。キャッシュ、ローカルバックアップ、ノード固有設定は転送せず、リモートだけのファイルも削除しません。'; Risk='サーバー更新' },
    [pscustomobject]@{ Group='サイト'; Name='ヘルプページをデプロイ'; File='Xrea\Deploy-TUTI-Help.ps1'; Description='TUTI-Help.htmlを2415.jpへアップロードし、公開済みファイルのバックアップとサイズ確認を行います。'; Risk='サーバー更新' },
    [pscustomobject]@{ Group='Sunabar'; Name='Sunabar Coreをデプロイ'; File='Sunabar\Deploy-SunaCore.ps1'; Description='Core Serverの指定ファイルをFTPSで配置し、公開ヘルスチェックを行います。DBパスワードは任意の更新時だけ入力します。'; Risk='サーバー更新' },
    [pscustomobject]@{ Group='Sunabar'; Name='Sunabar中継をデプロイ'; File='Sunabar\Deploy-Sunabar.ps1'; Description='2415.jp側のSunabar中継ファイルをバックアップ後に配置し、ハッシュと公開URLを確認します。'; Risk='サーバー更新' },
    [pscustomobject]@{ Group='Main.2415.jp'; Name='main.2415.jpへ同期'; File='MainSite\Deploy-Main2415.ps1'; Description='xrea-sourceをCore Serverのmain.2415.jp公開ルートへFTPS同期します。リモート専用ファイルとサーバー固有のfastapi-runtime.jsonは保持します。'; Risk='サーバー更新' },
    [pscustomobject]@{ Group='SSO'; Name='SSO FTP構成を確認'; File='SSO\Inspect-SsoFtp.ps1'; Description='Core ServerのFTP構成を読み取り確認します。ファイル変更は行いません。'; Risk='読み取り専用' },
    [pscustomobject]@{ Group='運用'; Name='HAトークンをローテーション'; File='Maintenance\Rotate-XreaHaToken.ps1'; Description='Primary/BackupのHA運用トークンを更新します。両サーバーの現在値をGUIで入力します。'; Risk='高影響・認証変更' },
    [pscustomobject]@{ Group='運用'; Name='V8データベース移行'; File='Maintenance\Run-XreaV8Migration.ps1'; Description='V8用データベース移行を実行します。バックアップと移行対象を確認してから実行してください。'; Risk='高影響・DB変更' }
)
$script:BackupSettingsPath = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'TutiOperations\settings.json'
$script:BackupGenerations = 3
try {
    if (Test-Path -LiteralPath $script:BackupSettingsPath -PathType Leaf) {
        $savedSettings = Get-Content -LiteralPath $script:BackupSettingsPath -Raw | ConvertFrom-Json
        $savedGenerations = [int]$savedSettings.backup_generations
        if ($savedGenerations -ge 1 -and $savedGenerations -le 20) { $script:BackupGenerations = $savedGenerations }
    }
} catch { $script:BackupGenerations = 3 }

$form = New-Object System.Windows.Forms.Form
$form.Text = 'TUTI / XREA 運用ツール'
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(780, 540)
$form.Size = New-Object System.Drawing.Size(920, 650)
$form.Font = New-Object System.Drawing.Font('Yu Gothic UI', 10)
$form.BackColor = [System.Drawing.Color]::FromArgb(244, 248, 247)

$header = New-Object System.Windows.Forms.Label
$header.Text = '運用ツール  |  操作を選んで実行'
$header.Font = New-Object System.Drawing.Font('Yu Gothic UI', 18, [System.Drawing.FontStyle]::Bold)
$header.Location = New-Object System.Drawing.Point(22, 18)
$header.Size = New-Object System.Drawing.Size(850, 36)
$form.Controls.Add($header)

$sub = New-Object System.Windows.Forms.Label
$sub.Text = '資格情報は各ツールの入力画面で扱います。このランチャーはパスワードやトークンを保存しません。'
$sub.Location = New-Object System.Drawing.Point(24, 58)
$sub.Size = New-Object System.Drawing.Size(630, 28)
$form.Controls.Add($sub)

$backupSettings = New-Object System.Windows.Forms.Button
$backupSettings.Text = "バックアップ保持: $($script:BackupGenerations) 世代"
$backupSettings.Location = New-Object System.Drawing.Point(674, 52)
$backupSettings.Size = New-Object System.Drawing.Size(202, 34)
$form.Controls.Add($backupSettings)

$backupSettings.add_Click({
    $script:BackupSettingsDialog = New-Object System.Windows.Forms.Form
    $script:BackupSettingsDialog.Text = 'バックアップ保持設定'
    $script:BackupSettingsDialog.StartPosition = 'CenterParent'
    $script:BackupSettingsDialog.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $script:BackupSettingsDialog.MaximizeBox = $false
    $script:BackupSettingsDialog.MinimizeBox = $false
    $script:BackupSettingsDialog.ClientSize = New-Object System.Drawing.Size(420, 190)
    $script:BackupSettingsDialog.Font = $form.Font
    $label = New-Object System.Windows.Forms.Label
    $label.Text = 'デプロイ系列ごとに残すバックアップ世代数（1～20）'
    $label.Location = New-Object System.Drawing.Point(18, 18)
    $label.Size = New-Object System.Drawing.Size(380, 26)
    $script:BackupSettingsDialog.Controls.Add($label)
    $script:BackupGenerationChoice = New-Object System.Windows.Forms.ComboBox
    $script:BackupGenerationChoice.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $script:BackupGenerationChoice.Location = New-Object System.Drawing.Point(20, 52)
    $script:BackupGenerationChoice.Size = New-Object System.Drawing.Size(120, 28)
    foreach ($count in 1..20) { [void]$script:BackupGenerationChoice.Items.Add([string]$count) }
    $script:BackupGenerationChoice.SelectedItem = [string]$script:BackupGenerations
    $script:BackupSettingsDialog.Controls.Add($script:BackupGenerationChoice)
    $note = New-Object System.Windows.Forms.Label
    $note.Text = '次回以降のデプロイ成功後に、古い世代を自動削除します。'
    $note.Location = New-Object System.Drawing.Point(20, 91)
    $note.Size = New-Object System.Drawing.Size(380, 28)
    $script:BackupSettingsDialog.Controls.Add($note)
    $save = New-Object System.Windows.Forms.Button
    $save.Text = '保存'
    $save.Location = New-Object System.Drawing.Point(206, 137)
    $save.Size = New-Object System.Drawing.Size(90, 34)
    $script:BackupSettingsDialog.Controls.Add($save)
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'キャンセル'
    $cancel.Location = New-Object System.Drawing.Point(306, 137)
    $cancel.Size = New-Object System.Drawing.Size(100, 34)
    $script:BackupSettingsDialog.Controls.Add($cancel)
    $cancel.add_Click({ $script:BackupSettingsDialog.Close() })
    $save.add_Click({
        $count = [int]$script:BackupGenerationChoice.SelectedItem
        try {
            $directory = Split-Path -Path $script:BackupSettingsPath -Parent
            if (-not (Test-Path -LiteralPath $directory -PathType Container)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
            $json = @{ backup_generations = $count } | ConvertTo-Json -Compress
            [System.IO.File]::WriteAllText($script:BackupSettingsPath, $json, [System.Text.UTF8Encoding]::new($false))
            $script:BackupGenerations = $count
            $backupSettings.Text = "バックアップ保持: $count 世代"
            $status.Text = "バックアップ保持数を$count 世代に保存しました。"
            $script:BackupSettingsDialog.Close()
        } catch {
            [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, '設定を保存できません', 'OK', 'Error')
        }
    })
    [void]$script:BackupSettingsDialog.ShowDialog($form)
})

$groupLabel = New-Object System.Windows.Forms.Label
$groupLabel.Text = 'カテゴリ'
$groupLabel.Location = New-Object System.Drawing.Point(24, 102)
$groupLabel.Size = New-Object System.Drawing.Size(120, 24)
$form.Controls.Add($groupLabel)

$group = New-Object System.Windows.Forms.ComboBox
$group.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$group.Location = New-Object System.Drawing.Point(24, 128)
$group.Size = New-Object System.Drawing.Size(250, 30)
[void]$group.Items.Add('すべて')
foreach ($item in ($script:Tasks.Group | Sort-Object -Unique)) { [void]$group.Items.Add($item) }
[void]$group.Items.Add('高度な個別スクリプト')
$group.SelectedIndex = 0
$form.Controls.Add($group)

$list = New-Object System.Windows.Forms.ListBox
$list.Location = New-Object System.Drawing.Point(24, 170)
$list.Size = New-Object System.Drawing.Size(340, 330)
$list.IntegralHeight = $false
$form.Controls.Add($list)

$detail = New-Object System.Windows.Forms.Panel
$detail.Location = New-Object System.Drawing.Point(386, 103)
$detail.Size = New-Object System.Drawing.Size(490, 397)
$detail.BackColor = [System.Drawing.Color]::White
$detail.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$form.Controls.Add($detail)

$taskTitle = New-Object System.Windows.Forms.Label
$taskTitle.Location = New-Object System.Drawing.Point(18, 18)
$taskTitle.Size = New-Object System.Drawing.Size(450, 32)
$taskTitle.Font = New-Object System.Drawing.Font('Yu Gothic UI', 14, [System.Drawing.FontStyle]::Bold)
$detail.Controls.Add($taskTitle)

$risk = New-Object System.Windows.Forms.Label
$risk.Location = New-Object System.Drawing.Point(20, 58)
$risk.Size = New-Object System.Drawing.Size(440, 26)
$risk.ForeColor = [System.Drawing.Color]::DarkSlateBlue
$detail.Controls.Add($risk)

$description = New-Object System.Windows.Forms.Label
$description.Location = New-Object System.Drawing.Point(20, 96)
$description.Size = New-Object System.Drawing.Size(440, 125)
$description.AutoSize = $false
$detail.Controls.Add($description)

$scriptName = New-Object System.Windows.Forms.Label
$scriptName.Location = New-Object System.Drawing.Point(20, 235)
$scriptName.Size = New-Object System.Drawing.Size(440, 42)
$scriptName.ForeColor = [System.Drawing.Color]::DimGray
$detail.Controls.Add($scriptName)

$run = New-Object System.Windows.Forms.Button
$run.Text = '選択した操作を起動'
$run.Location = New-Object System.Drawing.Point(20, 300)
$run.Size = New-Object System.Drawing.Size(205, 42)
$run.Enabled = $false
$detail.Controls.Add($run)

$openFolder = New-Object System.Windows.Forms.Button
$openFolder.Text = 'スクリプトの場所を開く'
$openFolder.Location = New-Object System.Drawing.Point(238, 300)
$openFolder.Size = New-Object System.Drawing.Size(205, 42)
$openFolder.Enabled = $false
$detail.Controls.Add($openFolder)

$status = New-Object System.Windows.Forms.Label
$status.Location = New-Object System.Drawing.Point(24, 520)
$status.Size = New-Object System.Drawing.Size(850, 28)
$status.Text = '準備完了'
$form.Controls.Add($status)

$advanced = @(
    [pscustomobject]@{ Name='汎用アップロード（要パス指定）'; File='Xrea\Upload-Xrea.ps1'; Description='任意フォルダーを任意のXREA公開パスへ送る汎用ツールです。誤配備防止のためランチャーからは直接起動しません。'; Risk='上級者向け・要確認' },
    [pscustomobject]@{ Name='SSO Core旧単体配備'; File='SSO\Deploy-SsoTenantInvite.ps1'; Description='server.pyのみを配置する旧スクリプトです。スクリプトの文字コードと配置先を確認してから個別起動してください。'; Risk='旧版・要確認' }
)
$script:VisibleTasks = @()

function Update-TaskList {
    $list.Items.Clear()
    if ($group.SelectedItem -eq '高度な個別スクリプト') {
        $script:VisibleTasks = @($advanced)
    } elseif ($group.SelectedItem -eq 'すべて') {
        $script:VisibleTasks = @($script:Tasks)
    } else {
        $script:VisibleTasks = @($script:Tasks | Where-Object Group -eq ([string]$group.SelectedItem))
    }
    foreach ($task in $script:VisibleTasks) { [void]$list.Items.Add($task.Name) }
    $list.ClearSelected()
    $taskTitle.Text = '操作を選択してください'
    $risk.Text = ''
    $description.Text = ''
    $scriptName.Text = ''
    $run.Enabled = $false
    $openFolder.Enabled = $false
}

$group.add_SelectedIndexChanged({ Update-TaskList })
$list.add_SelectedIndexChanged({
    if ($list.SelectedIndex -lt 0) { return }
    $task = $script:VisibleTasks[$list.SelectedIndex]
    $taskTitle.Text = $task.Name
    $risk.Text = '区分: ' + $task.Risk
    $description.Text = $task.Description
    $scriptName.Text = 'ファイル: ' + $task.File
    $exists = Test-Path -LiteralPath (Join-Path $script:OperationsRoot $task.File) -PathType Leaf
    $run.Enabled = $exists -and $task.Risk -notlike '*上級者向け*' -and $task.Risk -notlike '*旧版*' -and $task.Risk -notlike '*要確認*'
    $openFolder.Enabled = $exists
    if (-not $exists) { $status.Text = 'スクリプトが見つかりません: ' + $task.File }
})

$openFolder.add_Click({
    if ($list.SelectedIndex -lt 0) { return }
    $task = $script:VisibleTasks[$list.SelectedIndex]
    Start-Process -FilePath 'explorer.exe' -ArgumentList ('/select,"' + (Join-Path $script:OperationsRoot $task.File) + '"')
})

$run.add_Click({
    if ($list.SelectedIndex -lt 0) { return }
    $task = $script:VisibleTasks[$list.SelectedIndex]
    $path = Join-Path $script:OperationsRoot $task.File
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        [void][System.Windows.Forms.MessageBox]::Show('対象スクリプトが見つかりません。', '起動できません', 'OK', 'Error')
        return
    }
    if ($task.Risk -like '*高影響*') {
        $answer = [System.Windows.Forms.MessageBox]::Show(($task.Name + "`r`n" + $task.Description + "`r`n`r`n内容を確認し、続行しますか？"), '高影響操作の確認', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning, [System.Windows.Forms.MessageBoxDefaultButton]::Button2)
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    } elseif ($task.Risk -like '*要確認*') {
        [void][System.Windows.Forms.MessageBox]::Show('旧個別スクリプトはこのランチャーから起動できません。ファイルを開き、接続先と内容を確認してください。', '起動を制限しました', 'OK', 'Warning')
        return
    }
    $engine = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path -LiteralPath $engine -PathType Leaf)) { $engine = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' }
    try {
        $runner = Join-Path $script:OperationsRoot 'Invoke-XreaOperation.ps1'
        $arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "{0}" -ScriptPath "{1}" -OperationsRoot "{2}" -WorkingDirectory "{3}"' -f $runner, $path, $script:OperationsRoot, $script:ProjectRoot
        Start-Process -FilePath $engine -ArgumentList $arguments -WorkingDirectory $script:ProjectRoot -WindowStyle Hidden
        $status.Text = '起動しました: ' + $task.Name + '（資格情報は個別画面に入力してください）'
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, '起動に失敗しました', 'OK', 'Error')
    }
})

Update-TaskList
[void]$form.ShowDialog()
