<#
.SYNOPSIS
  Preview the local XREA differential upload without connecting or requesting credentials.
#>
[CmdletBinding()]
param([string] $LocalPath)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
. (Join-Path $PSScriptRoot 'Invoke-XreaDifferentialUpload.ps1')
. (Join-Path $PSScriptRoot 'Xrea-DeployTargets.ps1')

if ([string]::IsNullOrWhiteSpace($LocalPath)) {
    $projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $LocalPath = Join-Path $projectRoot 'xrea-source'
}

try {
    $root = [System.IO.Path]::GetFullPath($LocalPath)
    $commonExcludes = @('(^|/)__pycache__(/|$)', '\.py[co]$', '(^|/)\.tuti-deploy-(backup|stage)-')
    $report = New-Object System.Text.StringBuilder
    [void]$report.AppendLine("送信元: $root")
    [void]$report.AppendLine('この確認はローカルの差分台帳だけを読みます。FTP接続・資格情報入力・ファイル変更は行いません。')
    [void]$report.AppendLine('')

    foreach ($target in (Get-XreaDeployTargets)) {
        $excludes = @($commonExcludes)
        if ($target.Name -eq 'Backup') { $excludes += '(^|/)fastapi-runtime\.json$' }
        $plan = Get-XreaDifferentialPlan -LocalRoot $root -StateKey "$($target.Host)|$($target.Remote)" -ExcludePatterns $excludes
        $changed = @($plan.Changed)
        $changedBytes = [long]0
        foreach ($item in $changed) { $changedBytes += [long]$item.Length }
        $sizeMiB = $changedBytes / 1MB
        $stateExists = Test-Path -LiteralPath $plan.StateFile -PathType Leaf
        $mode = if ($stateExists) { '差分' } else { '初回（全件）' }
        [void]$report.AppendLine("[$($target.Name)] $($target.Host):$($target.Remote)")
        [void]$report.AppendLine("方式: $mode　対象: $($changed.Count) / $($plan.Files.Count) ファイル　合計: $('{0:N2}' -f $sizeMiB) MiB")
        if ($changed.Count -eq 0) {
            [void]$report.AppendLine('変更ファイルはありません。')
        } else {
            foreach ($item in $changed) {
                [void]$report.AppendLine(('  {0,10:N0} bytes  {1}' -f $item.Length, $item.Relative))
            }
        }
        [void]$report.AppendLine('')
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'XREA 差分アップロード内容の確認'
    $form.StartPosition = 'CenterScreen'
    $form.MinimumSize = New-Object System.Drawing.Size(740, 480)
    $form.Size = New-Object System.Drawing.Size(980, 720)
    $form.Font = New-Object System.Drawing.Font('Yu Gothic UI', 10)

    $text = New-Object System.Windows.Forms.TextBox
    $text.Multiline = $true
    $text.ReadOnly = $true
    $text.WordWrap = $false
    $text.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
    $text.Dock = [System.Windows.Forms.DockStyle]::Fill
    $text.Font = New-Object System.Drawing.Font('Consolas', 9)
    $text.Text = $report.ToString()
    $form.Controls.Add($text)

    $buttons = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttons.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $buttons.Height = 52
    $buttons.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
    $copy = New-Object System.Windows.Forms.Button
    $copy.Text = '一覧をコピー'
    $copy.Width = 120
    $copy.Add_Click({ [System.Windows.Forms.Clipboard]::SetText($text.Text) })
    $close = New-Object System.Windows.Forms.Button
    $close.Text = '閉じる'
    $close.Width = 100
    $close.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    [void]$buttons.Controls.Add($close)
    [void]$buttons.Controls.Add($copy)
    $form.Controls.Add($buttons)
    $form.CancelButton = $close
    [void]$form.ShowDialog()
}
catch {
    [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, '差分プレビューに失敗しました', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}
