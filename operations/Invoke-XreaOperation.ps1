[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string] $ScriptPath,
    [Parameter(Mandatory=$true)][string] $OperationsRoot,
    [Parameter(Mandatory=$true)][string] $WorkingDirectory
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms

try {
    $base = [System.IO.Path]::GetFullPath($OperationsRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    $target = [System.IO.Path]::GetFullPath($ScriptPath)
    if (-not $target.StartsWith($base, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The selected script is outside the operations folder.'
    }
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
        throw 'The selected operations script was not found.'
    }
    Set-Location -LiteralPath $WorkingDirectory
    & $target
} catch {
    $message = [string]$_.Exception.Message
    if ([string]::IsNullOrWhiteSpace($message)) { $message = '処理に失敗しました。' }
    [void][System.Windows.Forms.MessageBox]::Show($message, '運用処理に失敗しました', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}
