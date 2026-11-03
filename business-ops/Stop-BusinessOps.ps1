param([int] $Port = 8765)
$ErrorActionPreference = 'Stop'
$connections = Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if (-not $connections) { Write-Host '業務運用Webアプリは停止しています。'; exit 0 }
$pids = @($connections | Select-Object -ExpandProperty OwningProcess -Unique)
foreach ($processId in $pids) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $processId"
    if ($process -and $process.CommandLine -match 'uvicorn main:app') {
        Stop-Process -Id $processId -Force
        Write-Host '業務運用Webアプリを停止しました。'
    } else {
        throw "Port $Port is used by a different process (PID $processId); it was not stopped."
    }
}
