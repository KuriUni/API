param(
    [int] $Port = 8765,
    [switch] $NoBrowser
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$python = Join-Path $root '.venv\Scripts\python.exe'
$stdoutLog = Join-Path $root 'business-ops.stdout.log'
$stderrLog = Join-Path $root 'business-ops.stderr.log'
$requirementsFile = Join-Path $root 'requirements.txt'
$requirementsStamp = Join-Path $root '.venv\.requirements-lock.sha256'
$baseUrl = "http://127.0.0.1:$Port"

if (-not (Test-Path -LiteralPath $python)) {
    Write-Host 'Python virtual environment is missing. Creating it...'
    python -m venv (Join-Path $root '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Python virtual environment creation failed.' }
}

$importsReady = $false
& $python -c 'import fastapi, uvicorn, cryptography' 2>$null
if ($LASTEXITCODE -eq 0) { $importsReady = $true }
$expectedLockHash = (Get-FileHash -LiteralPath $requirementsFile -Algorithm SHA256).Hash
$installedLockHash = if (Test-Path -LiteralPath $requirementsStamp) { (Get-Content -LiteralPath $requirementsStamp -Raw).Trim() } else { '' }
if (-not $importsReady -or $installedLockHash -ne $expectedLockHash) {
    Write-Host 'Installing pinned and locked packages...'
    & $python -m pip install --disable-pip-version-check -r $requirementsFile
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
    Set-Content -LiteralPath $requirementsStamp -Value $expectedLockHash -Encoding ascii -NoNewline
}

$running = $false
try {
    $null = Invoke-WebRequest -Uri "$baseUrl/api/healthz" -TimeoutSec 2 -UseBasicParsing
    $running = $true
} catch { }

if (-not $running) {
    $process = Start-Process -FilePath $python `
        -ArgumentList @('-m', 'uvicorn', 'main:app', '--host', '127.0.0.1', '--port', [string]$Port) `
        -WorkingDirectory $root -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog

    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        Start-Sleep -Milliseconds 500
        if ($process.HasExited) { break }
        try {
            $health = Invoke-RestMethod -Uri "$baseUrl/api/healthz" -TimeoutSec 2
            if ($health.ok -and $health.database -eq 'ok') { $ready = $true; break }
        } catch { }
    }
    if (-not $ready) {
        $details = if (Test-Path -LiteralPath $stderrLog) { (Get-Content -LiteralPath $stderrLog -Tail 30) -join "`n" } else { 'No server log was created.' }
        throw "業務運用Webアプリを起動できませんでした。`n$details"
    }
}

Write-Host "業務運用Webアプリは起動しています: $baseUrl"
Write-Host 'SSOクライアント未設定の場合、トップ画面は表示されますがSSOログインは利用できません。'
if (-not $NoBrowser) { Start-Process $baseUrl }
