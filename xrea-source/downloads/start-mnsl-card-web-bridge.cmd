@echo off
setlocal
where pwsh.exe >nul 2>nul
if errorlevel 1 (
  echo PowerShell 7 が見つかりません。PowerShell 7 x64 をインストールしてください。
  pause
  exit /b 1
)
pwsh.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0mnsl-card-web-bridge.ps1"
pause
