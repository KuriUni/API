@echo off
setlocal
where pwsh.exe >nul 2>nul
if errorlevel 1 (
  echo PowerShell 7 ^(pwsh^) was not found. Install it from https://aka.ms/powershell and run this file again.
  pause
  exit /b 1
)
start "" pwsh.exe -NoLogo -NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File "%~dp0operations\Xrea\Configure-StripeBilling.ps1"
exit /b 0
