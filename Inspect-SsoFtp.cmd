@echo off
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0operations\SSO\Inspect-SsoFtp.ps1"
exit /b
