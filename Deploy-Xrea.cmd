@echo off
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0Deploy-Xrea.ps1"
exit /b
