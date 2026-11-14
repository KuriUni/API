#requires -Version 7.0
[CmdletBinding()]
param(
    [int] $Port = 8766,
    [string] $Bind = '127.0.0.1'
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$python = Join-Path $PSScriptRoot '..\business-ops\.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    $python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
}
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'Python venv was not found. Create one with: py -m venv .venv; .\.venv\Scripts\pip install -r requirements.txt'
}

if (-not $env:CRM_DATA) {
    $env:CRM_DATA = Join-Path $PSScriptRoot 'data'
}
if (-not $env:CRM_PASSWORD) {
    $env:CRM_PASSWORD = 'demo'
    Write-Host 'DEMO MODE: login with admin / demo. Set CRM_PASSWORD for any shared or production environment.' -ForegroundColor Yellow
}
if (-not $env:CRM_SESSION_KEY) {
    Write-Host 'CRM_SESSION_KEY is not set; a temporary key will be generated for this process.' -ForegroundColor DarkYellow
}
if (-not $env:CRM_SECURE_COOKIES) {
    $env:CRM_SECURE_COOKIES = '0'
}

Write-Host "TUTI CRM: http://${Bind}:$Port/"
& $python -m uvicorn main:app --host $Bind --port $Port
