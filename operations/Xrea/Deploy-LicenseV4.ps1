#requires -Version 7.0
[CmdletBinding()]
param([ValidateSet('Both','Primary','Backup')][string] $Target = 'Both')
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Deploy-V8Cutover.ps1') -Target $Target -Profile LicenseV4
