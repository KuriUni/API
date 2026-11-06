[CmdletBinding(SupportsShouldProcess)]
param([ValidateRange(1, 20)][int] $Keep = 3)

$ErrorActionPreference = 'Stop'
$backupRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\deploy-backups'))
if (-not (Test-Path -LiteralPath $backupRoot -PathType Container)) { return }
$rootPrefix = $backupRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
$entries = foreach ($directory in Get-ChildItem -LiteralPath $backupRoot -Directory) {
    if ($directory.Name -match '^(?<series>.+)-(?<stamp>\d{8}-\d{6})$') {
        [pscustomobject]@{ Series=$Matches.series; Stamp=$Matches.stamp; Path=$directory.FullName }
    }
}

$removed = 0
foreach ($group in ($entries | Group-Object Series)) {
    $ordered = @($group.Group | Sort-Object Stamp -Descending)
    foreach ($entry in ($ordered | Select-Object -Skip $Keep)) {
        $resolved = [System.IO.Path]::GetFullPath($entry.Path)
        if (-not $resolved.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove a path outside deploy-backups: $resolved"
        }
        if ($PSCmdlet.ShouldProcess($resolved, 'Remove old deployment backup generation')) {
            Remove-Item -LiteralPath $resolved -Recurse -Force
            $removed++
            Write-Host "Removed old backup generation: $($entry.Series)-$($entry.Stamp)"
        }
    }
}

# The main-site synchronization keeps dated snapshots inside the source tree.
# Retain the same number there as in deploy-backups.
$xreaSourceRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\xrea-source'))
if (Test-Path -LiteralPath $xreaSourceRoot -PathType Container) {
    $xreaPrefix = $xreaSourceRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    $xreaEntries = foreach ($directory in Get-ChildItem -LiteralPath $xreaSourceRoot -Directory -Force) {
        if ($directory.Name -match '^\.tuti-deploy-backup-(?<stamp>\d{8}T\d{6}Z)-[a-f0-9]+$') {
            [pscustomobject]@{ Stamp=$Matches.stamp; Path=$directory.FullName }
        }
    }
    $orderedXrea = @($xreaEntries | Sort-Object Stamp -Descending)
    foreach ($entry in ($orderedXrea | Select-Object -Skip $Keep)) {
        $resolved = [System.IO.Path]::GetFullPath($entry.Path)
        if (-not $resolved.StartsWith($xreaPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove a path outside xrea-source: $resolved"
        }
        if ($PSCmdlet.ShouldProcess($resolved, 'Remove old main-site backup generation')) {
            Remove-Item -LiteralPath $resolved -Recurse -Force
            $removed++
            Write-Host "Removed old main-site backup generation: $([System.IO.Path]::GetFileName($resolved))"
        }
    }
}
Write-Host "Backup retention complete; kept up to $Keep generations per series and removed $removed older generation(s)."
