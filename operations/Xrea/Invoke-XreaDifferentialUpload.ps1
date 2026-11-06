function Invoke-XreaDifferentialUpload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Session,
        [Parameter(Mandatory = $true)][string] $LocalRoot,
        [Parameter(Mandatory = $true)][string] $RemoteRoot,
        [Parameter(Mandatory = $true)][string] $StateKey,
        [Parameter(Mandatory = $true)] $TransferOptions,
        [string[]] $ExcludePatterns = @()
    )

    $root = [System.IO.Path]::GetFullPath($LocalRoot)
    $stateRoot = Join-Path $env:LOCALAPPDATA 'XreaDeploy\sync-state'
    if (-not (Test-Path -LiteralPath $stateRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
    }
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($StateKey)
    $stateName = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($keyBytes)).ToLowerInvariant() + '.json'
    $stateFile = Join-Path $stateRoot $stateName
    $state = @{}
    if (Test-Path -LiteralPath $stateFile -PathType Leaf) {
        try {
            $loaded = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json -AsHashtable
            if ($loaded -is [System.Collections.IDictionary]) { $state = $loaded }
        } catch {
            throw "Differential upload state is unreadable ($stateFile). Preserve it, then remove it to force a full upload. $($_.Exception.Message)"
        }
    }

    $files = @(Get-ChildItem -LiteralPath $root -File -Recurse -Force | Where-Object {
        $relative = [System.IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/')
        $skip = $false
        foreach ($pattern in $ExcludePatterns) {
            if ($relative -match $pattern) { $skip = $true; break }
        }
        -not $skip
    })
    $changed = @()
    foreach ($file in $files) {
        $relative = [System.IO.Path]::GetRelativePath($root, $file.FullName).Replace('\', '/')
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if (-not $state.Contains($relative) -or $state[$relative] -ne $hash) {
            $changed += [pscustomobject]@{ File = $file; Relative = $relative; Hash = $hash }
        }
    }

    $base = $RemoteRoot.TrimEnd('/')
    $checkedDirectories = @{}
    foreach ($item in $changed) {
        $segments = @($item.Relative.Split('/'))
        $directory = $base
        for ($i = 0; $i -lt ($segments.Count - 1); $i++) {
            $directory += '/' + $segments[$i]
            if (-not $checkedDirectories.ContainsKey($directory)) {
                if (-not $Session.DirectoryExists($directory)) { $Session.CreateDirectory($directory) }
                $checkedDirectories[$directory] = $true
            }
        }
        $remoteFile = $base + '/' + $item.Relative
        $transfer = $Session.PutFiles($item.File.FullName, $remoteFile, $false, $TransferOptions)
        $transfer.Check()
        $state[$item.Relative] = $item.Hash
        $tempFile = $stateFile + '.tmp'
        $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tempFile -Encoding utf8
        Move-Item -LiteralPath $tempFile -Destination $stateFile -Force
    }

    [pscustomobject]@{ Uploaded = $changed.Count; CheckedLocal = $files.Count; StateFile = $stateFile }
}

