function Get-XreaSha256([string] $Path) {
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            return [System.BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
        }
        finally { $stream.Dispose() }
    }
    finally { $hasher.Dispose() }
}

function Get-XreaDifferentialPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $LocalRoot,
        [Parameter(Mandatory = $true)][string] $StateKey,
        [string[]] $ExcludePatterns = @()
    )

    $root = [System.IO.Path]::GetFullPath($LocalRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "Source folder not found: $root" }
    $rootPrefix = $root + [System.IO.Path]::DirectorySeparatorChar
    $stateRoot = Join-Path $env:LOCALAPPDATA 'XreaDeploy\sync-state'
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($StateKey)
    $keyHasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $keyHash = $keyHasher.ComputeHash($keyBytes)
        $stateName = (($keyHash | ForEach-Object { $_.ToString('x2') }) -join '') + '.json'
    } finally { $keyHasher.Dispose() }
    $stateFile = Join-Path $stateRoot $stateName
    $state = @{}
    if (Test-Path -LiteralPath $stateFile -PathType Leaf) {
        try {
            $loaded = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
            if ($loaded -is [System.Collections.IDictionary]) {
                foreach ($key in $loaded.Keys) { $state[[string]$key] = [string]$loaded[$key] }
            } elseif ($null -ne $loaded) {
                foreach ($property in $loaded.PSObject.Properties) { $state[$property.Name] = [string]$property.Value }
            }
        } catch {
            throw "Differential upload state is unreadable ($stateFile). Preserve it, then remove it to force a full upload. $($_.Exception.Message)"
        }
    }

    $files = @(Get-ChildItem -LiteralPath $root -File -Recurse -Force | Where-Object {
        $relative = $_.FullName.Substring($rootPrefix.Length).Replace('\', '/')
        $skip = $false
        foreach ($pattern in $ExcludePatterns) {
            if ($relative -match $pattern) { $skip = $true; break }
        }
        -not $skip
    })
    $changed = @()
    foreach ($file in $files) {
        $relative = $file.FullName.Substring($rootPrefix.Length).Replace('\', '/')
        $hash = Get-XreaSha256 -Path $file.FullName
        if (-not $state.Contains($relative) -or $state[$relative] -ne $hash) {
            $changed += [pscustomobject]@{ File = $file; Relative = $relative; Hash = $hash; Length = $file.Length }
        }
    }
    [pscustomobject]@{ Root = $root; Files = $files; Changed = $changed; State = $state; StateFile = $stateFile }
}

function Invoke-XreaDifferentialUpload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Session,
        [Parameter(Mandatory = $true)][string] $LocalRoot,
        [Parameter(Mandatory = $true)][string] $RemoteRoot,
        [Parameter(Mandatory = $true)][string] $StateKey,
        [Parameter(Mandatory = $true)] $TransferOptions,
        [string[]] $ExcludePatterns = @(),
        [switch] $PreserveUnselectedState
    )

    $stateRoot = Join-Path $env:LOCALAPPDATA 'XreaDeploy\sync-state'
    if (-not (Test-Path -LiteralPath $stateRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
    }
    $plan = Get-XreaDifferentialPlan -LocalRoot $LocalRoot -StateKey $StateKey -ExcludePatterns $ExcludePatterns
    $stateFile = $plan.StateFile
    $state = $plan.State
    $files = $plan.Files
    $changed = $plan.Changed
    $root = $plan.Root

    $base = $RemoteRoot.TrimEnd('/')
    $checkedDirectories = @{}
    foreach ($item in $changed) {
        $segments = @($item.Relative.Split('/'))
        $directory = $base
        for ($i = 0; $i -lt ($segments.Count - 1); $i++) {
            $directory += '/' + $segments[$i]
            if (-not $checkedDirectories.ContainsKey($directory)) {
                try { [void]$Session.ListDirectory($directory) }
                catch { $Session.CreateDirectory($directory) }
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

    $removedStateEntries = 0
    if (-not $PreserveUnselectedState) {
        # Prune only after all uploads succeeded. This cleans local bookkeeping
        # for deleted/excluded files without deleting anything from the server.
        $activeFiles = @{}
        foreach ($file in $files) {
            $relative = $file.FullName.Substring(($root + [System.IO.Path]::DirectorySeparatorChar).Length).Replace('\', '/')
            $activeFiles[$relative] = $true
        }
        foreach ($key in @($state.Keys)) {
            if (-not $activeFiles.ContainsKey([string]$key)) {
                [void]$state.Remove([string]$key)
                $removedStateEntries++
            }
        }
        if ($removedStateEntries -gt 0) {
            $tempFile = $stateFile + '.tmp'
            $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tempFile -Encoding utf8
            Move-Item -LiteralPath $tempFile -Destination $stateFile -Force
        }
    }

    [pscustomobject]@{ Uploaded = $changed.Count; CheckedLocal = $files.Count; PrunedStateEntries = $removedStateEntries; StateFile = $stateFile }
}

