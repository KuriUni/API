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

function Save-XreaDifferentialState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable] $State,
        [Parameter(Mandatory = $true)][string] $StateFile
    )

    $tempFile = $StateFile + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $json = $State | ConvertTo-Json -Depth 5
        $encoding = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($tempFile, $json, $encoding)
        if (Test-Path -LiteralPath $StateFile -PathType Leaf) {
            [System.IO.File]::Replace($tempFile, $StateFile, $null)
        } else {
            [System.IO.File]::Move($tempFile, $StateFile)
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempFile -PathType Leaf) {
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
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
        [switch] $PreserveUnselectedState,
        [ValidateRange(0, 300)][int] $LockTimeoutSeconds = 0
    )

    $stateRoot = Join-Path $env:LOCALAPPDATA 'XreaDeploy\sync-state'
    if (-not (Test-Path -LiteralPath $stateRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
    }

    # The OS releases this exclusive handle even if PowerShell is terminated.
    # This prevents concurrent runs from overwriting each other's state or
    # interleaving uploads to the same destination/state key.
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($StateKey)
    $keyHasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $keyHash = $keyHasher.ComputeHash($keyBytes)
        $stateName = (($keyHash | ForEach-Object { $_.ToString('x2') }) -join '') + '.json'
    } finally { $keyHasher.Dispose() }
    $lockFile = Join-Path $stateRoot ($stateName + '.lock')
    $lockStream = $null
    $deadline = [DateTime]::UtcNow.AddSeconds($LockTimeoutSeconds)
    do {
        try {
            $lockStream = [System.IO.File]::Open(
                $lockFile,
                [System.IO.FileMode]::OpenOrCreate,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None
            )
        } catch [System.IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) {
                throw "Another deployment is using this destination/state key. Lock: $lockFile. Wait for it to finish, then retry."
            }
            Start-Sleep -Milliseconds 250
        }
    } while ($null -eq $lockStream)

    try {
        $plan = Get-XreaDifferentialPlan -LocalRoot $LocalRoot -StateKey $StateKey -ExcludePatterns $ExcludePatterns
        $stateFile = $plan.StateFile
        $state = $plan.State
        $files = $plan.Files
        $changed = $plan.Changed
        $root = $plan.Root

        $base = $RemoteRoot.TrimEnd('/')
        if ([string]::IsNullOrWhiteSpace($base)) { throw 'RemoteRoot must not be empty or root-only.' }
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

            # Do not mark a transfer as synchronized until the source is proven
            # unchanged across the upload. If it changed mid-transfer, the next
            # run must retry it rather than trusting a stale hash.
            $currentHash = Get-XreaSha256 -Path $item.File.FullName
            if ($currentHash -ne $item.Hash) {
                throw "Local source changed after planning; rerun deployment: $($item.Relative)"
            }
            $transfer = $Session.PutFiles($item.File.FullName, $remoteFile, $false, $TransferOptions)
            $transfer.Check()
            $postUploadHash = Get-XreaSha256 -Path $item.File.FullName
            if ($postUploadHash -ne $item.Hash) {
                throw "Local source changed during upload; state was not advanced. Rerun deployment: $($item.Relative)"
            }
            $state[$item.Relative] = $item.Hash
            Save-XreaDifferentialState -State $state -StateFile $stateFile
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
                Save-XreaDifferentialState -State $state -StateFile $stateFile
            }
        }

        [pscustomobject]@{ Uploaded = $changed.Count; CheckedLocal = $files.Count; PrunedStateEntries = $removedStateEntries; StateFile = $stateFile }
    }
    finally {
        if ($null -ne $lockStream) { $lockStream.Dispose() }
    }
}
