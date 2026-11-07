#requires -Version 7.0
[CmdletBinding()]
param([ValidateSet('Both','Primary','Backup')][string] $Target = 'Both')
$ErrorActionPreference = 'Stop'
$base = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$source = Join-Path $base 'xrea-source'
. (Join-Path $PSScriptRoot 'Xrea-DeployTargets.ps1')
$install = Join-Path $env:LOCALAPPDATA 'Programs\WinSCP'
Add-Type -Path (Join-Path $install 'netstandard2.0\WinSCPnet.dll')
Add-Type -AssemblyName System.Security.Cryptography.ProtectedData
$credentials = Import-Clixml -LiteralPath (Join-Path $env:LOCALAPPDATA 'XreaDeploy\credentials.xml')
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupRoot = Join-Path $base "deploy-backups\v8-cutover-$stamp"
$privateRoot = Join-Path $env:LOCALAPPDATA "XreaDeploy\private-backups\v8-cutover-$stamp"
# Dependencies precede dispatchers and browser assets. Only these known paths are queried.
$files = @('retired_auth.py','product_key_v8_storage.py','ha_migrate.py','ha_export.py',
    'ha_snapshot.py','ha_handlers.py','baas_handlers.py','baas_v8_handlers.py',
    'service_handlers.py','app.py','native_routes.py','openapi-catalog.json',
    'api-catalog/openapi.json','tenant-portal/app.js','tenant-portal/index.html')
foreach ($file in $files) {
    if (-not (Test-Path -LiteralPath (Join-Path $source $file))) { throw "Missing source: $file" }
}
function Save-PrivateSnapshot($Url, $Headers, $Path) {
    $response = Invoke-WebRequest -Uri $Url -Headers $Headers -TimeoutSec 120 -SkipHttpErrorCheck
    if ([int]$response.StatusCode -ne 200) { throw "Snapshot export failed: HTTP $($response.StatusCode)" }
    $snapshot = $response.Content | ConvertFrom-Json
    if (-not $snapshot.ok -or $snapshot.schema -ne 2 -or -not $snapshot.tables) { throw 'Invalid snapshot response.' }
    $plain = [Text.Encoding]::UTF8.GetBytes([string]$response.Content)
    try {
        $encrypted = [Security.Cryptography.ProtectedData]::Protect($plain, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes($Path, $encrypted)
    } finally { [Array]::Clear($plain,0,$plain.Length) }
    return @($snapshot.tables.PSObject.Properties.Name)
}
$targets = @(Get-XreaDeployTargets | Where-Object { $Target -eq 'Both' -or $_.Name -eq $Target } | Sort-Object Name)
foreach ($destination in $targets) {
    $credential = if ($credentials -is [Collections.IDictionary]) { $credentials[$destination.Name] } else { $credentials.($destination.Name) }
    if ($credential -isnot [pscredential] -or $credential.UserName -ne $destination.User) { throw "Saved DPAPI credential missing for $($destination.Name)." }
    $domain = if ($destination.Name -eq 'Primary') { '2415.jp' } else { 'backup.2415.jp' }
    $backup = Join-Path $backupRoot $destination.Name
    New-Item -ItemType Directory -Path $backup,$privateRoot -Force | Out-Null
    $session = [WinSCP.Session]::new()
    $session.ExecutablePath = Join-Path $install 'WinSCP.exe'
    $uploaded = [Collections.Generic.List[string]]::new()
    $hashes = @{}
    try {
        $session.Open([WinSCP.SessionOptions]@{
            Protocol=[WinSCP.Protocol]::Ftp; FtpSecure=[WinSCP.FtpSecure]::Explicit
            FtpMode=[WinSCP.FtpMode]::Passive; HostName=$destination.Host; PortNumber=21
            UserName=$destination.User; SecurePassword=$credential.Password
            TlsHostCertificateFingerprint='9c:fb:c9:21:d2:6f:de:43:43:bc:cb:e2:65:b0:99:e4:20:11:e1:72:bb:26:16:48:d1:3e:30:89:68:6d:d4:c7'
        })
        $reader = [IO.StreamReader]::new($session.GetFile("/.tuti-license-ha-$domain/runtime/runtime-secrets.json"))
        try { $secrets = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
        $token = [string]$secrets.ha_sync_token
        if ($token.Length -lt 32) { throw "HA credential unavailable for $domain." }
        $headers = @{ 'X-HA-Token'=$token; Accept='application/json' }
        foreach ($file in $files) {
            $remote = $destination.Remote + '/' + $file
            $saved = Join-Path $backup $file
            New-Item -ItemType Directory -Path (Split-Path $saved -Parent) -Force | Out-Null
            $session.GetFiles($remote,$saved,$false).Check()
            $hashes[$file] = (Get-FileHash -LiteralPath (Join-Path $source $file) -Algorithm SHA256).Hash
        }
        foreach ($file in $files) {
            $saved = Join-Path $backup $file
            if ((Get-FileHash -LiteralPath $saved -Algorithm SHA256).Hash -eq $hashes[$file]) { continue }
            $remote = $destination.Remote + '/' + $file
            $uploaded.Add($file)
            $session.PutFiles((Join-Path $source $file),$remote,$false).Check()
            $verify = $saved + '.verify'
            $session.GetFiles($remote,$verify,$false).Check()
            if ((Get-FileHash -LiteralPath $verify -Algorithm SHA256).Hash -ne $hashes[$file]) { throw "SHA-256 mismatch: $file" }
        }
        $exportUrl = "https://$domain/license/ha/export.php"
        if ($destination.Name -eq 'Backup') { $exportUrl += '?standby_backup=1' }
        $tables = Save-PrivateSnapshot $exportUrl $headers (Join-Path $privateRoot ($destination.Name + '-before.dpapi'))
        $health = Invoke-WebRequest -Uri "https://$domain/license/api/baas/v8/issuance.php" -TimeoutSec 30 -SkipHttpErrorCheck
        if ([int]$health.StatusCode -eq 503 -and ($health.Content | ConvertFrom-Json).error -eq 'v8_migration_required') {
            $migration = Invoke-WebRequest -Uri "https://$domain/license/ha/migrate.php" -Method Post -Headers $headers -ContentType 'application/json' -Body '{"scope":"v8"}' -TimeoutSec 60 -SkipHttpErrorCheck
            $result = $migration.Content | ConvertFrom-Json
            if ([int]$migration.StatusCode -ne 200 -or -not $result.ok -or -not $result.product_key_issuance_v8.ok) { throw 'V8-only schema installation failed.' }
            $tables = Save-PrivateSnapshot $exportUrl $headers (Join-Path $privateRoot ($destination.Name + '-after.dpapi'))
            Write-Host "$($destination.Name): V8-only additive schema installation completed."
        }
        foreach ($table in @('product_key_v8_jobs','product_key_v8_items')) {
            if ($table -notin $tables) { throw "V8 table missing from HA snapshot: $table" }
        }
        foreach ($path in @('v8/issuance.php','v6/issuance.php')) {
            $response = Invoke-WebRequest -Uri "https://$domain/license/api/baas/$path" -TimeoutSec 30 -SkipHttpErrorCheck
            if ([int]$response.StatusCode -ne 401) { throw "Expected protected/readable endpoint: $path HTTP $($response.StatusCode)" }
        }
        foreach ($path in @('v7/issuance.php','v6/issuance.php')) {
            $response = Invoke-WebRequest -Uri "https://$domain/license/api/baas/$path" -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 30 -SkipHttpErrorCheck
            if ([int]$response.StatusCode -ne 410) { throw "Retired submission not closed: $path" }
        }
        $page = Invoke-WebRequest -Uri "https://$domain/license/tenant-portal/" -TimeoutSec 30
        if (-not ([string]$page.Content).Contains('20261107-v8-cutover-1')) { throw 'Portal script version not updated.' }
        Write-Host "$($destination.Name): $($uploaded.Count) changed files hash-verified; V8 ready, legacy submissions closed, HA snapshot includes both V8 tables."
    } catch {
        $reason = $_.Exception.Message
        $rollbackErrors = @()
        for ($index=$uploaded.Count-1; $index -ge 0; $index--) {
            $file=$uploaded[$index]
            try {
                $session.PutFiles((Join-Path $backup $file),($destination.Remote+'/'+$file),$false).Check()
                $check=(Join-Path $backup $file)+'.rollback'
                $session.GetFiles(($destination.Remote+'/'+$file),$check,$false).Check()
                if ((Get-FileHash $check).Hash -ne (Get-FileHash (Join-Path $backup $file)).Hash) { throw 'Rollback mismatch.' }
            } catch { $rollbackErrors += $file }
        }
        if ($rollbackErrors.Count) { throw "Deployment failed ($reason); rollback needs attention: $($rollbackErrors -join ', '). Backup: $backup" }
        throw "Deployment failed ($reason); uploaded files restored. Backup: $backup"
    } finally {
        $session.Dispose()
        $token=$null; $headers=$null; $secrets=$null
    }
}
Write-Host "Code backups: $backupRoot"
Write-Host "Database snapshots (Windows current-user DPAPI): $privateRoot"
& (Join-Path $PSScriptRoot '..\Prune-DeployBackups.ps1')
