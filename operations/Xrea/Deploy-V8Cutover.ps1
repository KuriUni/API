#requires -Version 7.0
[CmdletBinding()]
param([ValidateSet('Both','Primary','Backup')][string] $Target = 'Both',
      [ValidateSet('V8','License','LicenseV4')][string] $Profile = 'V8')
$ErrorActionPreference = 'Stop'
$base = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$source = Join-Path $base 'xrea-source'
. (Join-Path $PSScriptRoot 'Xrea-DeployTargets.ps1')
$install = Join-Path $env:LOCALAPPDATA 'Programs\WinSCP'
Add-Type -Path (Join-Path $install 'netstandard2.0\WinSCPnet.dll')
Add-Type -AssemblyName System.Security.Cryptography.ProtectedData
$credentials = Import-Clixml -LiteralPath (Join-Path $env:LOCALAPPDATA 'XreaDeploy\credentials.xml')
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$series = if ($Profile -eq 'LicenseV4') { 'license-v4-auth' } elseif ($Profile -eq 'License') { 'license-auth' } else { 'v8-cutover' }
$backupRoot = Join-Path $base "deploy-backups\$series-$stamp"
$privateRoot = Join-Path $env:LOCALAPPDATA "XreaDeploy\private-backups\$series-$stamp"
# Dependencies precede dispatchers and browser assets. Only these known paths are queried.
$files = @('retired_auth.py','product_key_v8_storage.py','ha_migrate.py','ha_export.py',
    'ha_snapshot.py','ha_handlers.py','baas_handlers.py','baas_v8_handlers.py',
    'ha_product_key_v8_worker.py','service_handlers.py','app.py','native_routes.py','openapi-catalog.json',
    'api-catalog/openapi.json','tenant-portal/bulk-jobs.js','tenant-portal/app.js','tenant-portal/index.html')
if ($Profile -eq 'License') {
    $files = @('http_utils.py','v3_handlers.py','native_v3.py','v2_handlers.py','openapi-catalog.json','api-catalog/openapi.json')
}
if ($Profile -eq 'LicenseV4') {
    $files = @('v4_crypto.py','license_v4_storage.py','v3_handlers.py','native_v4.py','asgi.py',
        'native_routes.py','routes.json','ha_migrate.py','ha_export.py','ha_snapshot.py',
        'openapi-catalog.json','api-catalog/openapi.json','api/v4/activate.html')
}
foreach ($file in $files) {
    if (-not (Test-Path -LiteralPath (Join-Path $source $file))) { throw "Missing source: $file" }
}
function Save-PrivateSnapshot($Url, $Headers, $Path) {
    $response = $null
    for ($attempt=1; $attempt -le 3; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri $Url -Headers $Headers -TimeoutSec 180 -SkipHttpErrorCheck
            break
        } catch {
            if ($attempt -eq 3) { throw }
            Start-Sleep -Seconds 2
        }
    }
    if ([int]$response.StatusCode -ne 200) { throw "Snapshot export failed: HTTP $($response.StatusCode)" }
    $snapshot = $response.Content | ConvertFrom-Json
    if (-not $snapshot.ok -or $snapshot.schema -ne 2 -or -not $snapshot.tables) { throw 'Invalid snapshot response.' }
    $plain = [Text.Encoding]::UTF8.GetBytes([string]$response.Content)
    try {
        $encrypted = [Security.Cryptography.ProtectedData]::Protect($plain, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes($Path, $encrypted)
    } finally { [Array]::Clear($plain,0,$plain.Length) }
    return [pscustomobject]@{ Tables=@($snapshot.tables.PSObject.Properties.Name); JobColumns=@($snapshot.schemas.product_key_v8_jobs.Field) }
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
    $session.SessionLogPath = Join-Path $backup 'winscp.log'
    $uploaded = [Collections.Generic.List[string]]::new()
    $hashes = @{}
    $missing = @{}
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
            if ($session.FileExists($remote)) { $session.GetFiles($remote,$saved,$false).Check() }
            else { $missing[$file]=$true }
            $hashes[$file] = (Get-FileHash -LiteralPath (Join-Path $source $file) -Algorithm SHA256).Hash
        }
        $manifest = foreach ($file in $files) {
            [pscustomobject]@{ path=$file; existed=(-not $missing.ContainsKey($file)); deployed_sha256=$hashes[$file];
                previous_sha256=$(if (-not $missing.ContainsKey($file)) { (Get-FileHash -LiteralPath (Join-Path $backup $file)).Hash } else { $null }) }
        }
        $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $backup 'deployment.json') -Encoding utf8
        $exportUrl = "https://$domain/license/ha/export.php"
        if ($destination.Name -eq 'Backup') { $exportUrl += '?standby_backup=1' }
        Write-Host "$($destination.Name): captured pre-deployment database snapshot."
        $before = Save-PrivateSnapshot $exportUrl $headers (Join-Path $privateRoot ($destination.Name + '-before.dpapi'))
        foreach ($file in $files) {
            $saved = Join-Path $backup $file
            if ($missing.ContainsKey($file) -or (Get-FileHash -LiteralPath $saved -Algorithm SHA256).Hash -ne $hashes[$file]) {
                $remote = $destination.Remote + '/' + $file
                $uploaded.Add($file)
                $session.PutFiles((Join-Path $source $file),$remote,$false).Check()
                $verify = $saved + '.verify'
                $session.GetFiles($remote,$verify,$false).Check()
                if ((Get-FileHash -LiteralPath $verify -Algorithm SHA256).Hash -ne $hashes[$file]) { throw "SHA-256 mismatch: $file" }
            }
            # Expand schema before activating handlers that require the new columns.
            if ($Profile -eq 'V8' -and $file -eq 'ha_migrate.py') {
                $migration = Invoke-WebRequest -Uri "https://$domain/license/ha/migrate.php" -Method Post -Headers $headers -ContentType 'application/json' -Body '{"scope":"v8"}' -TimeoutSec 90 -SkipHttpErrorCheck
                $result = $migration.Content | ConvertFrom-Json
                if ([int]$migration.StatusCode -ne 200 -or -not $result.ok -or -not $result.product_key_issuance_v8.ok) { throw 'V8-only schema installation failed.' }
                Write-Host "$($destination.Name): additive schema installation completed before handler activation."
            }
            if ($Profile -eq 'LicenseV4' -and $file -eq 'ha_migrate.py') {
                $migration = Invoke-WebRequest -Uri "https://$domain/license/ha/migrate.php" -Method Post -Headers $headers -ContentType 'application/json' -Body '{"scope":"license_v4"}' -TimeoutSec 90 -SkipHttpErrorCheck
                $result = $migration.Content | ConvertFrom-Json
                if ([int]$migration.StatusCode -ne 200 -or -not $result.ok -or -not $result.license_v4.ok) { throw 'V4 additive schema installation failed.' }
                foreach ($table in @('license_v4_challenges','license_v4_devices','license_v4_sessions','license_v4_proofs','license_v4_refresh_history')) {
                    if ($table -notin $result.license_v4.tables) { throw "V4 migration omitted table: $table" }
                }
                Write-Host "$($destination.Name): additive V4 schema installation completed."
            }
        }
        Write-Host "$($destination.Name): capturing post-migration database snapshot."
        $after = Save-PrivateSnapshot $exportUrl $headers (Join-Path $privateRoot ($destination.Name + '-after.dpapi'))
        if ($Profile -eq 'License' -or $Profile -eq 'LicenseV4') {
            $v3 = Invoke-WebRequest -Uri "https://$domain/license/api/v3/refresh.php" -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 30 -SkipHttpErrorCheck
            if ([int]$v3.StatusCode -ne 401 -or ($v3.Content|ConvertFrom-Json).error_code -ne 'REFRESH_TOKEN_REQUIRED' -or -not $v3.Headers['X-Request-ID']) { throw 'V3 authentication error contract failed.' }
            $method = Invoke-WebRequest -Uri "https://$domain/license/api/v3/refresh.php" -TimeoutSec 30 -SkipHttpErrorCheck
            if ([int]$method.StatusCode -ne 405 -or -not $method.Headers['X-Request-ID']) { throw 'V3 method protection failed.' }
            $v2 = Invoke-WebRequest -Uri "https://$domain/license/api/v2/activate.php" -Method Post -ContentType 'application/json' -Body '{"api_action":"refresh"}' -TimeoutSec 30 -SkipHttpErrorCheck
            $v2Body = $v2.Content|ConvertFrom-Json
            if (-not $v2.Headers['X-Request-ID'] -or ([int]$v2.StatusCode -ne 400 -and -not ([int]$v2.StatusCode -eq 503 -and $v2Body.error -eq 'server_not_writable'))) { throw 'V2 authentication protection failed.' }
            $catalog = Invoke-RestMethod -Uri "https://$domain/license/api-catalog/index.php?document=openapi.json" -TimeoutSec 30
            $expectedCatalogVersion = if ($Profile -eq 'LicenseV4') { '1.17.0' } else { '1.16.0' }
            if ($catalog.info.version -ne $expectedCatalogVersion) { throw 'License API specification not updated.' }
            if ($Profile -eq 'LicenseV4') {
                $guide = Invoke-WebRequest -Uri "https://$domain/license/api/v4/activate.php" -TimeoutSec 30 -SkipHttpErrorCheck
                if ([int]$guide.StatusCode -ne 200 -or -not ([string]$guide.Content).Contains('License API v4')) { throw 'V4 developer guide is unavailable.' }
                $challenge = Invoke-WebRequest -Uri "https://$domain/license/api/v4/challenge.php" -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 30 -SkipHttpErrorCheck
                $challengeBody = $challenge.Content | ConvertFrom-Json
                if ([int]$challenge.StatusCode -ne 400 -or $challengeBody.error_code -ne 'DEVICE_PUBLIC_KEY_INVALID' -or -not $challenge.Headers['X-Request-ID']) { throw 'V4 safe challenge validation failed.' }
            }
            Write-Host "$($destination.Name): $($uploaded.Count) changed files hash-verified; license API contracts verified."
        } else {
        foreach ($table in @('product_key_v8_jobs','product_key_v8_items')) {
            if ($table -notin $after.Tables) { throw "V8 table missing from HA snapshot: $table" }
        }
        foreach ($column in @('retry_count','next_attempt_at','last_error_at')) {
            if ($column -notin $after.JobColumns) { throw "Required reliability column missing: $column" }
        }
        $queue = Invoke-WebRequest -Uri "https://$domain/license/ha/product-key-v8-worker.php" -Headers $headers -TimeoutSec 30 -SkipHttpErrorCheck
        $queueState = $queue.Content | ConvertFrom-Json
        if ([int]$queue.StatusCode -ne 200 -or $queueState.mode -ne 'status') { throw 'Read-only queue diagnostics failed.' }
        Write-Host "$($destination.Name): queue diagnostics ready; active jobs=$($queueState.queue.active_jobs)."
        foreach ($path in @('v8/issuance.php','v6/issuance.php')) {
            $response = Invoke-WebRequest -Uri "https://$domain/license/api/baas/$path" -TimeoutSec 30 -SkipHttpErrorCheck
            if ([int]$response.StatusCode -ne 401) { throw "Expected protected/readable endpoint: $path HTTP $($response.StatusCode)" }
        }
        foreach ($path in @('v7/issuance.php','v6/issuance.php')) {
            $response = Invoke-WebRequest -Uri "https://$domain/license/api/baas/$path" -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 30 -SkipHttpErrorCheck
            if ([int]$response.StatusCode -ne 410) { throw "Retired submission not closed: $path" }
        }
        $page = Invoke-WebRequest -Uri "https://$domain/license/tenant-portal/" -TimeoutSec 30
        if (-not ([string]$page.Content).Contains('20261108-reliability-1')) { throw 'Portal script version not updated.' }
        $asset = Invoke-WebRequest -Uri "https://$domain/license/tenant-portal/bulk-jobs.js?v=20261108-reliability-1" -TimeoutSec 30
        if (-not ([string]$asset.Content).Contains('collectCsvPages')) { throw 'Bulk download helper not publicly available.' }
        Write-Host "$($destination.Name): $($uploaded.Count) changed files hash-verified; V8 ready, legacy submissions closed, HA snapshot includes both V8 tables."
        }
    } catch {
        $reason = $_.Exception.Message
        $rollbackErrors = @()
        for ($index=$uploaded.Count-1; $index -ge 0; $index--) {
            $file=$uploaded[$index]
            try {
                if ($missing.ContainsKey($file)) {
                    $session.RemoveFiles(($destination.Remote+'/'+$file)).Check()
                    continue
                }
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
