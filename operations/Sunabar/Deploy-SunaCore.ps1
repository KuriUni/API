[CmdletBinding()]
param([switch] $ResetCredentials, [switch] $ConfigureDatabase)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$base = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$source = Join-Path $base 'suna-core-source'
$files = @('.htaccess', 'main.py', 'sunabar_sessions.py', 'api.cgi', 'index.html', 'sunabar.css', 'sunabar.js', 'pymysql_vendor.zip')
$remoteDirectory = '' # This FTP account is rooted at /public_html/suna/.
$hostName = 'v2006.coreserver.jp'
$userName = 'suna@suna.2415.jp'
$databaseName = 'qowcpjnw_suna'
$databaseUser = 'qowcpjnw_suna'
$fingerprint = '20:9c:38:e5:92:50:52:0f:d1:9b:6c:69:e3:2d:5f:cb:b6:14:28:ed:bf:5f:34:f3:74:93:69:8d:46:a1:b3:f4'

foreach ($name in $files) {
    $path = Join-Path $source $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Deployment source missing: $path" }
}
$deployFiles = @($files)

$dll = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\WinSCP\WinSCPnet.dll'),
    (Join-Path $env:ProgramFiles 'WinSCP\WinSCPnet.dll'),
    (Join-Path ${env:ProgramFiles(x86)} 'WinSCP\WinSCPnet.dll')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
if (-not $dll) { throw 'WinSCP .NET library was not found.' }
Add-Type -Path $dll

function Read-SunabarCredentials {
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Deploy Sunabar to Core Server'
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.TopMost = $true
$form.ClientSize = New-Object System.Drawing.Size(520, 265)
$label = New-Object System.Windows.Forms.Label
$label.Text = "Explicit FTPS  |  $hostName`r`nFTP account: $userName`r`nFTP root maps to: /public_html/suna/"
$label.Location = New-Object System.Drawing.Point(16, 14)
$label.Size = New-Object System.Drawing.Size(485, 54)
$form.Controls.Add($label)
$passwordLabel = New-Object System.Windows.Forms.Label
$passwordLabel.Text = 'FTP password (saved with Windows DPAPI after successful login):'
$passwordLabel.Location = New-Object System.Drawing.Point(16, 77)
$passwordLabel.Size = New-Object System.Drawing.Size(480, 20)
$form.Controls.Add($passwordLabel)
$box = New-Object System.Windows.Forms.TextBox
$box.Location = New-Object System.Drawing.Point(18, 101)
$box.Size = New-Object System.Drawing.Size(480, 25)
$box.UseSystemPasswordChar = $true
$form.Controls.Add($box)
$dbPasswordLabel = New-Object System.Windows.Forms.Label
$dbPasswordLabel.Text = "Optional: enter a new MySQL password for $databaseUser / $($databaseName):"
$dbPasswordLabel.Location = New-Object System.Drawing.Point(16, 137)
$dbPasswordLabel.Size = New-Object System.Drawing.Size(488, 20)
$form.Controls.Add($dbPasswordLabel)
$dbBox = New-Object System.Windows.Forms.TextBox
$dbBox.Location = New-Object System.Drawing.Point(18, 161)
$dbBox.Size = New-Object System.Drawing.Size(480, 25)
$dbBox.UseSystemPasswordChar = $true
$form.Controls.Add($dbBox)
$note = New-Object System.Windows.Forms.Label
$note.Text = 'Leave blank to keep the existing server-side DB password. FTP password is required.'
$note.Location = New-Object System.Drawing.Point(18, 194)
$note.Size = New-Object System.Drawing.Size(480, 18)
$form.Controls.Add($note)
$button = New-Object System.Windows.Forms.Button
$button.Text = 'Connect and deploy'
$button.Location = New-Object System.Drawing.Point(354, 220)
$button.Size = New-Object System.Drawing.Size(144, 30)
$button.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.Controls.Add($button)
$form.AcceptButton = $button
$form.add_Shown({ $box.Focus() })
try {
    if ($form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK -or [string]::IsNullOrWhiteSpace($box.Text)) { throw 'Credential entry cancelled or FTP password missing.' }
    $password = ConvertTo-SecureString -String $box.Text -AsPlainText -Force
    return [pscustomobject]@{ Credential = (New-Object System.Management.Automation.PSCredential($userName, $password)); DatabasePassword = $dbBox.Text }
} finally {
    $box.Clear()
    $dbBox.Clear()
    $form.Dispose()
}
}

$credentialDirectory = Join-Path $env:LOCALAPPDATA 'SunabarDeploy'
$credentialFile = Join-Path $credentialDirectory 'ftp-credential.xml'
$credential = $null
$databasePassword = ''
$usedSavedCredential = $false
if (-not $ResetCredentials -and -not $ConfigureDatabase -and (Test-Path -LiteralPath $credentialFile -PathType Leaf)) {
    try {
        $candidate = Import-Clixml -LiteralPath $credentialFile
        if (($candidate -is [System.Management.Automation.PSCredential]) -and $candidate.UserName -eq $userName) {
            $credential = $candidate
            $usedSavedCredential = $true
            Write-Host 'Using saved Windows DPAPI credential for Sunabar FTP.'
        }
    } catch { Write-Warning 'The saved credential could not be read; enter it again.' }
}
if (-not $credential) {
    $entered = Read-SunabarCredentials
    $credential = $entered.Credential
    $databasePassword = $entered.DatabasePassword
}
$configureDatabase = -not [string]::IsNullOrWhiteSpace($databasePassword)

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupDirectory = Join-Path $base "deploy-backups\sunacore-$stamp"
$verifyDirectory = Join-Path $env:TEMP "sunacore-verify-$stamp"
New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $verifyDirectory -Force | Out-Null
$session = New-Object WinSCP.Session
try {
    $options = New-Object WinSCP.SessionOptions -Property @{
        Protocol = [WinSCP.Protocol]::Ftp
        FtpSecure = [WinSCP.FtpSecure]::Explicit
        FtpMode = [WinSCP.FtpMode]::Passive
        HostName = $hostName
        PortNumber = 21
        UserName = $userName
        SecurePassword = $credential.Password
        TlsHostCertificateFingerprint = $fingerprint
    }
    try { $session.Open($options) }
    catch {
        if (-not $usedSavedCredential -or $_.Exception.Message -notmatch '(?i)auth|530|\u8a8d\u8a3c') { throw }
        [void][System.Windows.Forms.MessageBox]::Show('Saved FTP credentials were rejected. Enter the updated password.', 'Sunabar deployment', 'OK', 'Warning')
        $entered = Read-SunabarCredentials
        $credential = $entered.Credential
        $databasePassword = $entered.DatabasePassword
        $configureDatabase = -not [string]::IsNullOrWhiteSpace($databasePassword)
        $options.SecurePassword = $credential.Password
        $session.Dispose()
        $session = New-Object WinSCP.Session
        $session.Open($options)
    }
    if (-not (Test-Path -LiteralPath $credentialDirectory -PathType Container)) { New-Item -ItemType Directory -Path $credentialDirectory -Force | Out-Null }
    $credential | Export-Clixml -LiteralPath $credentialFile -Force
    Write-Host 'Sunabar FTP credential saved with Windows DPAPI for this Windows account.'
    foreach ($name in $deployFiles) {
        $remoteFile = "/$name"
        if ($session.FileExists($remoteFile)) {
            $backupTarget = Join-Path $backupDirectory ($name.Replace('/', '\'))
            $backupParent = Split-Path -Path $backupTarget -Parent
            if (-not (Test-Path -LiteralPath $backupParent)) { New-Item -ItemType Directory -Path $backupParent -Force | Out-Null }
            $backup = $session.GetFiles($remoteFile, $backupTarget, $false)
            $backup.Check()
        }
    }

    $transferOptions = New-Object WinSCP.TransferOptions
    $transferOptions.TransferMode = [WinSCP.TransferMode]::Binary
    $transferOptions.ResumeSupport.State = [WinSCP.TransferResumeSupportState]::On
    foreach ($name in $deployFiles) {
        $localFile = Join-Path $source ($name.Replace('/', '\'))
        $upload = $session.PutFiles($localFile, '/', $false, $transferOptions)
        $upload.Check()
    }

    # FTP does not apply TransferOptions.FilePermissions; set the CGI mode explicitly.
    $chmod = $session.ExecuteCommand('SITE CHMOD 755 /api.cgi')
    if ($chmod.ExitCode -ne 0) { throw "Could not set api.cgi to mode 0755: $($chmod.ErrorOutput)" }
    if (-not $session.FileExists('/.sunabar')) { $session.CreateDirectory('/.sunabar') }
    $dirMode = $session.ExecuteCommand('SITE CHMOD 700 /.sunabar')
    if ($dirMode.ExitCode -ne 0) { throw "Could not protect .sunabar directory: $($dirMode.ErrorOutput)" }
    if ($configureDatabase) {
        $dbConfig = @{
            host = 'localhost'
            port = 3306
            database = $databaseName
            user = $databaseUser
            password = $databasePassword
        } | ConvertTo-Json -Compress
        $dbBytes = [System.Text.Encoding]::UTF8.GetBytes($dbConfig)
        $dbStream = New-Object System.IO.MemoryStream
        $dbStream.Write($dbBytes, 0, $dbBytes.Length)
        $dbStream.Position = 0
        $session.PutFile($dbStream, '/.sunabar/database.json', $transferOptions)
        $dbStream.Dispose()
        $dbMode = $session.ExecuteCommand('SITE CHMOD 600 /.sunabar/database.json')
        if ($dbMode.ExitCode -ne 0) { throw "Could not protect database credentials: $($dbMode.ErrorOutput)" }
        $databasePassword = $null
        $dbConfig = $null
        $dbBytes = $null
    } elseif (-not $session.FileExists('/.sunabar/database.json')) {
        throw 'No existing private database configuration was found. Enter the DB password to initialize it.'
    }
    foreach ($name in $deployFiles) {
        $remoteFile = "/$name"
        $target = Join-Path $verifyDirectory ($name.Replace('/', '\'))
        $download = $session.GetFiles($remoteFile, $target, $false)
        $download.Check()
        $localHash = (Get-FileHash -LiteralPath (Join-Path $source ($name.Replace('/', '\'))) -Algorithm SHA256).Hash
        $remoteHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
        if ($localHash -ne $remoteHash) { throw "Remote content verification failed: $name" }
        Write-Host "Verified $name (SHA-256 matched)"
    }

    # Remove only the accidental nested copy created by an earlier path assumption.
    # Each file is downloaded and compared first; unrelated files and state are untouched.
    $nestedDirectory = '/suna'
    foreach ($name in $files) {
        $nestedFile = "$nestedDirectory/$name"
        if ($session.FileExists($nestedFile)) {
            $nestedTarget = Join-Path $verifyDirectory ("nested-" + $name)
            $nestedDownload = $session.GetFiles($nestedFile, $nestedTarget, $false)
            $nestedDownload.Check()
            $nestedHash = (Get-FileHash -LiteralPath $nestedTarget -Algorithm SHA256).Hash
            $sourceHash = (Get-FileHash -LiteralPath (Join-Path $source $name) -Algorithm SHA256).Hash
            if ($nestedHash -eq $sourceHash) {
                $session.RemoveFiles($nestedFile).Check()
                Write-Host "Removed duplicate deployment file $nestedFile (matched local SHA-256)"
            } else {
                Write-Warning "Kept $nestedFile because its contents differ from this deployment."
            }
        }
    }

    Write-Host 'Deployment and file verification completed.'
    Write-Host 'URL: https://suna.2415.jp/suna/'
    Write-Host "Previous deployed files, if any, backed up under: $backupDirectory"
    Write-Host 'Runtime state in the FTP root .sunabar was not downloaded, replaced, or deleted.'
    if ($configureDatabase) {
        Write-Host 'Database credentials were uploaded directly from memory and protected as mode 0600.'
    } else {
        Write-Host 'The existing server-side database credentials were preserved.'
    }
}
finally {
    $session.Dispose()
    if ($null -ne $dbStream) { $dbStream.Dispose() }
    $databasePassword = $null
}

try {
    $response = Invoke-WebRequest -Uri 'https://suna.2415.jp/suna/api/v1/healthz' -Method Get -UseBasicParsing -TimeoutSec 20
    $health = $response.Content | ConvertFrom-Json
    if (-not $health.ok -or $health.dependencies.database -ne 'ok') { throw 'The API health check did not report database readiness.' }
    Write-Host 'HTTP health check: API and database are ready.'
}
catch {
    $status = $null
    if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
    if ($status -eq 503) {
        Write-Warning 'Files are deployed, but the database is not ready. Check the database password, account grants, and MySQL host.'
    } else {
        Write-Warning "FTP upload was verified, but the public health check needs attention: $($_.Exception.Message)"
    }
}
