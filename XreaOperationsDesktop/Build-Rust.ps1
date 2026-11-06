$ErrorActionPreference = 'Stop'
$rustDir = Join-Path $PSScriptRoot 'rust'
$cargoExe = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
if (-not (Test-Path -LiteralPath $cargoExe)) {
    $command = Get-Command cargo -ErrorAction SilentlyContinue
    if ($null -eq $command) { throw 'Rust/Cargo が見つかりません。rustup をインストールしてから再実行してください。' }
    $cargoExe = $command.Source
}
Push-Location $rustDir
try {
    & $cargoExe build --release --locked --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    Write-Host "Build complete: $(Join-Path $rustDir 'target\x86_64-pc-windows-msvc\release\TutiOperations.exe')"
} finally {
    Pop-Location
}\n