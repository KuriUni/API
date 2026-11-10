$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$sourceRoot = Join-Path $repoRoot 'xrea-source\sunabar'
$templatePath = Join-Path $sourceRoot 'index.template.html'
$cssPath = Join-Path $sourceRoot 'sunabar.css'
$jsPath = Join-Path $sourceRoot 'sunabar.js'
$outputPath = Join-Path $sourceRoot 'index.html'
$template = [System.IO.File]::ReadAllText($templatePath, [System.Text.Encoding]::UTF8)
$css = [System.IO.File]::ReadAllText($cssPath, [System.Text.Encoding]::UTF8).TrimEnd("`r", "`n")
$js = [System.IO.File]::ReadAllText($jsPath, [System.Text.Encoding]::UTF8).TrimEnd("`r", "`n")
$styleContent = "`n$css`n"
$scriptContent = "`n$js`n"
$styleHash = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($styleContent)))
$scriptHash = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($scriptContent)))
$policy = "default-src 'self'; script-src 'self' 'sha256-$scriptHash'; style-src 'self' 'sha256-$styleHash'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'"
$oldPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'"
$template = $template.Replace($oldPolicy, $policy)
$template = $template.Replace('  <link rel="stylesheet" href="sunabar.css?v=20261108-v2">', "  <style>$styleContent</style>")
$template = $template.Replace('  <script src="sunabar.js?v=20261108-v2" defer></script>', '')
$template = $template.Replace('</body>', "  <script>$scriptContent</script>`n</body>")
if ($template.Contains('sunabar.css?v=') -or $template.Contains('sunabar.js?v=') -or -not $template.Contains("'sha256-$scriptHash'") -or -not $template.Contains("'sha256-$styleHash'")) {
    throw 'The bundled HTML did not pass its self-contained asset and CSP checks.'
}
[System.IO.File]::WriteAllText($outputPath, $template, [System.Text.UTF8Encoding]::new($false))
Write-Host "Built self-contained Sunabar v2: $outputPath"
