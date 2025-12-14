$root = Split-Path -Parent $PSScriptRoot
$script = Join-Path $root "sentry.ps1"
$outDir = Join-Path $root "output"

& $script -NoHtml -OutDir $outDir

$json = Join-Path $outDir "sentry_results.json"
$csv  = Join-Path $outDir "sentry_results.csv"

if (-not (Test-Path $json)) { throw "Missing output JSON: $json" }
if (-not (Test-Path $csv))  { throw "Missing output CSV:  $csv" }

# Validate JSON parses
Get-Content $json -Raw | ConvertFrom-Json | Out-Null

Write-Host "Smoke test passed."
