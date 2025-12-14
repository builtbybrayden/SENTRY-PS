[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path $PSScriptRoot "output"),
    [switch]$NoHtml,
    [switch]$SaveBaseline,
    [string]$BaselinePath = (Join-Path $PSScriptRoot "output\baseline.json"),
    [string]$CompareBaseline
)

$SentryVersion = "1.0.0"

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot

function Get-SeverityWeight {
    param(
        [Parameter(Mandatory)]$RiskMatrix,
        [Parameter(Mandatory)][string]$Severity
    )
    $w = $RiskMatrix.severity_weights.($Severity)
    if (-not $w) { return 5 }
    return [double]$w
}

function New-Delta {
    param(
        [Parameter(Mandatory)]$Baseline,
        [Parameter(Mandatory)]$Current
    )

    # Identity key generator
    $keyFunc = {
        param($x)
        $p =
    if ($x.PSObject.Properties.Name -contains "Profile" -and
        $null -ne $x.Profile -and
        "$($x.Profile)".Length -gt 0) {
        $x.Profile
    } else {
        ""
    }
        "$($x.Host)|$($x.CheckName)|$($x.Finding)|$p"
    }

    $bMap = @{}
    foreach ($b in $Baseline) {
        $k = & $keyFunc $b
        $bMap[$k] = $b
    }

    $cMap = @{}
    foreach ($c in $Current) {
        $k = & $keyFunc $c
        $cMap[$k] = $c
    }

    $added   = @()
    $removed = @()
    $changed = @()

    foreach ($k in $cMap.Keys) {
        if (-not $bMap.ContainsKey($k)) {
            $added += $cMap[$k]
            continue
        }

        $b = $bMap[$k]
        $c = $cMap[$k]

        if (
            $b.Severity  -ne $c.Severity -or
            $b.RiskScore -ne $c.RiskScore -or
            $b.Evidence  -ne $c.Evidence
        ) {
            $changed += [PSCustomObject]@{
                Key    = $k
                Before = $b
                After  = $c
            }
        }
    }

    foreach ($k in $bMap.Keys) {
        if (-not $cMap.ContainsKey($k)) {
            $removed += $bMap[$k]
        }
    }

    [PSCustomObject]@{
        Added   = $added
        Removed = $removed
        Changed = $changed
    }
}

function Convert-MitreToLinks {
    param(
        [string]$MitreString
    )

    if ([string]::IsNullOrWhiteSpace($MitreString)) {
        return ""
    }

    $links = foreach ($tech in ($MitreString -split ",")) {
        $t = $tech.Trim()

        # Handle sub-techniques (Txxxx.yyy)
        if ($t -match "^T\d{4}\.\d{3}$") {
            $base = $t.Split(".")[0]
            "<a href='https://attack.mitre.org/techniques/$($base.Substring(1))/$($t.Split(".")[1])/' target='_blank'>$t</a>"
        }
        elseif ($t -match "^T\d{4}$") {
            "<a href='https://attack.mitre.org/techniques/$($t.Substring(1))/' target='_blank'>$t</a>"
        }
        else {
            $t
        }
    }

    $links -join ", "
}

function ConvertFrom-HtmlEncoded {
    param([string]$Html)

    Add-Type -AssemblyName System.Web
    return [System.Web.HttpUtility]::HtmlDecode($Html)
}

function ConvertTo-SentryHtml {
    param(
        [Parameter(Mandatory)]$Results
    )

    # Normalize
    $Results = @($Results)

    # --- Safe counts ---
    $total = ($Results | Measure-Object).Count

    $mitreMapped = ($Results | Where-Object {
        $_.PSObject.Properties.Name -contains "MITRE" -and
        -not [string]::IsNullOrWhiteSpace($_.MITRE)
    } | Measure-Object).Count

    $nistMapped = ($Results | Where-Object {
        $_.PSObject.Properties.Name -contains "NIST" -and
        -not [string]::IsNullOrWhiteSpace($_.NIST)
    } | Measure-Object).Count

    $cisMapped = ($Results | Where-Object {
        $_.PSObject.Properties.Name -contains "CIS" -and
        -not [string]::IsNullOrWhiteSpace($_.CIS)
    } | Measure-Object).Count

    $coverage = @(
        [PSCustomObject]@{
            Framework = "MITRE ATT&CK"
            Mapped    = $mitreMapped
            Total     = $total
            Coverage  = "{0:P0}" -f ($mitreMapped / [Math]::Max(1, $total))
        },
        [PSCustomObject]@{
            Framework = "NIST SP 800-53"
            Mapped    = $nistMapped
            Total     = $total
            Coverage  = "{0:P0}" -f ($nistMapped / [Math]::Max(1, $total))
        },
        [PSCustomObject]@{
            Framework = "CIS Benchmarks"
            Mapped    = $cisMapped
            Total     = $total
            Coverage  = "{0:P0}" -f ($cisMapped / [Math]::Max(1, $total))
        }
    )

    # --- Severity summary (safe) ---
    $summaryRows =
        $Results |
        Group-Object Severity |
        Sort-Object Name |
        ForEach-Object {
            [PSCustomObject]@{
                Severity = $_.Name
                Count    = $_.Group.Count
            }
        }

    $top =
        $Results |
        Sort-Object RiskScore -Descending |
        Select-Object -First 10

    $grouped =
        $Results |
        Group-Object CheckName |
        Sort-Object Name

    # --- HTML ---
    $html = @()
    $html += "<h1>SENTRY-PS Security Report (v$SentryVersion)</h1>"
    $html += "<p><b>Host:</b> $($env:COMPUTERNAME)<br/><b>Generated:</b> $(Get-Date)</p>"

    $html += "<h2>Summary</h2>"
    $html += ($summaryRows | ConvertTo-Html -Fragment)

    $html += "<h2>Framework Coverage</h2>"
    $html += ($coverage | ConvertTo-Html -Fragment)

    $html += "<p><b>Total Findings:</b> $total</p>"

    $html += "<h2>Top Risks</h2>"
    $topHtml =
        $top |
        Select-Object Timestamp, Severity, RiskScore, Finding, CheckName, Evidence,
            @{ Name = "MITRE"; Expression = { Convert-MitreToLinks $_.MITRE } },
            NIST, CIS |
        ConvertTo-Html -Fragment

    $html += ConvertFrom-HtmlEncoded $topHtml


    foreach ($g in $grouped) {
        $html += "<h2>$($g.Name)</h2>"
        $groupHtml =
        $g.Group |
        Sort-Object RiskScore -Descending |
        Select-Object Timestamp, Severity, RiskScore, Finding, Evidence,
            @{ Name = "MITRE"; Expression = { Convert-MitreToLinks $_.MITRE } },
            NIST, CIS, Remediation, Profile, Enabled |
        ConvertTo-Html -Fragment

    $html += ConvertFrom-HtmlEncoded $groupHtml
    }

    ($html -join "`n")
}

# Ensure output directory exists
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

# Load config (using root paths)
$riskMatrixPath = Join-Path $Root "config\risk_matrix.json"
$mappingsPath   = Join-Path $Root "config\mappings.json"

$riskMatrix = Get-Content $riskMatrixPath -Raw | ConvertFrom-Json
$mappings   = Get-Content $mappingsPath -Raw | ConvertFrom-Json

# Dot-source modules safely (only function definitions should exist in module files)
Get-ChildItem (Join-Path $Root "modules\*.ps1") | ForEach-Object { . $_.FullName }

# Run checks
$rawFindings = @()
$rawFindings += Get-FirewallStatus
$rawFindings += Get-RdpStatus
$rawFindings += Get-SmbHardening
$rawFindings += Get-DefenderStatus

# Enrich + score
$results = foreach ($f in $rawFindings) {

    $map = $null
    if ($mappings.PSObject.Properties.Name -contains $f.Finding) {
        $map = $mappings.($f.Finding)
    }

    $sevWeight = Get-SeverityWeight -RiskMatrix $riskMatrix -Severity $f.Severity
    $confidence =
    if ($f.PSObject.Properties.Name -contains "Confidence") {
        [double]$f.Confidence
    } else {
        [double]$riskMatrix.default_confidence
    }

    $riskScore = [Math]::Round(($sevWeight * $confidence), 2)

    [PSCustomObject]@{
        Timestamp   = (Get-Date).ToString("s")
        Host        = $env:COMPUTERNAME
        CheckName   = $f.CheckName
        Finding     = $f.Finding
        Severity    = $f.Severity
        Confidence  = $confidence
        RiskScore   = $riskScore
        Evidence    = $f.Evidence
        MITRE       = if ($map) { ($map.MITRE -join ",") } else { "" }
        NIST        = if ($map) { ($map.NIST -join ",") } else { "" }
        CIS         = if ($map) { ($map.CIS -join ",") } else { "" }
        Remediation = if ($map) { $map.Remediation } else { "" }
        Profile =
            if ($f.PSObject.Properties.Name -contains "Profile") {
                $f.Profile
            } else {
                ""
            }

        Enabled =
            if ($f.PSObject.Properties.Name -contains "Enabled") {
                $f.Enabled
            } else {
                $null
            }
    }
    if (-not $map) {
        Write-Verbose "No framework mapping found for finding: $($f.Finding)"
    }
}

# Export current outputs
$jsonPath = Join-Path $OutDir "sentry_results.json"
$csvPath  = Join-Path $OutDir "sentry_results.csv"

$results | ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 $jsonPath
$results | Export-Csv -NoTypeInformation -Encoding utf8 $csvPath

# Baseline save
if ($SaveBaseline) {
    $results | ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 $BaselinePath
    Write-Host "Baseline saved: $BaselinePath"
}

# Baseline compare
if ($CompareBaseline) {
    $baseline = Get-Content $CompareBaseline -Raw | ConvertFrom-Json
    $delta = New-Delta -Baseline $baseline -Current $results

    $deltaPath = Join-Path $OutDir "sentry_delta.json"
    $delta | ConvertTo-Json -Depth 8 | Out-File -Encoding utf8 $deltaPath
    Write-Host "Delta saved: $deltaPath"

    Write-Host ("Delta summary: Added={0}, Removed={1}, Changed={2}" -f $delta.Added.Count, $delta.Removed.Count, $delta.Changed.Count)
}

# HTML report
if (-not $NoHtml) {
    $htmlPath = Join-Path $OutDir "sentry_report.html"
    $html = ConvertTo-SentryHtml -Results $results
    $html | Out-File -Encoding utf8 $htmlPath
    Write-Host "HTML: $htmlPath"
}

Write-Host "JSON: $jsonPath"
Write-Host "CSV : $csvPath"
Write-Host "Done."
Write-Host "SENTRY-PS version $SentryVersion"