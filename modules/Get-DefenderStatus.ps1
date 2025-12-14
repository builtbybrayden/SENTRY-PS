function Get-DefenderStatus {
    [CmdletBinding()]
    param()

    $results = @()

    # Best-effort: only works if Defender module/cmdlets present
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop

        $results += [PSCustomObject]@{
            CheckName  = "Defender Posture"
            Finding    = if ($mp.RealTimeProtectionEnabled) { "Defender Real-time Protection Enabled" } else { "Defender Real-time Protection Disabled" }
            Severity   = if ($mp.RealTimeProtectionEnabled) { "Low" } else { "High" }
            Confidence = 0.9
            Evidence   = "RealTimeProtectionEnabled=$($mp.RealTimeProtectionEnabled)"
        }

        $results += [PSCustomObject]@{
            CheckName  = "Defender Posture"
            Finding    = if ($mp.AntivirusEnabled) { "Defender Antivirus Enabled" } else { "Defender Antivirus Disabled" }
            Severity   = if ($mp.AntivirusEnabled) { "Low" } else { "High" }
            Confidence = 0.85
            Evidence   = "AntivirusEnabled=$($mp.AntivirusEnabled)"
        }

        $results += [PSCustomObject]@{
            CheckName  = "Defender Posture"
            Finding    = "Defender Signature Age (Hours)"
            Severity   = "Low"
            Confidence = 0.8
            Evidence   = "AntivirusSignatureLastUpdated=$($mp.AntivirusSignatureLastUpdated)"
        }

    } catch {
        $results += [PSCustomObject]@{
            CheckName  = "Defender Posture"
            Finding    = "Defender Status Unavailable"
            Severity   = "Low"
            Confidence = 0.6
            Evidence   = "Get-MpComputerStatus not available or failed"
        }
    }

    $results
}
