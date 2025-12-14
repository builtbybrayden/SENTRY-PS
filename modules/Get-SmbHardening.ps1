function Get-SmbHardening {
    [CmdletBinding()]
    param()

    $results = @()

    # --- SMBv1 status ---
    $smb1Enabled = $null

    try {
        # Preferred method (Windows optional feature)
        $feat = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
        $smb1Enabled = ($feat.State -eq "Enabled")
        $evidence = "WindowsOptionalFeature State=$($feat.State)"
    }
    catch {
        # Fallback: registry (value may not exist on hardened systems)
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $reg = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

        if ($null -ne $reg -and ($reg.PSObject.Properties.Name -contains "SMB1")) {
            $smb1Enabled = ([int]$reg.SMB1 -eq 1)
            $evidence = "Registry SMB1=$($reg.SMB1)"
        }
        else {
            # Property missing usually means SMBv1 is disabled/removed
            $smb1Enabled = $false
            $evidence = "SMB1 registry value not present (treated as disabled)"
        }
    }

    $results += [PSCustomObject]@{
        CheckName  = "SMB Hardening"
        Finding    = if ($smb1Enabled) { "SMBv1 Enabled" } else { "SMBv1 Disabled" }
        Severity   = if ($smb1Enabled) { "High" } else { "Low" }
        Confidence = 0.9
        Evidence   = $evidence
    }

    # --- SMB Signing (Server) ---
    $srvRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $srv = Get-ItemProperty -Path $srvRegPath -ErrorAction SilentlyContinue

    if ($null -ne $srv -and ($srv.PSObject.Properties.Name -contains "RequireSecuritySignature")) {
        $required = ([int]$srv.RequireSecuritySignature -eq 1)

        $results += [PSCustomObject]@{
            CheckName  = "SMB Hardening"
            Finding    = if ($required) { "SMB Signing Required (Server)" } else { "SMB Signing Not Required (Server)" }
            Severity   = if ($required) { "Low" } else { "High" }
            Confidence = 0.9
            Evidence   = "RequireSecuritySignature=$($srv.RequireSecuritySignature)"
        }
    }

    # --- SMB Signing (Client) ---
    $cliRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    $cli = Get-ItemProperty -Path $cliRegPath -ErrorAction SilentlyContinue

    if ($null -ne $cli -and ($cli.PSObject.Properties.Name -contains "RequireSecuritySignature")) {
        $required = ([int]$cli.RequireSecuritySignature -eq 1)

        $results += [PSCustomObject]@{
            CheckName  = "SMB Hardening"
            Finding    = if ($required) { "SMB Signing Required (Client)" } else { "SMB Signing Not Required (Client)" }
            Severity   = if ($required) { "Low" } else { "High" }
            Confidence = 0.9
            Evidence   = "RequireSecuritySignature=$($cli.RequireSecuritySignature)"
        }
    }

    $results
}
