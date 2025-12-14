function Get-SmbHardening {
    [CmdletBinding()]
    param()

    $results = @()

    # SMBv1 status (optional feature)
    $smb1Enabled = $null
    try {
        $feat = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
        $smb1Enabled = ($feat.State -eq "Enabled")
    } catch {
        # Fallback: try registry
        $v = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue).SMB1
        if ($null -ne $v) { $smb1Enabled = ([int]$v -eq 1) }
    }

    if ($null -ne $smb1Enabled) {
        $results += [PSCustomObject]@{
            CheckName  = "SMB Hardening"
            Finding    = if ($smb1Enabled) { "SMBv1 Enabled" } else { "SMBv1 Disabled" }
            Severity   = if ($smb1Enabled) { "High" } else { "Low" }
            Confidence = 0.85
            Evidence   = "SMBv1Enabled=$smb1Enabled"
        }
    } else {
        $results += [PSCustomObject]@{
            CheckName  = "SMB Hardening"
            Finding    = "SMBv1 Status Unknown"
            Severity   = "Low"
            Confidence = 0.6
            Evidence   = "Unable to read SMB1 feature/registry"
        }
    }

    # SMB Signing (server)
    $srvSigning = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
    if ($null -ne $srvSigning) {
        $required = ([int]$srvSigning -eq 1)
        $results += [PSCustomObject]@{
            CheckName  = "SMB Hardening"
            Finding    = if ($required) { "SMB Signing Required (Server)" } else { "SMB Signing Not Required (Server)" }
            Severity   = if ($required) { "Low" } else { "High" }
            Confidence = 0.9
            Evidence   = "RequireSecuritySignature=$srvSigning"
        }
    }

    # SMB Signing (client)
    $cliSigning = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
    if ($null -ne $cliSigning) {
        $required = ([int]$cliSigning -eq 1)
        $results += [PSCustomObject]@{
            CheckName  = "SMB Hardening"
            Finding    = if ($required) { "SMB Signing Required (Client)" } else { "SMB Signing Not Required (Client)" }
            Severity   = if ($required) { "Low" } else { "High" }
            Confidence = 0.9
            Evidence   = "RequireSecuritySignature=$cliSigning"
        }
    }

    $results
}
