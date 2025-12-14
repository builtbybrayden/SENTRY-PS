function Get-RdpStatus {
    [CmdletBinding()]
    param()

    # RDP enabled if fDenyTSConnections = 0
    $rdpRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $deny = (Get-ItemProperty -Path $rdpRegPath -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    $rdpEnabled = ($null -ne $deny -and [int]$deny -eq 0)

    # NLA: UserAuthentication = 1 (required) in RDP-Tcp key
    $nlaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    $ua = (Get-ItemProperty -Path $nlaPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
    $nlaRequired = ($null -ne $ua -and [int]$ua -eq 1)

    # Firewall: check enabled rules for Remote Desktop group (best-effort)
    $fwAllow = $null
    try {
        $rules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction Stop |
            Where-Object { $_.Enabled -eq "True" -and $_.Action -eq "Allow" }
        $fwAllow = ($rules.Count -gt 0)
    } catch {
        $fwAllow = $null
    }

    $findings = @()

    $findings += [PSCustomObject]@{
        CheckName   = "RDP Configuration"
        Finding     = if ($rdpEnabled) { "RDP Enabled" } else { "RDP Disabled" }
        Severity    = if ($rdpEnabled) { "High" } else { "Low" }
        Confidence  = 0.9
        Evidence    = "fDenyTSConnections=$deny"
    }

    if ($rdpEnabled) {
        $findings += [PSCustomObject]@{
            CheckName   = "RDP Configuration"
            Finding     = if ($nlaRequired) { "RDP NLA Required" } else { "RDP NLA Not Required" }
            Severity    = if ($nlaRequired) { "Low" } else { "High" }
            Confidence  = 0.85
            Evidence    = "UserAuthentication=$ua"
        }

        $findings += [PSCustomObject]@{
            CheckName   = "RDP Configuration"
            Finding     = if ($fwAllow -eq $true) { "RDP Firewall Rule Allow Enabled" }
                          elseif ($fwAllow -eq $false) { "RDP Firewall Rule Allow Not Enabled" }
                          else { "RDP Firewall Rule Unknown" }
            Severity    = if ($fwAllow -eq $true) { "Medium" } elseif ($fwAllow -eq $false) { "Low" } else { "Low" }
            Confidence  = if ($fwAllow -eq $null) { 0.6 } else { 0.8 }
            Evidence    = "Remote Desktop firewall allow rule enabled=$fwAllow"
        }
    }

    $findings
}
