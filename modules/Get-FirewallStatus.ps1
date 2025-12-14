function Get-FirewallStatus {
    [CmdletBinding()]
    param()

    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
    } catch {
        # Fallback for older/limited environments without NetSecurity cmdlets
        $profiles = @()

        foreach ($name in @("Domain", "Private", "Public")) {
            $value = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$name" -ErrorAction SilentlyContinue).EnableFirewall
            $enabled = $false
            if ($null -ne $value) { $enabled = [bool]$value }

            $profiles += [PSCustomObject]@{
                Name    = $name
                Enabled = $enabled
            }
        }
    }

    foreach ($p in $profiles) {
        [PSCustomObject]@{
            CheckName = "Firewall Profile Enabled"
            Profile   = $p.Name
            Enabled   = [bool]$p.Enabled
            Finding   = if ($p.Enabled) { "Firewall Enabled" } else { "Firewall Disabled" }
            Severity  = if ($p.Enabled) { "Low" } else { "High" }
            Evidence  = "Profile=$($p.Name); Enabled=$([bool]$p.Enabled)"
        }
    }
}
