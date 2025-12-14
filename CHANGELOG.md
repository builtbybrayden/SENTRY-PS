# Changelog

## v1.0.0 – Initial Release

### Features
- Modular PowerShell security enumeration engine
- Read-only audits for Windows systems
- Security checks:
  - Windows Firewall profile status
  - RDP configuration (enabled, NLA, firewall rules)
  - SMB hardening (SMBv1, SMB signing client/server)
  - Microsoft Defender posture (best-effort)
- Risk scoring based on severity × confidence
- Centralized framework mappings:
  - MITRE ATT&CK
  - NIST SP 800-53
  - CIS Benchmarks
- Framework coverage statistics
- Clickable MITRE technique links in HTML report
- Output formats:
  - JSON (automation / SIEM)
  - CSV (analysis / dashboards)
  - HTML (executive reporting)
- Baseline save and drift comparison
- GitHub Actions CI smoke test

### Notes
- Designed to run under Set-StrictMode -Version Latest
- Defensive use only; no system modifications performed
