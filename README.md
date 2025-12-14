# SENTRY-PS

SENTRY-PS is a PowerShell-based security enumeration and risk triage tool that audits local Windows security posture and generates actionable reports for defensive security teams.

It is designed to be **read-only**, modular, and framework-aligned, making it suitable for security assessments, baseline comparisons, and continuous posture monitoring.

---

## Key Features

- PowerShell-native (no external dependencies)
- Read-only security checks (no system changes)
- Modular architecture for easy extension
- Risk scoring based on severity × confidence
- Framework mappings:
  - MITRE ATT&CK
  - NIST SP 800-53
  - CIS Benchmarks
- Multiple output formats:
  - JSON (SIEM / automation friendly)
  - CSV (Power BI / Excel ready)
  - HTML (executive-friendly report)
- Baseline save and comparison for drift detection

---

## Security Checks Implemented

- Windows Firewall profile status
- Remote Desktop Protocol (RDP)
  - Enabled/disabled
  - Network Level Authentication (NLA)
  - Firewall allow rules
- SMB hardening
  - SMBv1 enablement
  - SMB signing (client and server)
- Microsoft Defender posture (best-effort)
  - Real-time protection
  - Antivirus status
  - Signature information

---

## Quick Start

```powershell
git clone https://github.com/builtbybrayden/SENTRY-PS.git
cd SENTRY-PS
.\sentry.ps1

---

## Baseline & Drift Detection

Save a baseline:

```powershell
.\sentry.ps1 -SaveBaseline


Compare against a previous baseline:

```powershell
.\sentry.ps1 -CompareBaseline .\output\baseline.json


This highlights:

- Newly introduced findings
- Removed findings
- Changes in severity, evidence, or risk score

---

## Output

All results are written to the output/ directory:
- sentry_results.json — structured output for automation or SIEM ingestion
- sentry_results.csv — analyst-friendly tabular data
- sentry_report.html — summarized security report with risk prioritization, framework mappings, and remediation guidance

---

## Safety & Intended Use

SENTRY-PS performs read-only security checks only and does not modify system configuration.

It is intended for defensive security assessment, posture monitoring, and educational use.