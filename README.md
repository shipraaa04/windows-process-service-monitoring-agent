# Windows Service & Process Monitoring Agent

> **Blue Team Cybersecurity Tool** — Detects malicious, unauthorized, and suspicious process behavior on Windows systems.


---

## What It Does

The monitoring agent runs a **6-step detection pipeline** on every scan:

```
Enumerate Processes  →  Analyze Parent-Child Trees  →  Audit Services
       ↓
Detect Unauthorized Processes  →  Generate Alerts  →  Export JSON Report
```

**On the sample simulation run it detected:**
- `winword.exe → powershell.exe` (Office macro abuse)
- `mshta.exe → cmd.exe` (HTML application host abuse)
- `nc.exe` running from `C:\Users\Public\Downloads\` (netcat — reverse shell tool)
- 2 services with base64-encoded commands (`-enc` flag in service path)
- `svchosts.exe` masquerading as `svchost.exe` from `C:\Windows\Temp\`
- `backdoor_svc.exe` running as an unknown process
- **Total: 13 alerts — Risk Level: CRITICAL**

---

## Quick Start

### Requirements

```bash
# All platforms
pip install psutil pandas numpy streamlit

# Windows only (for live monitoring)
pip install psutil wmi pywin32
```

### Run a Scan

```bash
# Single scan (cross-platform, uses simulation on non-Windows)
python monitoring_agent.py

# Continuous monitoring (Windows)
python monitoring_agent.py --continuous

# Custom interval and output directory
python monitoring_agent.py --continuous --interval 30 --output C:\SecurityReports
```

### Output

```
reports/
├── detection_report.json   ← Full structured report with all alerts
└── agent.log               ← Timestamped debug log
```

---

## Detection Modules

| Module | Class | What It Detects |
|--------|-------|-----------------|
| 1 | `ProcessEnumerator` | All running processes: PID, PPID, exe path, user |
| 2 | `ParentChildAnalyzer` | Forbidden parent→child process relationships (15+ rules) |
| 3 | `StartupServiceAuditor` | Suspicious service paths, encoded commands, Temp-path binaries |
| 4 | `UnauthorizedProcessDetector` | Blacklisted tools (mimikatz, nc.exe), unknown processes, suspicious paths |
| 5 | `ReportGenerator` | Structured JSON report + colour-coded console summary |

---

## Detection Rules

| Rule | Type | Description | Severity | MITRE |
|------|------|-------------|----------|-------|
| R-001 | Parent-Child | Office apps spawning PowerShell/cmd | HIGH | T1059 |
| R-002 | Parent-Child | mshta/wscript spawning shell | HIGH | T1059 |
| R-003 | Parent-Child | lsass/csrss spawning any shell | HIGH | T1059 |
| R-004 | Parent-Child | svchost spawning scripting interpreters | HIGH | T1059 |
| R-005 | Parent-Child | Browsers spawning cmd/PowerShell | HIGH | T1059 |
| R-006 | Service Audit | Service binary in Temp/Public/ProgramData | HIGH | T1543.003 |
| R-007 | Service Audit | Service path contains `-enc` or `cmd /c` | CRITICAL | T1059 |
| R-008 | Service Audit | Service path contains `.vbs`, `.bat`, `.ps1` | CRITICAL | T1059 |
| R-009 | Process Detect | Known offensive tool name (nc, mimikatz…) | CRITICAL | T1003 |
| R-010 | Process Detect | Process executing from user-writable path | HIGH | T1036 |
| R-011 | Process Detect | Unknown .exe not in whitelist | LOW | T1036.005 |

---

## Alert Severity Model

| Level | Icon | Meaning |
|-------|------|---------|
| CRITICAL 🔴 | Active compromise — known offensive tools, encoded service commands |
| HIGH 🟠 | Strong anomaly — Office→PowerShell spawn, Temp-path services |
| MEDIUM 🟡 | Moderate risk — reserved for future rules |
| LOW 🔵 | Unknown process not in whitelist; review recommended |
| INFO ⚪ | Informational — no immediate threat |

---

## MITRE ATT&CK Coverage

| Technique | ID | Description |
|-----------|----|-------------|
| Command & Scripting Interpreter | T1059 | PowerShell, cmd, wscript, mshta abuse |
| Windows Service | T1543.003 | Malware persistence via registered services |
| Masquerading | T1036 | Processes mimicking legitimate names |
| Match Legitimate Name/Location | T1036.005 | Unknown executables blending with known |
| OS Credential Dumping | T1003 | Credential harvesting tools detected |
| Process Injection | T1055 | Suspicious process chains |

---

## Project Structure

```
.
├── monitoring_agent.py          ← Main agent (all modules + CLI)
├── requirements.txt             ← Python dependencies
├── runtime.txt                  ← Python 3.11
├── detection_report_sample.json ← Sample output report
├── README.md                    ← This file
├── CHANGELOG.md                 ← Version history
├── CONTRIBUTING.md              ← How to contribute
├── .gitignore                   ← Excludes reports/, logs, __pycache__
└── reports/ (generated)
    ├── detection_report.json    ← Created on scan
    └── agent.log                ← Created on scan
```

---

## Configuration

Edit `CONFIG` at the top of `monitoring_agent.py`:

```python
CONFIG = {
    "output_dir": "./reports",            # Report output location
    "log_file": "./reports/agent.log",    # Log file path
    "report_file": "./reports/detection_report.json",
    "scan_interval_seconds": 60,          # Continuous mode frequency
    "alert_threshold": "medium",          # low | medium | high
}
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- How to report bugs
- How to add new detection rules (with MITRE ID requirements)
- Code style guidelines (PEP 8, Alert class pattern)
- Areas that need help (event log integration, email alerting, unit tests)

**All contributions must be for defensive and educational purposes only.**

---

## Ethical Use

This tool is built for **authorized monitoring, blue team operations, and security education only**. Deploy only on systems you own or have explicit permission to monitor. The simulation mode allows safe demonstration on any OS without requiring Windows or elevated privileges.

---

## Version

**v2.0** — April 23, 2026 | [Full Changelog](CHANGELOG.md)
