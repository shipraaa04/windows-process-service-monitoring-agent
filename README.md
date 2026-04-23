# 🛡️ Windows Service & Process Monitoring Agent

> **Blue Team Cybersecurity Toolkit** — Real-time detection of malicious, unauthorized, and suspicious Windows process behavior using behavior-based and rule-based analysis.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Detection Capabilities](#-detection-capabilities)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [Sample Output](#-sample-output)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [Project Structure](#-project-structure)
- [Technologies Used](#-technologies-used)
- [Learning Outcomes](#-learning-outcomes)

---

## 🔍 Overview

Windows services and processes are the most commonly abused components in modern cyberattacks. Malware operators exploit them for:

- **Initial Access** — malicious services registered at startup
- **Privilege Escalation** — misconfigured service permissions
- **Persistence** — registry-based and service-based persistence mechanisms
- **Lateral Movement** — process injection and parent-child chain abuse

This monitoring agent continuously analyzes running processes and startup services to detect these threats **before they cause damage** — mapping every finding to the MITRE ATT&CK framework for standardized threat intelligence.

> ✅ Works on **Windows** (live system scan) and **any OS** (simulation mode with realistic threat scenarios for learning/demo).

---

## ✨ Features

| Feature | Description |
|---|---|
| 🌲 **Parent-Child Analysis** | Detects forbidden process spawn chains (e.g., `winword.exe → powershell.exe`) |
| 🔧 **Service Auditing** | Enumerates all startup services and flags suspicious paths/commands |
| 🚫 **Unauthorized Detection** | Whitelist/blacklist engine for process authorization |
| 🔴 **Severity Alerting** | CRITICAL / HIGH / MEDIUM / LOW tiered alert system |
| 🗺️ **MITRE ATT&CK Mapping** | Every alert linked to a specific ATT&CK technique ID |
| 📊 **Structured Reports** | JSON reports + human-readable console summaries |
| ⏱️ **Continuous Monitoring** | Scheduled scans with configurable intervals |
| 💻 **Simulation Mode** | Full demo on non-Windows systems for learning |

---

## 🎯 Detection Capabilities

### Parent-Child Relationship Rules

The agent flags these process spawn chains as suspicious:

```
winword.exe  →  powershell.exe  ❌  (Office macro abuse)
winword.exe  →  cmd.exe         ❌  (Office macro abuse)
mshta.exe    →  cmd.exe         ❌  (HTML application abuse)
excel.exe    →  wscript.exe     ❌  (Excel macro → script)
iexplore.exe →  mshta.exe       ❌  (Browser → HTML app)
svchost.exe  →  powershell.exe  ❌  (Service host abuse)
lsass.exe    →  cmd.exe         ❌  (LSASS child process)
```
*15+ forbidden relationships monitored across all major Office, browser, and system processes.*

### Startup Service Detection Rules

| Rule | Severity | Condition |
|---|---|---|
| R-004 | HIGH | Service binary located in `\Temp\` or `\Public\` |
| R-005 | CRITICAL | `powershell -enc` found in service path |
| R-008 | CRITICAL | `.vbs`, `.js`, `.bat`, `.ps1` in service path |
| R-007 | HIGH | Service binary in `\ProgramData\` |

### Unauthorized Process Detection

- **CRITICAL** — Known offensive tools: `mimikatz.exe`, `nc.exe`, `procdump.exe`, `wce.exe`, `meterpreter.exe` and 15+ more
- **HIGH** — Executables running from `C:\Temp`, `C:\Users\Public`, `%APPDATA%\Temp`
- **LOW** — Processes not found in the approved whitelist (50+ known-good processes)

---

## 🏗️ Architecture

```
START
  │
  ▼
┌─────────────────────┐
│  Process Enumerator  │  ← PID, PPID, Name, Path, Username, CmdLine
└──────────┬──────────┘
           │
  ▼        ▼
┌─────────────────────┐   ┌─────────────────────────┐
│ Parent-Child Analyzer│   │  Startup Service Auditor │  ← WMI / Win32_Service
└──────────┬──────────┘   └────────────┬────────────┘
           │                           │
           ▼                           ▼
┌──────────────────────────────────────────────┐
│           Unauthorized Process Detector       │  ← Whitelist / Blacklist / Path Check
└──────────────────────┬───────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Alert Aggregator │  ← Severity scoring, deduplication
              └────────┬────────┘
                       │
                       ▼
             ┌──────────────────┐
             │  Report Generator │  ← JSON + Console + Log
             └──────────────────┘
                       │
                       ▼
                      END
```

---

## ⚙️ Installation

### Requirements

```bash
Python 3.8+
```

### Step 1 — Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/windows-monitoring-agent.git
cd windows-monitoring-agent
```

### Step 2 — Install Dependencies

```bash
pip install -r requirements.txt
```

**On Windows (for live scanning):**
```bash
pip install psutil wmi pywin32
```

**On any OS (simulation mode — no extra setup needed):**
```bash
pip install psutil
```

---

## 🚀 Usage

### Single Scan (recommended for first run)

```bash
python monitoring_agent.py
```

### Continuous Monitoring Mode

```bash
python monitoring_agent.py --continuous
```

### Custom Scan Interval

```bash
python monitoring_agent.py --continuous --interval 30
```

### Custom Output Directory

```bash
python monitoring_agent.py --output ./my_reports
```

### All Options

```
usage: monitoring_agent.py [-h] [--continuous] [--interval N] [--output DIR]

optional arguments:
  -h, --help       Show this help message and exit
  --continuous     Run in continuous monitoring loop (default: single scan)
  --interval N     Scan interval in seconds (default: 60)
  --output DIR     Directory for reports and logs (default: ./reports)
```

---

## 📊 Sample Output

```
══════════════════════════════════════════════════════════════════════
  DETECTION REPORT — Windows Service & Process Monitoring Agent
══════════════════════════════════════════════════════════════════════
  Generated : 2026-04-23T11:04:12
  Mode      : SIMULATION
  Risk Level: CRITICAL
══════════════════════════════════════════════════════════════════════
  Processes Scanned : 19
  Services Audited  : 8
  Total Alerts      : 13

  ALERTS BY SEVERITY:
    CRITICAL   :   4  ████
    HIGH       :   7  ███████
    LOW        :   2  ██

══════════════════════════════════════════════════════════════════════
  DETAILED ALERTS:
══════════════════════════════════════════════════════════════════════

  [CRITICAL] Suspicious Startup Service
  Title      : Encoded/script command in service path: UpdaterTaskSvc
  Description: Service path contains 'powershell -enc' — encoded persistence detected.
  MITRE ATT&CK: T1059 - Command and Scripting Interpreter

  [CRITICAL] High-Risk Process
  Title      : High-risk process detected: nc.exe
  Description: Known offensive tool. Presence strongly indicates compromise.
  MITRE ATT&CK: T1003 - OS Credential Dumping

  [HIGH] Parent-Child Anomaly
  Title      : Suspicious spawn: winword.exe → powershell.exe
  Description: Office macro execution chain — living-off-the-land attack pattern.
  MITRE ATT&CK: T1059 - Command and Scripting Interpreter

  [HIGH] Suspicious Process Location
  Title      : Process running from suspicious path: svchosts.exe
  Description: Masquerading svchost.exe executing from C:\Windows\Temp
  MITRE ATT&CK: T1036 - Masquerading
```

**Reports saved to:**
```
reports/
├── detection_report.json   ← Full structured alert data
└── agent.log               ← Timestamped event log
```

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Name | Detection Module |
|---|---|---|
| T1059 | Command and Scripting Interpreter | Parent-Child Analyzer, Service Auditor |
| T1059.001 | PowerShell | Encoded service path detection |
| T1543.003 | Windows Service | Startup Service Auditor |
| T1036 | Masquerading | Unauthorized Process Detector |
| T1036.005 | Match Legitimate Name or Location | Whitelist violation detection |
| T1003 | OS Credential Dumping | High-risk process blacklist |
| T1055 | Process Injection | Parent-child chain analysis |
| T1569.002 | Service Execution | Service path command detection |

---

## 📁 Project Structure

```
windows-monitoring-agent/
│
├── monitoring_agent.py          ← Main detection agent (all modules)
├── requirements.txt             ← Python dependencies
├── README.md                    ← This file
│
├── reports/                     ← Auto-created on first run
│   ├── detection_report.json    ← Structured alert output
│   └── agent.log                ← Event log
│
├── docs/
│   ├── Windows_Monitoring_Agent_Documentation.docx
│   └── Windows_Monitoring_Agent_Presentation.pptx
│
└── sample_output/
    └── detection_report.json    ← Example report (simulation mode)
```

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| **Python 3.x** | Primary programming language |
| **psutil** | Cross-platform process enumeration |
| **wmi** | Windows Management Instrumentation queries |
| **pywin32** | Win32 API access for Windows services |
| **json** | Structured report generation |
| **logging** | Multi-level event logging |
| **argparse** | Command-line interface |

---

## 📚 Learning Outcomes

This project teaches:

- ✅ Windows process architecture (PID, PPID, process trees, service internals)
- ✅ How malware abuses services and processes (LOTL, persistence, masquerading)
- ✅ Python security tooling (psutil, WMI, win32 APIs)
- ✅ Rule-based detection engineering with low false-positive logic
- ✅ MITRE ATT&CK framework — mapping detections to industry-standard TTPs
- ✅ Blue team operations — monitoring, alert triage, SOC-ready reporting
- ✅ Defensive security engineering principles

---

<div align="center">
  <strong>Built for Blue Team | Defensive Security Engineering</strong><br>
  <em>Detect threats before they cause damage</em>
</div>
