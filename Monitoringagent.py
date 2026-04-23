import os
import sys
import json
import time
import platform
import datetime
import logging
from pathlib import Path
from collections import defaultdict

# ─────────────────────────────────────────────────────────────
# CONDITIONAL IMPORTS (Windows vs simulation mode)
# ─────────────────────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    try:
        import psutil
        import wmi
    except ImportError:
        print("[!] Missing libraries. Run: pip install psutil wmi pywin32")
        sys.exit(1)
else:
    # ── SIMULATION MODE for non-Windows environments ──────────
    print("[INFO] Non-Windows system detected. Running in SIMULATION MODE.")
    print("[INFO] All detections below are simulated for demonstration.\n")
    import psutil  # still available cross-platform


# ─────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────
CONFIG = {
    "output_dir": "./reports",
    "log_file": "./reports/agent.log",
    "report_file": "./reports/detection_report.json",
    "scan_interval_seconds": 60,
    "alert_threshold": "medium",  # low | medium | high
}

# ─────────────────────────────────────────────────────────────
# WHITELISTS & THREAT INTELLIGENCE
# ─────────────────────────────────────────────────────────────
WHITELIST_PROCESSES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "taskhost.exe", "taskhostw.exe", "spoolsv.exe", "dwm.exe",
    "ctfmon.exe", "rundll32.exe", "conhost.exe", "dllhost.exe",
    "msiexec.exe", "audiodg.exe", "wuauclt.exe", "searchindexer.exe",
    "python.exe", "python3.exe", "powershell.exe", "cmd.exe",
    "chrome.exe", "firefox.exe", "msedge.exe", "notepad.exe",
    "code.exe", "git.exe", "node.exe", "bash.exe",
}

# Suspicious parent → [forbidden_children] relationships
SUSPICIOUS_PARENT_CHILD = {
    "winword.exe":    ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
    "excel.exe":      ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"],
    "outlook.exe":    ["powershell.exe", "cmd.exe", "regsvr32.exe"],
    "acrobat.exe":    ["powershell.exe", "cmd.exe", "wscript.exe"],
    "acrord32.exe":   ["powershell.exe", "cmd.exe", "wscript.exe"],
    "iexplore.exe":   ["powershell.exe", "cmd.exe", "mshta.exe"],
    "chrome.exe":     ["powershell.exe", "cmd.exe"],
    "firefox.exe":    ["powershell.exe", "cmd.exe"],
    "svchost.exe":    ["powershell.exe", "cmd.exe", "wscript.exe"],
    "wscript.exe":    ["powershell.exe", "cmd.exe", "cscript.exe"],
    "mshta.exe":      ["powershell.exe", "cmd.exe", "wscript.exe"],
    "regsvr32.exe":   ["powershell.exe", "cmd.exe"],
    "lsass.exe":      ["cmd.exe", "powershell.exe", "net.exe"],
    "csrss.exe":      ["cmd.exe", "powershell.exe"],
}

# High-risk binary names
HIGH_RISK_PROCESSES = {
    "mimikatz.exe", "procdump.exe", "pwdump.exe", "gsecdump.exe",
    "fgdump.exe", "wce.exe", "nc.exe", "ncat.exe", "netcat.exe",
    "meterpreter.exe", "psexec.exe", "psexesvc.exe", "radmin.exe",
    "winvnc.exe", "ultravnc.exe", "teamviewer.exe", "anydesk.exe",
    "cobalt_strike.exe", "beacon.exe", "cobaltstrike.exe",
}

# Suspicious directories (running executables from these is suspicious)
SUSPICIOUS_DIRECTORIES = [
    r"C:\Windows\Temp",
    r"C:\Users\Public",
    r"C:\ProgramData",
    r"C:\Temp",
    r"%APPDATA%",
    r"%LOCALAPPDATA%\Temp",
    r"C:\Users\Default",
    "/tmp", "/var/tmp", "/dev/shm",  # Linux equiv for demo
]

# Suspicious startup service indicators
SUSPICIOUS_SERVICE_INDICATORS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\", "\\public\\",
    "powershell -enc", "powershell -e ", "cmd /c", "wscript",
    "cscript", "mshta", "regsvr32", "rundll32",
    ".vbs", ".js", ".bat", ".ps1",
]


# ─────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────
def setup_logging(config: dict) -> logging.Logger:
    os.makedirs(config["output_dir"], exist_ok=True)
    logger = logging.getLogger("MonitoringAgent")
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)-8s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File handler
    fh = logging.FileHandler(config["log_file"])
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger


# ─────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────
class Alert:
    """Represents a single security detection alert."""

    SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def __init__(self, severity: str, category: str, title: str,
                 description: str, details: dict = None):
        self.timestamp = datetime.datetime.now().isoformat()
        self.severity = severity.upper()
        self.category = category
        self.title = title
        self.description = description
        self.details = details or {}

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "details": self.details,
        }

    def __str__(self) -> str:
        sev_icons = {
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🔵", "INFO": "⚪",
        }
        icon = sev_icons.get(self.severity, "❓")
        return f"{icon} [{self.severity}] {self.category} | {self.title}"


class ProcessInfo:
    """Snapshot of a running process."""

    def __init__(self, pid: int, name: str, ppid: int, parent_name: str,
                 exe_path: str, cmdline: str, username: str):
        self.pid = pid
        self.name = name.lower()
        self.ppid = ppid
        self.parent_name = parent_name.lower() if parent_name else ""
        self.exe_path = exe_path or ""
        self.cmdline = cmdline or ""
        self.username = username or ""

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "ppid": self.ppid,
            "parent_name": self.parent_name,
            "exe_path": self.exe_path,
            "cmdline": self.cmdline,
            "username": self.username,
        }


# ─────────────────────────────────────────────────────────────
# MODULE 1: PROCESS ENUMERATOR
# ─────────────────────────────────────────────────────────────
class ProcessEnumerator:
    """Enumerates and maps all running processes with their metadata."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def enumerate(self) -> dict:
        """Returns {pid: ProcessInfo} for all running processes."""
        if not IS_WINDOWS:
            return self._simulate_processes()

        processes = {}
        pid_to_name = {}

        # First pass: collect names
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid_to_name[proc.info["pid"]] = proc.info["name"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Second pass: collect full info
        for proc in psutil.process_iter(["pid", "name", "ppid", "exe", "username"]):
            try:
                info = proc.info
                pid = info["pid"]
                ppid = info.get("ppid", 0) or 0
                parent_name = pid_to_name.get(ppid, "unknown")

                try:
                    cmdline = " ".join(proc.cmdline())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cmdline = ""

                processes[pid] = ProcessInfo(
                    pid=pid,
                    name=info.get("name") or "",
                    ppid=ppid,
                    parent_name=parent_name,
                    exe_path=info.get("exe") or "",
                    cmdline=cmdline,
                    username=info.get("username") or "",
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self.logger.info(f"Enumerated {len(processes)} running processes")
        return processes

    def _simulate_processes(self) -> dict:
        """Generate realistic simulated process data for demo/testing."""
        sim_data = [
            # Normal processes
            (4,    "System",          0,    "",               "C:\\Windows\\System32\\"),
            (512,  "smss.exe",        4,    "System",         "C:\\Windows\\System32\\smss.exe"),
            (668,  "csrss.exe",       512,  "smss.exe",       "C:\\Windows\\System32\\csrss.exe"),
            (784,  "wininit.exe",     512,  "smss.exe",       "C:\\Windows\\System32\\wininit.exe"),
            (832,  "winlogon.exe",    512,  "smss.exe",       "C:\\Windows\\System32\\winlogon.exe"),
            (928,  "services.exe",    784,  "wininit.exe",    "C:\\Windows\\System32\\services.exe"),
            (960,  "lsass.exe",       784,  "wininit.exe",    "C:\\Windows\\System32\\lsass.exe"),
            (1200, "svchost.exe",     928,  "services.exe",   "C:\\Windows\\System32\\svchost.exe"),
            (1400, "svchost.exe",     928,  "services.exe",   "C:\\Windows\\System32\\svchost.exe"),
            (2000, "explorer.exe",    832,  "winlogon.exe",   "C:\\Windows\\explorer.exe"),
            (3200, "chrome.exe",      2000, "explorer.exe",   "C:\\Program Files\\Google\\Chrome\\chrome.exe"),
            (4100, "notepad.exe",     2000, "explorer.exe",   "C:\\Windows\\notepad.exe"),
            # ── DETECTIONS ──────────────────────────────────────────────────
            # 1. Suspicious parent-child: winword → powershell
            (5500, "winword.exe",     2000, "explorer.exe",   "C:\\Program Files\\Microsoft Office\\winword.exe"),
            (5501, "powershell.exe",  5500, "winword.exe",    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            # 2. Suspicious parent-child: mshta → cmd
            (5600, "mshta.exe",       2000, "explorer.exe",   "C:\\Windows\\System32\\mshta.exe"),
            (5601, "cmd.exe",         5600, "mshta.exe",      "C:\\Windows\\System32\\cmd.exe"),
            # 3. Process running from temp
            (6000, "svchosts.exe",    928,  "services.exe",   "C:\\Windows\\Temp\\svchosts.exe"),
            # 4. High-risk process
            (7000, "nc.exe",          5501, "powershell.exe", "C:\\Users\\Public\\Downloads\\nc.exe"),
            # 5. Unknown process
            (8000, "backdoor_svc.exe", 928, "services.exe",   "C:\\ProgramData\\backdoor_svc.exe"),
        ]

        processes = {}
        for pid, name, ppid, parent_name, exe_path in sim_data:
            processes[pid] = ProcessInfo(
                pid=pid, name=name.lower(), ppid=ppid,
                parent_name=parent_name.lower(), exe_path=exe_path,
                cmdline=f'"{exe_path}"', username="SYSTEM" if ppid < 1000 else "DESKTOP-USER",
            )

        self.logger.info(f"[SIM] Generated {len(processes)} simulated processes")
        return processes


# ─────────────────────────────────────────────────────────────
# MODULE 2: PARENT-CHILD RELATIONSHIP ANALYZER
# ─────────────────────────────────────────────────────────────
class ParentChildAnalyzer:
    """Detects anomalous parent → child process relationships."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def analyze(self, processes: dict) -> list:
        """Returns list of Alert objects for suspicious relationships."""
        alerts = []
        self.logger.info("Analyzing parent-child process relationships...")

        for pid, proc in processes.items():
            parent_name = proc.parent_name
            child_name = proc.name

            if parent_name in SUSPICIOUS_PARENT_CHILD:
                forbidden = SUSPICIOUS_PARENT_CHILD[parent_name]
                if child_name in [f.lower() for f in forbidden]:
                    alert = Alert(
                        severity="HIGH",
                        category="Parent-Child Anomaly",
                        title=f"Suspicious spawn: {parent_name} → {child_name}",
                        description=(
                            f"'{parent_name}' spawned '{child_name}' — this is a "
                            f"known malware execution pattern (e.g., Office macro abuse, "
                            f"living-off-the-land attacks)."
                        ),
                        details={
                            "parent_process": parent_name,
                            "parent_pid": proc.ppid,
                            "child_process": child_name,
                            "child_pid": pid,
                            "child_exe": proc.exe_path,
                            "child_cmdline": proc.cmdline,
                            "mitre_technique": "T1059 - Command and Scripting Interpreter",
                        }
                    )
                    alerts.append(alert)
                    self.logger.warning(str(alert))

        return alerts

    def build_tree(self, processes: dict) -> dict:
        """Build {ppid: [child_pids]} tree structure."""
        tree = defaultdict(list)
        for pid, proc in processes.items():
            tree[proc.ppid].append(pid)
        return dict(tree)


# ─────────────────────────────────────────────────────────────
# MODULE 3: STARTUP SERVICE AUDITOR
# ─────────────────────────────────────────────────────────────
class StartupServiceAuditor:
    """Audits Windows startup services for suspicious configurations."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def audit(self) -> tuple:
        """Returns (services_list, alerts_list)."""
        if IS_WINDOWS:
            return self._audit_windows()
        else:
            return self._simulate_audit()

    def _audit_windows(self) -> tuple:
        """Real Windows service audit via WMI."""
        alerts = []
        services = []

        try:
            c = wmi.WMI()
            for svc in c.Win32_Service():
                service_data = {
                    "name": svc.Name,
                    "display_name": svc.DisplayName,
                    "state": svc.State,
                    "start_mode": svc.StartMode,
                    "path": svc.PathName or "",
                    "description": svc.Description or "",
                }
                services.append(service_data)
                alerts.extend(self._check_service(service_data))
        except Exception as e:
            self.logger.error(f"WMI query failed: {e}")

        return services, alerts

    def _simulate_audit(self) -> tuple:
        """Simulated service data for demo."""
        sim_services = [
            {"name": "wuauserv",     "display_name": "Windows Update",          "state": "Running", "start_mode": "Auto",   "path": "C:\\Windows\\System32\\svchost.exe -k netsvcs"},
            {"name": "LanmanServer", "display_name": "Server",                   "state": "Running", "start_mode": "Auto",   "path": "C:\\Windows\\System32\\svchost.exe -k netsvcs"},
            {"name": "Spooler",      "display_name": "Print Spooler",            "state": "Running", "start_mode": "Auto",   "path": "C:\\Windows\\System32\\spoolsv.exe"},
            {"name": "MSDTC",        "display_name": "Distributed Transaction",  "state": "Stopped", "start_mode": "Manual", "path": "C:\\Windows\\System32\\msdtc.exe"},
            # ── SUSPICIOUS SERVICES ────────────────────────────────────────
            {"name": "WindowsHelperSvc",  "display_name": "Windows Helper Service", "state": "Running", "start_mode": "Auto", "path": "C:\\Windows\\Temp\\svchelper.exe"},
            {"name": "SysMonSvc",         "display_name": "System Monitor",          "state": "Running", "start_mode": "Auto", "path": "C:\\ProgramData\\sysmon\\sysmon.exe -enc SGVsbG8="},
            {"name": "UpdaterTaskSvc",    "display_name": "Updater Task",            "state": "Running", "start_mode": "Auto", "path": "cmd /c powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBS"},
            {"name": "UnknownServiceXYZ", "display_name": "Unknown Service XYZ",     "state": "Running", "start_mode": "Auto", "path": "C:\\Users\\Public\\unknown_xyz.exe"},
        ]

        alerts = []
        for svc in sim_services:
            alerts.extend(self._check_service(svc))

        self.logger.info(f"[SIM] Audited {len(sim_services)} services")
        return sim_services, alerts

    def _check_service(self, svc: dict) -> list:
        """Apply detection rules to a service entry."""
        alerts = []
        path_lower = svc["path"].lower()
        name = svc["name"]

        # Rule 1: Service path in suspicious directories
        for suspicious_dir in SUSPICIOUS_DIRECTORIES:
            if suspicious_dir.lower() in path_lower:
                alert = Alert(
                    severity="HIGH",
                    category="Suspicious Startup Service",
                    title=f"Service running from suspicious path: {name}",
                    description=(
                        f"Service '{name}' has its binary in a suspicious directory "
                        f"often used for malware persistence."
                    ),
                    details={
                        "service_name": name,
                        "display_name": svc.get("display_name"),
                        "path": svc["path"],
                        "state": svc.get("state"),
                        "suspicious_dir_matched": suspicious_dir,
                        "mitre_technique": "T1543.003 - Create or Modify System Process: Windows Service",
                    }
                )
                alerts.append(alert)
                self.logger.warning(str(alert))
                break

        # Rule 2: Suspicious command patterns in service path
        for pattern in SUSPICIOUS_SERVICE_INDICATORS:
            if pattern in path_lower:
                alert = Alert(
                    severity="CRITICAL",
                    category="Suspicious Startup Service",
                    title=f"Encoded/script command in service path: {name}",
                    description=(
                        f"Service '{name}' path contains '{pattern}' — a common "
                        f"persistence technique used by malware."
                    ),
                    details={
                        "service_name": name,
                        "path": svc["path"],
                        "pattern_matched": pattern,
                        "mitre_technique": "T1059 - Command and Scripting Interpreter",
                    }
                )
                alerts.append(alert)
                self.logger.warning(str(alert))
                break

        return alerts


# ─────────────────────────────────────────────────────────────
# MODULE 4: UNAUTHORIZED PROCESS DETECTOR
# ─────────────────────────────────────────────────────────────
class UnauthorizedProcessDetector:
    """Detects unknown, high-risk, or unauthorized running processes."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def detect(self, processes: dict) -> list:
        """Returns list of Alert objects for unauthorized processes."""
        alerts = []
        self.logger.info("Scanning for unauthorized or high-risk processes...")

        for pid, proc in processes.items():
            name = proc.name
            exe_path = proc.exe_path.lower()

            # Rule 1: High-risk process names
            if name in [h.lower() for h in HIGH_RISK_PROCESSES]:
                alert = Alert(
                    severity="CRITICAL",
                    category="High-Risk Process",
                    title=f"High-risk process detected: {name}",
                    description=(
                        f"'{name}' is a known offensive security / hacking tool. "
                        f"Its presence strongly indicates compromise or unauthorized activity."
                    ),
                    details={
                        "process_name": name,
                        "pid": pid,
                        "exe_path": proc.exe_path,
                        "username": proc.username,
                        "mitre_technique": "T1003 - OS Credential Dumping",
                    }
                )
                alerts.append(alert)
                self.logger.warning(str(alert))

            # Rule 2: Process running from suspicious directories
            elif any(d.lower() in exe_path for d in SUSPICIOUS_DIRECTORIES if d):
                alert = Alert(
                    severity="HIGH",
                    category="Suspicious Process Location",
                    title=f"Process running from suspicious path: {name}",
                    description=(
                        f"'{name}' (PID {pid}) is executing from a user-writable "
                        f"or temporary directory — a common malware staging technique."
                    ),
                    details={
                        "process_name": name,
                        "pid": pid,
                        "exe_path": proc.exe_path,
                        "username": proc.username,
                        "mitre_technique": "T1036 - Masquerading",
                    }
                )
                alerts.append(alert)
                self.logger.warning(str(alert))

            # Rule 3: Not in whitelist and not a known system process
            elif (name not in [w.lower() for w in WHITELIST_PROCESSES]
                  and name.endswith(".exe")
                  and proc.ppid > 0):
                alert = Alert(
                    severity="LOW",
                    category="Unknown Process",
                    title=f"Unrecognized process: {name}",
                    description=(
                        f"'{name}' (PID {pid}) is not in the approved process whitelist. "
                        f"Manual review recommended."
                    ),
                    details={
                        "process_name": name,
                        "pid": pid,
                        "exe_path": proc.exe_path,
                        "username": proc.username,
                        "mitre_technique": "T1036.005 - Match Legitimate Name or Location",
                    }
                )
                alerts.append(alert)
                self.logger.info(str(alert))

        return alerts


# ─────────────────────────────────────────────────────────────
# MODULE 5: REPORT GENERATOR
# ─────────────────────────────────────────────────────────────
class ReportGenerator:
    """Generates structured detection reports."""

    def __init__(self, logger: logging.Logger, config: dict):
        self.logger = logger
        self.config = config

    def generate(self, all_alerts: list, processes: dict, services: list) -> dict:
        """Build and save the final detection report."""
        # Count by severity
        severity_counts = defaultdict(int)
        for a in all_alerts:
            severity_counts[a.severity] += 1

        # Count by category
        category_counts = defaultdict(int)
        for a in all_alerts:
            category_counts[a.category] += 1

        report = {
            "report_metadata": {
                "generated_at": datetime.datetime.now().isoformat(),
                "agent_version": "2.0",
                "platform": platform.system(),
                "hostname": platform.node(),
                "scan_mode": "LIVE" if IS_WINDOWS else "SIMULATION",
            },
            "executive_summary": {
                "total_processes_scanned": len(processes),
                "total_services_audited": len(services),
                "total_alerts": len(all_alerts),
                "alerts_by_severity": dict(severity_counts),
                "alerts_by_category": dict(category_counts),
                "risk_level": self._calculate_risk_level(severity_counts),
            },
            "alerts": [a.to_dict() for a in all_alerts],
            "processes_snapshot": [p.to_dict() for p in list(processes.values())[:50]],
            "services_snapshot": services[:30],
        }

        # Save JSON report
        report_path = self.config["report_file"]
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        self.logger.info(f"Report saved → {report_path}")
        return report

    def _calculate_risk_level(self, severity_counts: dict) -> str:
        if severity_counts.get("CRITICAL", 0) > 0:
            return "CRITICAL"
        elif severity_counts.get("HIGH", 0) > 0:
            return "HIGH"
        elif severity_counts.get("MEDIUM", 0) > 0:
            return "MEDIUM"
        elif severity_counts.get("LOW", 0) > 0:
            return "LOW"
        return "CLEAN"

    def print_summary(self, report: dict) -> None:
        """Print a human-readable summary to console."""
        summary = report["executive_summary"]
        meta = report["report_metadata"]
        alerts = report["alerts"]

        border = "═" * 70
        print(f"\n{border}")
        print("  DETECTION REPORT — Windows Service & Process Monitoring Agent")
        print(border)
        print(f"  Generated : {meta['generated_at']}")
        print(f"  Hostname  : {meta['hostname']}")
        print(f"  Mode      : {meta['scan_mode']}")
        print(f"  Risk Level: {summary['risk_level']}")
        print(border)
        print(f"  Processes Scanned : {summary['total_processes_scanned']}")
        print(f"  Services Audited  : {summary['total_services_audited']}")
        print(f"  Total Alerts      : {summary['total_alerts']}")
        print()

        sev = summary["alerts_by_severity"]
        print("  ALERTS BY SEVERITY:")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = sev.get(level, 0)
            bar = "█" * count
            print(f"    {level:10s} : {count:3d}  {bar}")
        print()
        print("  ALERTS BY CATEGORY:")
        for cat, count in summary["alerts_by_category"].items():
            print(f"    {cat:35s} : {count}")
        print(border)
        print("  DETAILED ALERTS:")
        print(border)

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_alerts = sorted(alerts, key=lambda a: sev_order.get(a["severity"], 5))

        for a in sorted_alerts:
            sev_color = {
                "CRITICAL": "\033[91m", "HIGH": "\033[93m",
                "MEDIUM": "\033[94m", "LOW": "\033[96m",
            }.get(a["severity"], "")
            reset = "\033[0m"
            print(f"\n  {sev_color}[{a['severity']}]{reset} {a['category']}")
            print(f"  Title      : {a['title']}")
            print(f"  Timestamp  : {a['timestamp']}")
            print(f"  Description: {a['description']}")
            if "mitre_technique" in a.get("details", {}):
                print(f"  MITRE ATT&CK: {a['details']['mitre_technique']}")

        print(f"\n{border}")
        print(f"  Full report saved to: {self.config['report_file']}")
        print(f"  Agent logs saved to:  {self.config['log_file']}")
        print(f"{border}\n")


# ─────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────
class MonitoringAgent:
    """Main orchestrator that runs all detection modules."""

    def __init__(self, config: dict = None):
        self.config = config or CONFIG
        self.logger = setup_logging(self.config)
        self.enumerator = ProcessEnumerator(self.logger)
        self.parent_child_analyzer = ParentChildAnalyzer(self.logger)
        self.service_auditor = StartupServiceAuditor(self.logger)
        self.unauthorized_detector = UnauthorizedProcessDetector(self.logger)
        self.report_generator = ReportGenerator(self.logger, self.config)

    def run_once(self) -> dict:
        """Execute a single full scan and return the report."""
        self.logger.info("=" * 60)
        self.logger.info("  MONITORING AGENT — SCAN STARTED")
        self.logger.info("=" * 60)
        start_time = time.time()

        # Step 1: Enumerate processes
        processes = self.enumerator.enumerate()

        # Step 2: Parent-child analysis
        pc_alerts = self.parent_child_analyzer.analyze(processes)

        # Step 3: Service audit
        services, svc_alerts = self.service_auditor.audit()

        # Step 4: Unauthorized process detection
        unauth_alerts = self.unauthorized_detector.detect(processes)

        # Step 5: Aggregate all alerts
        all_alerts = pc_alerts + svc_alerts + unauth_alerts

        # Step 6: Generate report
        report = self.report_generator.generate(all_alerts, processes, services)

        elapsed = time.time() - start_time
        self.logger.info(f"Scan completed in {elapsed:.2f}s — {len(all_alerts)} alerts generated")

        # Print summary
        self.report_generator.print_summary(report)
        return report

    def run_continuous(self, interval_seconds: int = None):
        """Run scans on a schedule."""
        interval = interval_seconds or self.config["scan_interval_seconds"]
        self.logger.info(f"Continuous monitoring started (interval: {interval}s). Press Ctrl+C to stop.")
        while True:
            try:
                self.run_once()
                self.logger.info(f"Next scan in {interval} seconds...")
                time.sleep(interval)
            except KeyboardInterrupt:
                self.logger.info("Monitoring stopped by user.")
                break


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Windows Service & Process Monitoring Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python monitoring_agent.py               # Single scan
  python monitoring_agent.py --continuous  # Continuous monitoring
  python monitoring_agent.py --interval 30 # Scan every 30 seconds
        """
    )
    parser.add_argument("--continuous", action="store_true",
                        help="Run in continuous monitoring mode")
    parser.add_argument("--interval", type=int, default=60,
                        help="Scan interval in seconds (default: 60)")
    parser.add_argument("--output", type=str, default="./reports",
                        help="Output directory for reports")

    args = parser.parse_args()

    CONFIG["output_dir"] = args.output
    CONFIG["log_file"] = os.path.join(args.output, "agent.log")
    CONFIG["report_file"] = os.path.join(args.output, "detection_report.json")
    CONFIG["scan_interval_seconds"] = args.interval

    agent = MonitoringAgent(CONFIG)

    if args.continuous:
        agent.run_continuous()
    else:
        agent.run_once()