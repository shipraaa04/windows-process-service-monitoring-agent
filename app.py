import os
import sys
import json
import time
import platform
import datetime
import logging
from pathlib import Path
from collections import defaultdict

import streamlit as st
import pandas as pd
import numpy as np

# ──────────────────────────────────────────────────────────────
# PAGE CONFIG  (must be first Streamlit call)
# ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Process Monitoring Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────────────────────
# CONDITIONAL IMPORTS
# ──────────────────────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

# ──────────────────────────────────────────────────────────────
# THREAT INTELLIGENCE TABLES
# ──────────────────────────────────────────────────────────────
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

SUSPICIOUS_PARENT_CHILD = {
    "winword.exe":  ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
    "excel.exe":    ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"],
    "outlook.exe":  ["powershell.exe", "cmd.exe", "regsvr32.exe"],
    "acrobat.exe":  ["powershell.exe", "cmd.exe", "wscript.exe"],
    "acrord32.exe": ["powershell.exe", "cmd.exe", "wscript.exe"],
    "iexplore.exe": ["powershell.exe", "cmd.exe", "mshta.exe"],
    "chrome.exe":   ["powershell.exe", "cmd.exe"],
    "firefox.exe":  ["powershell.exe", "cmd.exe"],
    "svchost.exe":  ["powershell.exe", "cmd.exe", "wscript.exe"],
    "wscript.exe":  ["powershell.exe", "cmd.exe", "cscript.exe"],
    "mshta.exe":    ["powershell.exe", "cmd.exe", "wscript.exe"],
    "regsvr32.exe": ["powershell.exe", "cmd.exe"],
    "lsass.exe":    ["cmd.exe", "powershell.exe", "net.exe"],
    "csrss.exe":    ["cmd.exe", "powershell.exe"],
}

HIGH_RISK_PROCESSES = {
    "mimikatz.exe", "procdump.exe", "pwdump.exe", "gsecdump.exe",
    "fgdump.exe", "wce.exe", "nc.exe", "ncat.exe", "netcat.exe",
    "meterpreter.exe", "psexec.exe", "psexesvc.exe", "radmin.exe",
    "winvnc.exe", "ultravnc.exe", "teamviewer.exe", "anydesk.exe",
    "cobalt_strike.exe", "beacon.exe", "cobaltstrike.exe",
}

SUSPICIOUS_DIRECTORIES = [
    r"c:\windows\temp", r"c:\users\public", r"c:\programdata",
    r"c:\temp", r"%appdata%", r"%localappdata%\temp",
    r"c:\users\default", "/tmp", "/var/tmp", "/dev/shm",
]

SUSPICIOUS_SERVICE_INDICATORS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\", "\\public\\",
    "powershell -enc", "powershell -e ", "cmd /c", "wscript",
    "cscript", "mshta", "regsvr32", "rundll32",
    ".vbs", ".js", ".bat", ".ps1",
]

# ──────────────────────────────────────────────────────────────
# SIMULATION DATA
# ──────────────────────────────────────────────────────────────
SIM_PROCESSES = [
    (4,    "System",           0,    "",              "C:\\Windows\\System32\\",                                          "SYSTEM"),
    (512,  "smss.exe",         4,    "System",        "C:\\Windows\\System32\\smss.exe",                                  "SYSTEM"),
    (668,  "csrss.exe",        512,  "smss.exe",      "C:\\Windows\\System32\\csrss.exe",                                 "SYSTEM"),
    (784,  "wininit.exe",      512,  "smss.exe",      "C:\\Windows\\System32\\wininit.exe",                               "SYSTEM"),
    (832,  "winlogon.exe",     512,  "smss.exe",      "C:\\Windows\\System32\\winlogon.exe",                              "SYSTEM"),
    (928,  "services.exe",     784,  "wininit.exe",   "C:\\Windows\\System32\\services.exe",                              "SYSTEM"),
    (960,  "lsass.exe",        784,  "wininit.exe",   "C:\\Windows\\System32\\lsass.exe",                                 "SYSTEM"),
    (1200, "svchost.exe",      928,  "services.exe",  "C:\\Windows\\System32\\svchost.exe",                               "SYSTEM"),
    (1400, "svchost.exe",      928,  "services.exe",  "C:\\Windows\\System32\\svchost.exe",                               "NETWORK SERVICE"),
    (2000, "explorer.exe",     832,  "winlogon.exe",  "C:\\Windows\\explorer.exe",                                        "DESKTOP-USER"),
    (3200, "chrome.exe",       2000, "explorer.exe",  "C:\\Program Files\\Google\\Chrome\\chrome.exe",                    "DESKTOP-USER"),
    (4100, "notepad.exe",      2000, "explorer.exe",  "C:\\Windows\\notepad.exe",                                         "DESKTOP-USER"),
    (5500, "winword.exe",      2000, "explorer.exe",  "C:\\Program Files\\Microsoft Office\\winword.exe",                 "DESKTOP-USER"),
    (5501, "powershell.exe",   5500, "winword.exe",   "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",   "DESKTOP-USER"),
    (5600, "mshta.exe",        2000, "explorer.exe",  "C:\\Windows\\System32\\mshta.exe",                                 "DESKTOP-USER"),
    (5601, "cmd.exe",          5600, "mshta.exe",     "C:\\Windows\\System32\\cmd.exe",                                   "DESKTOP-USER"),
    (6000, "svchosts.exe",     928,  "services.exe",  "C:\\Windows\\Temp\\svchosts.exe",                                  "SYSTEM"),
    (7000, "nc.exe",           5501, "powershell.exe","C:\\Users\\Public\\Downloads\\nc.exe",                             "DESKTOP-USER"),
    (8000, "backdoor_svc.exe", 928,  "services.exe",  "C:\\ProgramData\\backdoor_svc.exe",                                "SYSTEM"),
]

SIM_SERVICES = [
    {"name": "LanmanServer",      "display_name": "Server",                   "state": "Running", "start_mode": "Auto",   "path": "C:\\Windows\\System32\\svchost.exe -k netsvcs"},
    {"name": "Spooler",           "display_name": "Print Spooler",            "state": "Running", "start_mode": "Auto",   "path": "C:\\Windows\\System32\\spoolsv.exe"},
    {"name": "MSDTC",             "display_name": "Distributed Transaction",  "state": "Stopped", "start_mode": "Manual", "path": "C:\\Windows\\System32\\msdtc.exe"},
    {"name": "WindowsHelperSvc",  "display_name": "Windows Helper Service",   "state": "Running", "start_mode": "Auto",   "path": "C:\\Windows\\Temp\\svchelper.exe"},
    {"name": "SysMonSvc",         "display_name": "System Monitor",           "state": "Running", "start_mode": "Auto",   "path": "C:\\ProgramData\\sysmon\\sysmon.exe -enc SGVsbG8="},
    {"name": "UpdaterTaskSvc",    "display_name": "Updater Task",             "state": "Running", "start_mode": "Auto",   "path": "cmd /c powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBS"},
    {"name": "UnknownServiceXYZ", "display_name": "Unknown Service XYZ",      "state": "Running", "start_mode": "Auto",   "path": "C:\\Users\\Public\\unknown_xyz.exe"},
    {"name": "WinDefend",         "display_name": "Windows Defender",         "state": "Running", "start_mode": "Auto",   "path": "C:\\Program Files\\Windows Defender\\MsMpEng.exe"},
]

# ──────────────────────────────────────────────────────────────
# DETECTION ENGINE
# ──────────────────────────────────────────────────────────────
def run_detection(use_simulation=True):
    alerts = []
    processes = []
    services = []

    # ── Build process list ──────────────────────────────────
    if use_simulation or not PSUTIL_OK:
        for pid, name, ppid, pname, exe, user in SIM_PROCESSES:
            processes.append({
                "pid": pid, "name": name.lower(), "ppid": ppid,
                "parent_name": pname.lower(), "exe_path": exe,
                "cmdline": f'"{exe}"', "username": user,
            })
    else:
        pid_to_name = {}
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid_to_name[proc.info["pid"]] = proc.info["name"] or ""
            except Exception:
                pass
        for proc in psutil.process_iter(["pid", "name", "ppid", "exe", "username"]):
            try:
                info = proc.info
                pid = info["pid"]
                ppid = info.get("ppid") or 0
                try:
                    cmdline = " ".join(proc.cmdline())
                except Exception:
                    cmdline = ""
                processes.append({
                    "pid": pid,
                    "name": (info.get("name") or "").lower(),
                    "ppid": ppid,
                    "parent_name": pid_to_name.get(ppid, "unknown").lower(),
                    "exe_path": info.get("exe") or "",
                    "cmdline": cmdline,
                    "username": info.get("username") or "",
                })
            except Exception:
                continue

    # ── Build service list ──────────────────────────────────
    if use_simulation or not IS_WINDOWS:
        services = SIM_SERVICES
    else:
        try:
            import wmi
            c = wmi.WMI()
            for svc in c.Win32_Service():
                services.append({
                    "name": svc.Name,
                    "display_name": svc.DisplayName,
                    "state": svc.State,
                    "start_mode": svc.StartMode,
                    "path": svc.PathName or "",
                })
        except Exception:
            services = SIM_SERVICES

    # ── MODULE 2: Parent-Child Analysis ────────────────────
    for proc in processes:
        parent = proc["parent_name"]
        child  = proc["name"]
        if parent in SUSPICIOUS_PARENT_CHILD:
            if child in [f.lower() for f in SUSPICIOUS_PARENT_CHILD[parent]]:
                alerts.append({
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "HIGH",
                    "category": "Parent-Child Anomaly",
                    "title": f"{parent} → {child}",
                    "description": f"'{parent}' spawned '{child}' — known malware execution pattern (Office macro abuse / LOTL).",
                    "pid": proc["pid"], "ppid": proc["ppid"],
                    "exe_path": proc["exe_path"],
                    "mitre": "T1059",
                })

    # ── MODULE 3: Service Audit ─────────────────────────────
    for svc in services:
        path_lower = svc["path"].lower()
        name = svc["name"]
        for d in SUSPICIOUS_DIRECTORIES:
            if d in path_lower:
                alerts.append({
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "HIGH",
                    "category": "Suspicious Startup Service",
                    "title": f"Service in suspicious path: {name}",
                    "description": f"Service '{name}' binary located in a directory commonly used for malware persistence.",
                    "pid": None, "ppid": None,
                    "exe_path": svc["path"],
                    "mitre": "T1543.003",
                })
                break
        for pattern in SUSPICIOUS_SERVICE_INDICATORS:
            if pattern in path_lower:
                alerts.append({
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "CRITICAL",
                    "category": "Suspicious Startup Service",
                    "title": f"Encoded/script command in service: {name}",
                    "description": f"Service '{name}' path contains '{pattern}' — a persistence technique used by malware.",
                    "pid": None, "ppid": None,
                    "exe_path": svc["path"],
                    "mitre": "T1059",
                })
                break

    # ── MODULE 4: Unauthorized Process Detection ────────────
    for proc in processes:
        name = proc["name"]
        exe  = proc["exe_path"].lower()
        if name in {h.lower() for h in HIGH_RISK_PROCESSES}:
            alerts.append({
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity": "CRITICAL",
                "category": "High-Risk Process",
                "title": f"Known offensive tool: {name}",
                "description": f"'{name}' is a known hacking/offensive tool. Indicates active compromise.",
                "pid": proc["pid"], "ppid": proc["ppid"],
                "exe_path": proc["exe_path"],
                "mitre": "T1003",
            })
        elif any(d in exe for d in SUSPICIOUS_DIRECTORIES if d):
            alerts.append({
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity": "HIGH",
                "category": "Suspicious Process Location",
                "title": f"Process from suspicious path: {name}",
                "description": f"'{name}' (PID {proc['pid']}) running from a user-writable/temp directory.",
                "pid": proc["pid"], "ppid": proc["ppid"],
                "exe_path": proc["exe_path"],
                "mitre": "T1036",
            })
        elif (name not in {w.lower() for w in WHITELIST_PROCESSES}
              and name.endswith(".exe") and proc["ppid"] > 0):
            alerts.append({
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity": "LOW",
                "category": "Unknown Process",
                "title": f"Unrecognized process: {name}",
                "description": f"'{name}' (PID {proc['pid']}) not in approved whitelist. Manual review recommended.",
                "pid": proc["pid"], "ppid": proc["ppid"],
                "exe_path": proc["exe_path"],
                "mitre": "T1036.005",
            })

    return alerts, processes, services


# ──────────────────────────────────────────────────────────────
# CSS STYLING
# ──────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Global ── */
[data-testid="stAppViewContainer"] { background: #0d1117; }
[data-testid="stSidebar"]          { background: #161b22; border-right: 1px solid #30363d; }
[data-testid="stSidebar"] *        { color: #e6edf3 !important; }
h1,h2,h3,h4                        { color: #e6edf3 !important; }
p, label, .stMarkdown              { color: #c9d1d9 !important; }

/* ── Metric cards ── */
[data-testid="metric-container"] {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 16px !important;
}
[data-testid="metric-container"] label { color: #8b949e !important; font-size: 13px !important; }
[data-testid="metric-container"] [data-testid="stMetricValue"] { font-size: 2rem !important; font-weight: 700 !important; }

/* ── Alert severity badges ── */
.badge-CRITICAL { background:#da3633; color:#fff; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:700; }
.badge-HIGH     { background:#d29922; color:#0d1117; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:700; }
.badge-MEDIUM   { background:#388bfd; color:#fff; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:700; }
.badge-LOW      { background:#3fb950; color:#0d1117; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:700; }
.badge-INFO     { background:#8b949e; color:#fff; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:700; }

/* ── Alert cards ── */
.alert-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 10px;
}
.alert-card.CRITICAL { border-left: 4px solid #da3633; }
.alert-card.HIGH     { border-left: 4px solid #d29922; }
.alert-card.MEDIUM   { border-left: 4px solid #388bfd; }
.alert-card.LOW      { border-left: 4px solid #3fb950; }

/* ── Risk banner ── */
.risk-CRITICAL { background:#4a1919; border:1px solid #da3633; border-radius:10px; padding:16px 24px; color:#ff7b72 !important; font-size:1.3rem; font-weight:700; text-align:center; }
.risk-HIGH     { background:#3d2b0a; border:1px solid #d29922; border-radius:10px; padding:16px 24px; color:#f0883e !important; font-size:1.3rem; font-weight:700; text-align:center; }
.risk-CLEAN    { background:#0e2b1a; border:1px solid #3fb950; border-radius:10px; padding:16px 24px; color:#3fb950 !important; font-size:1.3rem; font-weight:700; text-align:center; }

/* ── Section headers ── */
.section-header {
    border-bottom: 2px solid #21262d;
    padding-bottom: 8px;
    margin: 24px 0 16px 0;
    color: #58a6ff !important;
    font-size: 1.1rem;
    font-weight: 700;
    letter-spacing: .5px;
}

/* ── Dataframe ── */
[data-testid="stDataFrame"] { border-radius: 8px; overflow: hidden; }

/* ── Buttons ── */
.stButton > button {
    background: #238636; color: #fff; border: none;
    border-radius: 8px; font-weight: 600;
    padding: 10px 24px; width: 100%;
}
.stButton > button:hover { background: #2ea043; }

/* ── Code block ── */
code { background: #161b22 !important; color: #79c0ff !important; padding: 2px 6px; border-radius: 4px; }
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────
# SIDEBAR
# ──────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ Monitoring Agent")
    st.markdown("---")

    mode = st.radio(
        "Scan Mode",
        ["Simulation Mode", "Live Mode (Windows only)"],
        index=0,
        help="Simulation uses built-in realistic threat scenarios. Live mode requires Windows + psutil.",
    )
    use_sim = (mode == "Simulation Mode")

    st.markdown("---")
    st.markdown("### Filters")
    sev_filter = st.multiselect(
        "Show Severities",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    )
    cat_filter = st.multiselect(
        "Show Categories",
        ["Parent-Child Anomaly", "Suspicious Startup Service",
         "High-Risk Process", "Suspicious Process Location", "Unknown Process"],
        default=["Parent-Child Anomaly", "Suspicious Startup Service",
                 "High-Risk Process", "Suspicious Process Location", "Unknown Process"],
    )

    st.markdown("---")
    run_scan = st.button("▶  Run Scan")

    st.markdown("---")
    st.markdown("**Platform:** " + platform.system())
    st.markdown("**Python:** " + platform.python_version())
    st.markdown("**psutil:** " + ("✅ Available" if PSUTIL_OK else "❌ Not installed"))
    st.markdown("**Version:** v2.0")


# ──────────────────────────────────────────────────────────────
# SESSION STATE — run scan once on load or on button press
# ──────────────────────────────────────────────────────────────
if "scan_results" not in st.session_state or run_scan:
    with st.spinner("🔍 Running detection pipeline…"):
        alerts, processes, services = run_detection(use_simulation=use_sim)
        st.session_state["scan_results"] = (alerts, processes, services)
        st.session_state["scan_time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state["scan_mode"] = "SIMULATION" if use_sim else "LIVE"

alerts, processes, services = st.session_state["scan_results"]
scan_time = st.session_state["scan_time"]
scan_mode = st.session_state["scan_mode"]

# ── Apply filters ──────────────────────────────────────────
filtered = [a for a in alerts if a["severity"] in sev_filter and a["category"] in cat_filter]

# ── Severity counts ─────────────────────────────────────────
sev_counts = defaultdict(int)
for a in alerts:
    sev_counts[a["severity"]] += 1

risk_level = "CLEAN"
for lvl in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    if sev_counts[lvl] > 0:
        risk_level = lvl
        break


# ──────────────────────────────────────────────────────────────
# MAIN CONTENT
# ──────────────────────────────────────────────────────────────
st.markdown("# 🛡️ Windows Service & Process Monitoring Agent")
st.markdown(
    f"**Scan completed:** `{scan_time}`  &nbsp;|&nbsp;  "
    f"**Mode:** `{scan_mode}`  &nbsp;|&nbsp;  "
    f"**Platform:** `{platform.system()}`"
)
st.markdown("---")

# ── RISK BANNER ────────────────────────────────────────────
risk_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "CLEAN": "✅"}
st.markdown(
    f'<div class="risk-{risk_level if risk_level in ["CRITICAL","HIGH"] else "CLEAN"}">'
    f'{risk_icons.get(risk_level, "⚪")} Overall Risk Level: {risk_level}'
    f'</div>',
    unsafe_allow_html=True,
)
st.markdown("")

# ── KPI METRICS ────────────────────────────────────────────
c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("🔍 Processes", len(processes))
c2.metric("⚙️ Services",  len(services))
c3.metric("🚨 Total Alerts", len(alerts))
c4.metric("🔴 Critical", sev_counts["CRITICAL"])
c5.metric("🟠 High",     sev_counts["HIGH"])
c6.metric("🟡 Med/Low",  sev_counts["MEDIUM"] + sev_counts["LOW"])

st.markdown("---")

# ──────────────────────────────────────────────────────────────
# TABS
# ──────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🚨 Alerts", "📊 Analytics", "⚙️ Processes", "🔧 Services", "📄 JSON Report"
])


# ════════════════════════════════════════════════════════════
# TAB 1 — ALERTS
# ════════════════════════════════════════════════════════════
with tab1:
    st.markdown(f'<div class="section-header">🚨 Detection Alerts ({len(filtered)} shown / {len(alerts)} total)</div>', unsafe_allow_html=True)

    if not filtered:
        st.success("✅ No alerts match the current filter settings.")
    else:
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_alerts = sorted(filtered, key=lambda a: sev_order.get(a["severity"], 9))

        for a in sorted_alerts:
            sev = a["severity"]
            st.markdown(
                f'<div class="alert-card {sev}">'
                f'<span class="badge-{sev}">{sev}</span>'
                f'&nbsp;&nbsp;<strong style="color:#e6edf3">{a["title"]}</strong>'
                f'<br><span style="color:#8b949e;font-size:13px">🏷 {a["category"]}&nbsp;&nbsp;|&nbsp;&nbsp;'
                f'🕐 {a["timestamp"]}&nbsp;&nbsp;|&nbsp;&nbsp;'
                f'📋 MITRE: <code>{a["mitre"]}</code></span>'
                f'<br><span style="color:#c9d1d9;font-size:14px;margin-top:6px;display:block">{a["description"]}</span>'
                + (f'<span style="color:#6e7681;font-size:12px">📁 {a["exe_path"]}</span>' if a["exe_path"] else "")
                + '</div>',
                unsafe_allow_html=True,
            )


# ════════════════════════════════════════════════════════════
# TAB 2 — ANALYTICS
# ════════════════════════════════════════════════════════════
with tab2:
    st.markdown('<div class="section-header">📊 Detection Analytics</div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("##### Alerts by Severity")
        sev_df = pd.DataFrame([
            {"Severity": k, "Count": v}
            for k, v in [("CRITICAL", sev_counts["CRITICAL"]),
                         ("HIGH",     sev_counts["HIGH"]),
                         ("MEDIUM",   sev_counts["MEDIUM"]),
                         ("LOW",      sev_counts["LOW"])]
            if v > 0
        ])
        if not sev_df.empty:
            st.bar_chart(sev_df.set_index("Severity"), color="#da3633", height=260)

    with col2:
        st.markdown("##### Alerts by Category")
        cat_counts = defaultdict(int)
        for a in alerts:
            cat_counts[a["category"]] += 1
        cat_df = pd.DataFrame([
            {"Category": k.replace(" ", "\n"), "Count": v}
            for k, v in cat_counts.items()
        ])
        if not cat_df.empty:
            st.bar_chart(cat_df.set_index("Category"), color="#388bfd", height=260)

    st.markdown("---")
    st.markdown("##### MITRE ATT&CK Technique Coverage")
    mitre_counts = defaultdict(int)
    for a in alerts:
        mitre_counts[a["mitre"]] += 1
    mitre_df = pd.DataFrame([
        {"Technique": k, "Alerts": v, "Description": {
            "T1059":    "Command & Scripting Interpreter",
            "T1543.003":"Windows Service Persistence",
            "T1036":    "Masquerading",
            "T1036.005":"Match Legitimate Name/Location",
            "T1003":    "OS Credential Dumping",
        }.get(k, "")}
        for k, v in sorted(mitre_counts.items(), key=lambda x: -x[1])
    ])
    if not mitre_df.empty:
        st.dataframe(mitre_df, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown("##### Detection Rules Reference")
    rules = [
        ("R-001","Parent-Child","Office apps spawning PowerShell/cmd","HIGH","T1059"),
        ("R-002","Parent-Child","mshta/wscript spawning shell","HIGH","T1059"),
        ("R-003","Parent-Child","lsass/csrss spawning any shell","HIGH","T1059"),
        ("R-004","Parent-Child","svchost spawning scripting interpreters","HIGH","T1059"),
        ("R-005","Parent-Child","Browsers spawning cmd/PowerShell","HIGH","T1059"),
        ("R-006","Service Audit","Service binary in Temp/Public/ProgramData","HIGH","T1543.003"),
        ("R-007","Service Audit","Service path contains -enc or cmd /c","CRITICAL","T1059"),
        ("R-008","Service Audit","Service path contains .vbs/.bat/.ps1","CRITICAL","T1059"),
        ("R-009","Process Detect","Known offensive tool name detected","CRITICAL","T1003"),
        ("R-010","Process Detect","Process from user-writable path","HIGH","T1036"),
        ("R-011","Process Detect","Unknown .exe not in whitelist","LOW","T1036.005"),
    ]
    rules_df = pd.DataFrame(rules, columns=["Rule ID","Type","Description","Severity","MITRE"])
    st.dataframe(rules_df, use_container_width=True, hide_index=True)


# ════════════════════════════════════════════════════════════
# TAB 3 — PROCESSES
# ════════════════════════════════════════════════════════════
with tab3:
    st.markdown(f'<div class="section-header">⚙️ Running Processes ({len(processes)})</div>', unsafe_allow_html=True)

    search = st.text_input("🔎 Filter by process name or path", placeholder="e.g. powershell, temp, nc.exe")

    proc_df = pd.DataFrame(processes)[["pid","name","ppid","parent_name","exe_path","username"]]
    proc_df.columns = ["PID","Name","PPID","Parent","Exe Path","User"]

    if search:
        mask = (proc_df["Name"].str.contains(search, case=False, na=False) |
                proc_df["Exe Path"].str.contains(search, case=False, na=False))
        proc_df = proc_df[mask]

    # Highlight flagged processes
    flagged_names = {a["name"].lower() if "name" in a else "" for a in alerts}
    flagged_pids  = {a["pid"] for a in alerts if a.get("pid")}

    def highlight_row(row):
        if row["PID"] in flagged_pids or row["Name"] in flagged_names:
            return ["background-color: #3d1a1a"] * len(row)
        return [""] * len(row)

    st.dataframe(proc_df.style.apply(highlight_row, axis=1),
                 use_container_width=True, hide_index=True, height=400)
    st.caption("🔴 Red rows indicate processes involved in one or more alerts.")


# ════════════════════════════════════════════════════════════
# TAB 4 — SERVICES
# ════════════════════════════════════════════════════════════
with tab4:
    st.markdown(f'<div class="section-header">🔧 Startup Services ({len(services)})</div>', unsafe_allow_html=True)

    flagged_svc_names = set()
    for a in alerts:
        if a["category"] == "Suspicious Startup Service":
            for svc in services:
                if svc["name"].lower() in a["title"].lower():
                    flagged_svc_names.add(svc["name"])

    svc_df = pd.DataFrame(services)[["name","display_name","state","start_mode","path"]]
    svc_df.columns = ["Service Name","Display Name","State","Start Mode","Binary Path"]

    def highlight_svc(row):
        if row["Service Name"] in flagged_svc_names:
            return ["background-color: #3d1a1a"] * len(row)
        if row["State"] == "Running":
            return [""] * len(row)
        return ["color: #6e7681"] * len(row)

    st.dataframe(svc_df.style.apply(highlight_svc, axis=1),
                 use_container_width=True, hide_index=True)
    st.caption("🔴 Red rows indicate services that triggered one or more alerts.")


# ════════════════════════════════════════════════════════════
# TAB 5 — JSON REPORT
# ════════════════════════════════════════════════════════════
with tab5:
    st.markdown('<div class="section-header">📄 Detection Report (JSON)</div>', unsafe_allow_html=True)

    report = {
        "report_metadata": {
            "generated_at": scan_time,
            "agent_version": "2.0",
            "platform": platform.system(),
            "hostname": platform.node(),
            "scan_mode": scan_mode,
        },
        "executive_summary": {
            "total_processes_scanned": len(processes),
            "total_services_audited": len(services),
            "total_alerts": len(alerts),
            "alerts_by_severity": dict(sev_counts),
            "alerts_by_category": {
                k: v for k, v in
                sorted(defaultdict(int, {a["category"]: 0 for a in alerts}).items())
            },
            "risk_level": risk_level,
        },
        "alerts": alerts,
        "processes_snapshot": processes[:50],
        "services_snapshot": services,
    }

    # Recount categories properly
    cat_c = defaultdict(int)
    for a in alerts:
        cat_c[a["category"]] += 1
    report["executive_summary"]["alerts_by_category"] = dict(cat_c)

    json_str = json.dumps(report, indent=2, default=str)

    col_a, col_b = st.columns([3, 1])
    with col_b:
        st.download_button(
            label="⬇️  Download Report",
            data=json_str,
            file_name=f"detection_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
        )

    st.code(json_str[:4000] + ("\n\n... (truncated — download for full report)" if len(json_str) > 4000 else ""),
            language="json")