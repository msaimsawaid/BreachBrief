"""
PHASE 3 — TIMELINE GENERATION
Classifies aggregated events into attack-chain stages and builds the
chain-of-custody narrative.
"""
from __future__ import annotations

STAGE_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Lateral Movement", "Exfiltration", "Other",
]

_STAGE_MAP = {
    "Nmap Scan": "Reconnaissance",
    "Vulnerability Exploit": "Initial Access",
    "SSH Brute Force": "Initial Access",
    "Web Brute Force": "Initial Access",
    "Authentication Failure": "Initial Access",
    "Successful Login": "Initial Access",
    "SQL Injection": "Execution",
    "XSS Attempt": "Execution",
    "Web Attack": "Execution",
    "Malware Detected": "Execution",
    "Persistence Mechanism": "Persistence",
    "Privilege Escalation": "Privilege Escalation",
    "Lateral Movement": "Lateral Movement",
    "Data Exfiltration": "Exfiltration",
    "Firewall Block": "Other",
    "System Error": "Other",
    "Unclassified Event": "Other",
    # Real-world Wazuh/OSSEC housekeeping/compliance families
    "File Integrity Change": "Persistence",
    "File Added": "Other",
    "File Removed": "Other",
    "Compliance Check Failed": "Other",
    "Compliance Scan Summary": "Other",
    "Agent Disconnected": "Other",
    "Agent Connected": "Other",
    "Rootcheck Finding": "Other",
    "Active Response Triggered": "Other",
    "Vulnerability Advisory": "Other",
    "Account Logon/Logoff": "Other",
    "Package Management Activity": "Other",
}


def classify_stage(event_type: str) -> str:
    return _STAGE_MAP.get(event_type, "Other")


def build_timeline(aggregated_events: list[dict]) -> list[dict]:
    timeline = []
    for g in aggregated_events:
        stage = classify_stage(g["event_type"])
        start = g["start_time"]
        end = g["end_time"]
        time_label = _fmt(start)
        if end and start and end != start:
            time_label = f"{_fmt(start)} \u2013 {_fmt(end)}"
        narrative = _narrative_line(g, stage)
        timeline.append({
            "time_label": time_label,
            "start_time": start,
            "stage": stage,
            "event_type": g["event_type"],
            "count": g["count"],
            "source_ip": g["source_ip"],
            "source_ips": g.get("source_ips", []),
            "destination_ips": g["destination_ips"],
            "severity": g["severity"],
            "embedded_mitre": g.get("embedded_mitre"),
            "narrative": narrative,
        })
    return timeline


def _fmt(dt) -> str:
    if not dt:
        return "unknown time"
    return dt.strftime("%H:%M:%S")


def _narrative_line(g: dict, stage: str) -> str:
    count = g["count"]
    times = "attempt" if count == 1 else "attempts"

    if not g.get("is_identity_driven", True):
        # Condition-driven (syscheck/SCA/rootcheck/etc.) — describe the
        # scope (how many hosts/IPs) rather than a single attacker identity.
        agents = g.get("agents_seen") or []
        scope = f"across {len(agents)} host(s)" if len(agents) > 1 else (
            f"on {agents[0]}" if agents else "on the monitored host")
        return (f"[{stage}] {g['event_type']} recurred {count} {times} {scope} "
                f"(severity: {g['severity']}).")

    ip = g["source_ip"] or "an unknown host"
    targets = ", ".join(g["destination_ips"][:3]) if g["destination_ips"] else "the target environment"
    return (f"[{stage}] {g['event_type']} from {ip} against {targets} "
            f"({count} {times}, severity: {g['severity']}).")


def timeline_summary_paragraph(timeline: list[dict]) -> str:
    if not timeline:
        return "No correlated activity was identified in the supplied logs."
    stages_seen = []
    for t in timeline:
        if t["stage"] not in stages_seen:
            stages_seen.append(t["stage"])
    first, last = timeline[0], timeline[-1]
    return (
        f"The observed activity spans {len(timeline)} correlated event group(s) beginning with "
        f"{first['event_type']} at {first['time_label']} and progressing through the following "
        f"stage(s): {', '.join(stages_seen)}. The final correlated activity was "
        f"{last['event_type']} at {last['time_label']}."
    )
