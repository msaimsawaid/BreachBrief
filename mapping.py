"""
PHASE 4 — FRAMEWORK MAPPING ENGINE
Maps normalized event_types to MITRE ATT&CK, CWE, OWASP Top 10, NIST CSF,
and CIS Controls. CVE mapping is pulled straight from extracted CVE ids
found during parsing (see parsers.py).
"""
from __future__ import annotations
import logging
from .gemma_client import get_client, enrich_mapping as _gemma_enrich

log = logging.getLogger(__name__)

# event_type -> mapping record
_FRAMEWORK_MAP = {
    "Nmap Scan": {
        "MITRE": "T1046 - Network Service Discovery",
        "CWE": "CWE-200 - Exposure of Sensitive Information",
        "OWASP": None,
        "NIST": "DE.CM - Security Continuous Monitoring",
        "CIS": "Control 12 - Network Infrastructure Management",
    },
    "SSH Brute Force": {
        "MITRE": "T1110 - Brute Force",
        "CWE": "CWE-307 - Improper Restriction of Excessive Authentication Attempts",
        "OWASP": None,
        "NIST": "DE.CM / PR.AC - Access Control",
        "CIS": "Control 16 - Account Monitoring and Control",
    },
    "Web Brute Force": {
        "MITRE": "T1110 - Brute Force",
        "CWE": "CWE-307 - Improper Restriction of Excessive Authentication Attempts",
        "OWASP": "A07:2021 - Identification and Authentication Failures",
        "NIST": "DE.CM / PR.AC - Access Control",
        "CIS": "Control 16 - Account Monitoring and Control",
    },
    "SQL Injection": {
        "MITRE": "T1190 - Exploit Public-Facing Application",
        "CWE": "CWE-89 - SQL Injection",
        "OWASP": "A03:2021 - Injection",
        "NIST": "PR.DS - Data Security",
        "CIS": "Control 16 - Application Software Security",
    },
    "XSS Attempt": {
        "MITRE": "T1190 - Exploit Public-Facing Application",
        "CWE": "CWE-79 - Cross-Site Scripting",
        "OWASP": "A03:2021 - Injection",
        "NIST": "PR.DS - Data Security",
        "CIS": "Control 16 - Application Software Security",
    },
    "Web Attack": {
        "MITRE": "T1190 - Exploit Public-Facing Application",
        "CWE": "CWE-22 - Path Traversal",
        "OWASP": "A01:2021 - Broken Access Control",
        "NIST": "PR.PT - Protective Technology",
        "CIS": "Control 16 - Application Software Security",
    },
    "Malware Detected": {
        "MITRE": "T1204 - User Execution",
        "CWE": "CWE-506 - Embedded Malicious Code",
        "OWASP": None,
        "NIST": "DE.CM - Malicious Code Detection",
        "CIS": "Control 10 - Malware Defenses",
    },
    "Privilege Escalation": {
        "MITRE": "T1068 - Exploitation for Privilege Escalation",
        "CWE": "CWE-269 - Improper Privilege Management",
        "OWASP": None,
        "NIST": "PR.AC - Identity Management",
        "CIS": "Control 5 - Account Management",
    },
    "Persistence Mechanism": {
        "MITRE": "T1053 / T1547 - Scheduled Task / Boot or Logon Autostart",
        "CWE": "CWE-732 - Incorrect Permission Assignment",
        "OWASP": None,
        "NIST": "DE.CM - Continuous Monitoring",
        "CIS": "Control 4 - Secure Configuration",
    },
    "Lateral Movement": {
        "MITRE": "T1021 - Remote Services",
        "CWE": "CWE-284 - Improper Access Control",
        "OWASP": None,
        "NIST": "PR.AC - Network Segmentation",
        "CIS": "Control 12 - Network Infrastructure Management",
    },
    "Data Exfiltration": {
        "MITRE": "T1041 - Exfiltration Over C2 Channel",
        "CWE": "CWE-200 - Exposure of Sensitive Information",
        "OWASP": None,
        "NIST": "PR.DS / DE.AE - Data Security / Anomalies & Events",
        "CIS": "Control 3 - Data Protection",
    },
    "Firewall Block": {
        "MITRE": "T1590 - Gather Victim Network Information",
        "CWE": None,
        "OWASP": None,
        "NIST": "PR.PT - Protective Technology",
        "CIS": "Control 12 - Network Infrastructure Management",
    },
    "Authentication Failure": {
        "MITRE": "T1110 - Brute Force",
        "CWE": "CWE-287 - Improper Authentication",
        "OWASP": "A07:2021 - Identification and Authentication Failures",
        "NIST": "PR.AC - Access Control",
        "CIS": "Control 16 - Account Monitoring and Control",
    },
    "Successful Login": {
        "MITRE": "T1078 - Valid Accounts",
        "CWE": None,
        "OWASP": None,
        "NIST": "PR.AC - Access Control",
        "CIS": "Control 6 - Access Control Management",
    },
    "Vulnerability Exploit": {
        "MITRE": "T1203 - Exploitation for Client Execution",
        "CWE": "CWE-1035 - Use of Vulnerable Third-Party Component",
        "OWASP": "A06:2021 - Vulnerable and Outdated Components",
        "NIST": "ID.RA - Risk Assessment",
        "CIS": "Control 7 - Continuous Vulnerability Management",
    },
    "System Error": {
        "MITRE": None, "CWE": None, "OWASP": None,
        "NIST": "DE.AE - Anomalies and Events", "CIS": "Control 8 - Audit Log Management",
    },
    "Unclassified Event": {
        "MITRE": None, "CWE": None, "OWASP": None,
        "NIST": "DE.AE - Anomalies and Events", "CIS": "Control 8 - Audit Log Management",
    },
    # --- Real-world Wazuh/OSSEC housekeeping/compliance families ---
    "File Integrity Change": {
        "MITRE": "T1565 - Data Manipulation",
        "CWE": "CWE-668 - Exposure of Resource to Wrong Sphere",
        "OWASP": None,
        "NIST": "DE.CM - Continuous Monitoring (File Integrity)",
        "CIS": "Control 3 - Data Protection",
    },
    "File Added": {
        "MITRE": "T1105 - Ingress Tool Transfer",
        "CWE": None,
        "OWASP": None,
        "NIST": "DE.CM - Continuous Monitoring (File Integrity)",
        "CIS": "Control 3 - Data Protection",
    },
    "File Removed": {
        "MITRE": "T1070 - Indicator Removal",
        "CWE": None,
        "OWASP": None,
        "NIST": "DE.CM - Continuous Monitoring (File Integrity)",
        "CIS": "Control 3 - Data Protection",
    },
    "Compliance Check Failed": {
        "MITRE": None,
        "CWE": "CWE-16 - Configuration",
        "OWASP": None,
        "NIST": "ID.GV / PR.IP - Governance & Configuration Management",
        "CIS": "Control 4 - Secure Configuration",
    },
    "Compliance Scan Summary": {
        "MITRE": None, "CWE": None, "OWASP": None,
        "NIST": "ID.GV - Governance", "CIS": "Control 4 - Secure Configuration",
    },
    "Agent Disconnected": {
        "MITRE": "T1562 - Impair Defenses",
        "CWE": None,
        "OWASP": None,
        "NIST": "DE.CM - Continuous Monitoring",
        "CIS": "Control 8 - Audit Log Management",
    },
    "Agent Connected": {
        "MITRE": None, "CWE": None, "OWASP": None,
        "NIST": "DE.CM - Continuous Monitoring", "CIS": "Control 8 - Audit Log Management",
    },
    "Rootcheck Finding": {
        "MITRE": None,
        "CWE": "CWE-693 - Protection Mechanism Failure",
        "OWASP": None,
        "NIST": "DE.CM - Continuous Monitoring",
        "CIS": "Control 7 - Continuous Vulnerability Management",
    },
    "Active Response Triggered": {
        "MITRE": None, "CWE": None, "OWASP": None,
        "NIST": "RS.MI - Response Mitigation", "CIS": "Control 6 - Access Control Management",
    },
    "Vulnerability Advisory": {
        "MITRE": None,
        "CWE": "CWE-1035 - Use of Vulnerable Third-Party Component",
        "OWASP": "A06:2021 - Vulnerable and Outdated Components",
        "NIST": "ID.RA - Risk Assessment",
        "CIS": "Control 7 - Continuous Vulnerability Management",
    },
    "Account Logon/Logoff": {
        "MITRE": "T1078 - Valid Accounts", "CWE": None, "OWASP": None,
        "NIST": "PR.AC - Access Control", "CIS": "Control 6 - Access Control Management",
    },
    "Package Management Activity": {
        "MITRE": None, "CWE": None, "OWASP": None,
        "NIST": "PR.IP - Configuration Management", "CIS": "Control 2 - Software Asset Management",
    },
}

_DEFAULT_MAPPING = {"MITRE": None, "CWE": None, "OWASP": None, "NIST": None, "CIS": None}


def map_event(event_type: str, cves: list[str] | None = None, embedded_mitre: str | None = None) -> dict:
    m = dict(_FRAMEWORK_MAP.get(event_type, _DEFAULT_MAPPING))
    # An alert's own vendor-supplied MITRE mapping is more accurate than our
    # static keyword-based guess — prefer it when the source data has it,
    # and record WHY the mapping was chosen and how much to trust it. A
    # technique assigned only because the event category name resembles it
    # (no supporting evidence) should never be presented with the same
    # confidence as one the source data itself asserted.
    if embedded_mitre:
        m["MITRE"] = embedded_mitre
        m["mitre_source"] = "vendor-embedded"
        # High but deliberately not maximal — Wazuh's own rule-to-MITRE
        # associations are sometimes broad/generic themselves (e.g. a bare
        # auth-failure rule mapped to a tactic-level technique like Account
        # Access Removal rather than anything auth-failure-specific). Trust
        # it more than our keyword guess, but still surface it as "vendor
        # asserted", not "verified" — the analyst should still sanity-check
        # a mapping that looks like a stretch for the observed behavior.
        m["mitre_confidence"] = 88
    elif m.get("MITRE"):
        m["mitre_source"] = "static-mapping"
        m["mitre_confidence"] = 60
    else:
        m["mitre_source"] = None
        m["mitre_confidence"] = None
    m["CVE"] = cves or []

    # ── Gemma mapping enrichment ───────────────────────────────────────
    # Call Gemma when: (a) no vendor-embedded MITRE, AND (b) either the
    # event has no static MITRE mapping OR it's "Unclassified Event".
    # Gemma gives a more specific technique ID (e.g. T1110.001 instead of
    # the generic T1110) and fills in CWE gaps. Results are process-cached
    # per event_type so each unique type is called only once.
    should_enrich = (
        not embedded_mitre
        and (m.get("mitre_source") == "static-mapping" or not m.get("MITRE"))
    )
    if should_enrich:
        client = get_client()
        if client:
            m = _gemma_enrich(client, event_type, m)

    return m


def annotate_timeline(timeline: list[dict]) -> list[dict]:
    """Attach framework mapping onto each timeline entry, in place, and return it."""
    for entry in timeline:
        entry["mapping"] = map_event(entry["event_type"], embedded_mitre=entry.get("embedded_mitre"))
    return timeline


def annotate_aggregated(aggregated_events: list[dict]) -> list[dict]:
    for g in aggregated_events:
        g["mapping"] = map_event(g["event_type"], g.get("cves"), embedded_mitre=g.get("embedded_mitre"))
    return aggregated_events
