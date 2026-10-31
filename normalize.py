"""
PHASE 1.4 — NORMALIZATION
Converts parsed JSON-alert / raw-log dicts into the unified schema:

{
  "timestamp": datetime,
  "event_type": "",
  "source_ip": "",
  "destination_ip": "",
  "port": "",
  "protocol": "",
  "severity": "",       # low | medium | high | critical
  "raw_message": "",
  "source_file": "",
  "agent": "",
  "cves": [...],
}
"""
from __future__ import annotations
import re
from datetime import datetime, timezone

from .models import SecurityEvent

# ---- event-type classification -------------------------------------------
# Ordered keyword rules: first match wins. Tuned for common Wazuh/OSSEC +
# auth.log / syslog phrasing so v1 works out of the box without training data.
_CLASSIFY_RULES = [
    ("Nmap Scan",              [r"\bnmap\b", r"port ?scan", r"network scan", r"network recon", r"dropped packets"]),
    ("SSH Brute Force",        [r"sshd.*(failed|invalid)", r"brute[- ]?force.*ssh", r"multiple authentication failures"]),
    ("Web Brute Force",        [r"brute[- ]?force", r"multiple.*failed.*login", r"web.*login.*fail"]),
    ("SQL Injection",          [r"sql injection", r"union select", r"\bor 1=1\b"]),
    ("XSS Attempt",            [r"cross.site.script", r"<script>", r"\bxss\b"]),
    ("Web Attack",             [r"web attack", r"http.*exploit", r"directory traversal", r"\.\./\.\."]),
    ("Malware Detected",       [r"malware", r"trojan", r"virus detected", r"ransomware"]),
    ("Privilege Escalation",   [r"privilege escalation", r"sudo:.*command", r"\bsetuid\b", r"root shell"]),
    ("Persistence Mechanism",  [r"cron.*modif", r"registry run key", r"new service created", r"scheduled task"]),
    ("Lateral Movement",       [r"psexec", r"smb.*lateral", r"remote service.*creat", r"wmi.*exec"]),
    ("Data Exfiltration",      [r"exfiltrat", r"large.*upload", r"unusual outbound"]),
    ("Firewall Block",         [r"firewall.*(deny|drop|block)", r"iptables.*DROP"]),
    ("Authentication Failure", [r"authentication fail", r"invalid user", r"failed password",
                                 r"logon failure", r"bad password", r"unknown user"]),
    ("Account Logon/Logoff",   [r"\blogoff\b", r"logged off", r"session closed", r"user logoff",
                                 r"logon event registered", r"service logon"]),
    ("Package Management Activity", [r"\bdpkg\b", r"package installed", r"half configured", r"apt-get", r"\byum\b.*install"]),
    ("Successful Login",       [r"accepted password", r"session opened", r"successful login"]),
    ("Vulnerability Exploit",  [r"exploit"]),
    ("System Error",           [r"\berror\b", r"critical", r"fatal", r"audit failure"]),
]
_COMPILED_RULES = [(name, [re.compile(p, re.I) for p in pats]) for name, pats in _CLASSIFY_RULES]

# Structured-metadata rules for real Wazuh/OSSEC alert families. These are
# checked first (against rule.groups / decoder.name) because they're far
# more reliable than free-text keyword matching on full_log, and because
# these families (syscheck, sca, rootcheck, agent status) make up the bulk
# of real-world alert volume and previously had zero coverage, dumping
# almost everything into "Unclassified Event".
#
# Each rule: (event_type, groups_any_of, decoder_any_of)
_GROUP_RULES = [
    ("File Integrity Change",   {"syscheck_entry_modified"}, set()),
    ("File Added",              {"syscheck_entry_added"}, set()),
    ("File Removed",            {"syscheck_entry_deleted"}, set()),
    ("Compliance Scan Summary", {"sca"}, set()),  # refined further below (summary vs check)
    ("Compliance Check Failed", {"sca"}, set()),
    ("Agent Disconnected",      {"ossec"}, {"ossec"}),  # refined via rule_id / text below
    ("Rootcheck Finding",       {"rootcheck"}, set()),
    ("Active Response Triggered", {"active-response", "active_response"}, set()),
]

# rule.id values Wazuh uses consistently across versions for agent
# connectivity — more reliable than text matching "disconnected".
_AGENT_DISCONNECTED_RULE_IDS = {"504", "506"}
_AGENT_CONNECTED_RULE_IDS = {"502", "503"}

# Explicit rule-id overrides for common, very high-volume Windows
# Security/Sysmon audit events that are routine host activity, not attacks
# in themselves — checked before free-text keyword matching so they can't
# be misclassified by their own embedded MITRE tactic text (see parsers.py
# for why that text must never reach the classifier in the first place;
# this is a second, independent line of defense using authoritative rule
# IDs instead of text at all).
_RULE_ID_OVERRIDES = {
    "60106": "Successful Login",       # Windows Logon Success
    "60111": "Successful Login",       # Windows Logon Success (alt id)
    "60118": "Successful Login",       # Windows Workstation Logon Success
    "67028": "Successful Login",       # Special privileges assigned to new logon (routine audit)
    "61138": "Persistence Mechanism",  # New Windows Service Created — genuinely persistence-relevant, kept
}


def classify_event_type(text: str, rule_description: str = "", groups: list | None = None,
                         decoder_name: str | None = None, rule_id: str | None = None,
                         sca: dict | None = None) -> str:
    groups = set(groups or [])
    decoder_name = (decoder_name or "").lower()

    # --- structured-metadata classification (preferred) ---
    if "syscheck_entry_modified" in groups:
        return "File Integrity Change"
    if "syscheck_entry_added" in groups:
        return "File Added"
    if "syscheck_entry_deleted" in groups:
        return "File Removed"

    if "sca" in groups or decoder_name == "sca":
        if sca and sca.get("type") == "summary":
            return "Compliance Scan Summary"
        check = (sca or {}).get("check", {})
        if check.get("result") == "failed":
            return "Compliance Check Failed"
        return "Compliance Scan Summary"

    if rule_id in _AGENT_DISCONNECTED_RULE_IDS:
        return "Agent Disconnected"
    if rule_id in _AGENT_CONNECTED_RULE_IDS:
        return "Agent Connected"
    if rule_id in _RULE_ID_OVERRIDES:
        return _RULE_ID_OVERRIDES[rule_id]

    if "rootcheck" in groups:
        return "Rootcheck Finding"
    if "active-response" in groups or "active_response" in groups:
        return "Active Response Triggered"
    if "vulnerability-detector" in groups:
        # A vulnerability-detector alert means "this installed package is
        # affected by CVE-X" — an inventory/patch-management finding, NOT
        # an observed exploitation attempt. Conflating the two (matching a
        # bare CVE-ID pattern as "Vulnerability Exploit") turns routine
        # vulnerability-scan output into thousands of false "active attack"
        # rows. Keep them separate.
        return "Vulnerability Advisory"

    # --- fallback: free-text keyword classification (raw logs, generic alerts) ---
    haystack = f"{rule_description} {text}".strip()
    for name, patterns in _COMPILED_RULES:
        if any(p.search(haystack) for p in patterns):
            return name
    return "Unclassified Event"


# ---- severity ---------------------------------------------------------
def severity_from_level(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


# Housekeeping/compliance-drift event types are capped below their raw
# Wazuh `level` would otherwise imply — a failed CIS check at level 9 is
# configuration drift, not an active attack, and shouldn't rank alongside
# a level-9 exploitation attempt. This is what keeps real-world SCA/syscheck
# volume from dominating the risk-sorted view.
_SEVERITY_CEILING = {
    "Compliance Check Failed": "medium",
    "Compliance Scan Summary": "low",
    "File Added": "low",
    "File Integrity Change": "medium",
    "File Removed": "medium",
    "Rootcheck Finding": "medium",
    "Agent Disconnected": "low",
    "Agent Connected": "low",
    "Active Response Triggered": "medium",
    "Vulnerability Advisory": "medium",   # inventory finding, not an active attack
    "Account Logon/Logoff": "low",
    "Package Management Activity": "low",
    "Unclassified Event": "medium",
    "System Error": "medium",
}
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def apply_severity_ceiling(event_type: str, severity: str) -> str:
    ceiling = _SEVERITY_CEILING.get(event_type)
    if ceiling and _SEVERITY_RANK[severity] > _SEVERITY_RANK[ceiling]:
        return ceiling
    return severity


_SEVERITY_KEYWORDS = {
    "critical": ["critical", "ransomware", "exfiltrat", "root shell"],
    "high": ["exploit", "malware", "privilege escalation", "brute"],
    "medium": ["scan", "failed password", "invalid user", "firewall"],
}


def severity_from_text(text: str) -> str:
    low = text.lower()
    for sev, kws in _SEVERITY_KEYWORDS.items():
        if any(k in low for k in kws):
            return sev
    return "low"


# ---- timestamp parsing --------------------------------------------------
_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
    "%b %d %H:%M:%S",   # syslog, no year
]


def parse_timestamp(raw, fallback_year: int | None = None):
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        try:
            return datetime.fromtimestamp(raw, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    raw = str(raw).strip()
    for fmt in _FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            if "%Y" not in fmt and fallback_year:
                dt = dt.replace(year=fallback_year)
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except ValueError:
            continue
    return None


# ---- main entry point -----------------------------------------------------
def normalize_json_alert(parsed: dict, source_file: str) -> "SecurityEvent":
    event_type = classify_event_type(
        parsed.get("full_log") or "",
        parsed.get("rule_description") or "",
        groups=parsed.get("groups"),
        decoder_name=parsed.get("decoder_name"),
        rule_id=str(parsed.get("rule_id")) if parsed.get("rule_id") is not None else None,
        sca=parsed.get("sca"),
    )
    severity = severity_from_level(parsed.get("level") or 0)
    severity = apply_severity_ceiling(event_type, severity)

    # Prefer the alert's own embedded MITRE mapping over our static guess —
    # it's vendor-classified and more accurate than keyword inference.
    embedded_mitre = None
    if parsed.get("mitre_ids"):
        technique = ", ".join(parsed.get("mitre_techniques") or [])
        embedded_mitre = f"{'/'.join(parsed['mitre_ids'])}" + (f" - {technique}" if technique else "")

    return SecurityEvent(
        timestamp=parse_timestamp(parsed.get("timestamp")),
        raw_timestamp=parsed.get("timestamp"),
        event_type=event_type,
        source_ip=parsed.get("source_ip"),
        destination_ip=parsed.get("destination_ip"),
        port=parsed.get("port"),
        protocol=_guess_protocol(parsed.get("port")),
        severity=severity,
        rule_id=parsed.get("rule_id"),
        rule_description=parsed.get("rule_description"),
        raw_message=parsed.get("full_log"),
        source_file=source_file,
        agent=parsed.get("agent_name"),
        cves=parsed.get("cves", []),
        embedded_mitre=embedded_mitre,
    )


def normalize_raw_log(parsed: dict, source_file: str, agent: str) -> "SecurityEvent":
    event_type = classify_event_type(parsed.get("message") or "", parsed.get("process") or "")
    severity = severity_from_text(parsed.get("message") or "")
    severity = apply_severity_ceiling(event_type, severity)
    return SecurityEvent(
        timestamp=parse_timestamp(parsed.get("timestamp"), fallback_year=datetime.utcnow().year),
        raw_timestamp=parsed.get("timestamp"),
        event_type=event_type,
        source_ip=parsed.get("source_ip"),
        destination_ip=parsed.get("destination_ip"),
        port=parsed.get("port"),
        protocol=_guess_protocol(parsed.get("port")),
        severity=severity,
        rule_id=None,
        rule_description=parsed.get("process"),
        raw_message=parsed.get("message"),
        source_file=source_file,
        agent=agent,
        cves=parsed.get("cves", []),
        embedded_mitre=None,
    )


def _guess_protocol(port) -> str:
    try:
        p = int(port)
    except (TypeError, ValueError):
        return ""
    return {22: "SSH", 80: "HTTP", 443: "HTTPS", 21: "FTP", 3389: "RDP",
            23: "TELNET", 25: "SMTP", 53: "DNS", 3306: "MySQL", 445: "SMB"}.get(p, "")
