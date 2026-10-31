"""
PHASE 1.3 — PARSING ENGINE
Turns raw records (Wazuh/OSSEC JSON alerts, or freeform log lines) into
loosely-structured dicts. Normalization into the unified schema happens
in normalize.py.
"""
from __future__ import annotations
import re
from datetime import datetime

# Octet-validated IPv4 matcher. A plain "4 dot-separated numbers" regex
# happily matches CIS control IDs (3.5.2.3), version strings, and other
# dotted-quad-shaped junk that shows up constantly in real Wazuh/OSSEC SCA
# and syscheck payloads. Each octet must be 0-255.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IP_RE = re.compile(rf"\b{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}\b")

PORT_RE = re.compile(r"\bport[s]?\s*[:=]?\s*(\d{1,5})\b", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

# Fields/phrases that produce dotted-quad-shaped strings which are NOT IPs.
# If a matched "IP" was pulled from text containing these markers nearby,
# treat it as noise rather than a real address (CIS control numbers,
# version numbers, checksums referenced inline, scan/policy IDs).
_NON_IP_CONTEXT = re.compile(
    r"\b(cis|cis_csc|control|policy|benchmark|version|v\d+\.\d+|score|checksum)\b",
    re.I,
)


def extract_ips(text: str, allow_context_check: bool = True) -> list[str]:
    """Find genuine-looking IPv4 addresses in free text, filtering out
    dotted-quad lookalikes (CIS control IDs, version numbers, etc.)."""
    if not text:
        return []
    found = []
    for m in IP_RE.finditer(text):
        ip = m.group(0)
        if allow_context_check:
            window = text[max(0, m.start() - 40):m.start()]
            if _NON_IP_CONTEXT.search(window):
                continue
        found.append(ip)
    return found

# common syslog / auth.log style: "Mon DD HH:MM:SS host process[pid]: message"
SYSLOG_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w\-/\.]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# ISO-ish timestamp anywhere in a line as a fallback
ISO_TS_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)

CURRENT_YEAR = datetime.utcnow().year


def _get(d: dict, *keys, default=None):
    """Try several possible key paths (dot-notation) on a dict."""
    for key in keys:
        cur = d
        ok = True
        for part in key.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur not in (None, ""):
            return cur
    return default


def parse_json_alert(record: dict) -> dict:
    """Extract the fields the roadmap specifies from a Wazuh/OSSEC-style alert."""
    timestamp = _get(record, "timestamp", "@timestamp", "time")
    rule_id = _get(record, "rule.id", "rule_id")
    rule_desc = _get(record, "rule.description", "rule_description", default="Unknown alert")
    level = _get(record, "rule.level", "level", default=0)
    groups = _get(record, "rule.groups", default=[]) or []
    decoder_name = _get(record, "decoder.name", default=None)
    agent_name = _get(record, "agent.name", "agent_name", default="unknown-agent")

    # Structured fields are trustworthy IPs. Only fall back to scanning
    # full_log free text (with octet validation + context filtering) when
    # the alert doesn't carry data.srcip/dstip directly.
    src_ip = _get(record, "data.srcip", "srcip", "source_ip", "src_ip")
    dst_ip = _get(record, "data.dstip", "dstip", "destination_ip", "dst_ip")

    # IMPORTANT: full_log must be genuine free-text log content, never a dump
    # of the raw alert record. Wazuh alerts (esp. Windows Sysmon/Security
    # ones) often omit full_log entirely — falling back to json.dumps(record)
    # here would feed the classifier the alert's OWN rule.mitre.tactic text
    # (e.g. "Privilege Escalation") as if it were observed log content,
    # causing the classifier to match its own metadata and misclassify
    # routine, high-volume audit events (logon auditing, service creation)
    # as active attacks. Fall back to the rule description only — never to
    # a raw record dump — and keep classification text separate from any
    # display-only text.
    full_log = _get(record, "full_log", "message", default=rule_desc)

    if not src_ip:
        candidates = extract_ips(full_log or "")
        src_ip = candidates[0] if candidates else None
        dst_ip = dst_ip or (candidates[1] if len(candidates) > 1 else None)

    # Wazuh alerts frequently embed their own MITRE mapping — this is more
    # accurate than our static keyword-based guess and should be preferred.
    mitre_ids = _get(record, "rule.mitre.id", default=[]) or []
    mitre_tactics = _get(record, "rule.mitre.tactic", default=[]) or []
    mitre_techniques = _get(record, "rule.mitre.technique", default=[]) or []

    # SCA (Security Configuration Assessment) compliance checks carry their
    # own structured pass/fail result and policy name.
    sca = _get(record, "data.sca", default=None)

    port_match = PORT_RE.search(full_log or "")
    cve_matches = CVE_RE.findall(full_log or "") + CVE_RE.findall(rule_desc or "")

    return {
        "timestamp": timestamp,
        "rule_id": rule_id,
        "rule_description": rule_desc,
        "level": _safe_int(level),
        "groups": groups,
        "decoder_name": decoder_name,
        "agent_name": agent_name,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "port": port_match.group(1) if port_match else None,
        "event_type": None,   # filled in during normalization/classification
        "full_log": full_log,
        "cves": sorted(set(c.upper() for c in cve_matches)),
        "mitre_ids": mitre_ids,
        "mitre_tactics": mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "sca": sca,
    }


def parse_raw_log_line(line: str) -> dict:
    """Parse a single freeform / syslog-style log line."""
    m = SYSLOG_RE.match(line)
    if m:
        gd = m.groupdict()
        message = gd["message"]
        timestamp = gd["timestamp"]
        process = gd["process"]
    else:
        message = line
        process = None
        iso = ISO_TS_RE.search(line)
        timestamp = iso.group(0) if iso else None

    ips = extract_ips(message)
    port_match = PORT_RE.search(message)
    cves = CVE_RE.findall(message)

    return {
        "timestamp": timestamp,
        "process": process,
        "message": message,
        "source_ip": ips[0] if ips else None,
        "destination_ip": ips[1] if len(ips) > 1 else None,
        "port": port_match.group(1) if port_match else None,
        "event_type": None,
        "cves": sorted(set(c.upper() for c in cves)),
    }


def json_safe_str(record: dict) -> str:
    try:
        import json as _json
        return _json.dumps(record)[:500]
    except Exception:
        return str(record)[:500]


def _safe_int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0
