"""
Orchestrates PHASES 1-5 into one call, producing the data structure that
both the UI (as JSON) and the report generator (PHASE 6) consume.
"""
from __future__ import annotations
from datetime import datetime

from . import ingest, parsers, normalize, correlate, timeline as timeline_mod, mapping, risk, evidence_reasoning
from .gemma_client import get_client, batch_classify

_RECOMMENDATIONS = {
    "Nmap Scan": "Restrict exposed services; enable rate-limiting / IDS alerting on port-scan behavior.",
    "SSH Brute Force": "Enforce key-based SSH auth, enable fail2ban / account lockout, and block the offending source IP.",
    "Web Brute Force": "Enable account lockout and CAPTCHA on login endpoints; add WAF rate limiting.",
    "SQL Injection": "Use parameterized queries / an ORM, deploy a WAF rule for injection patterns, patch the affected endpoint.",
    "XSS Attempt": "Sanitize and encode all user-supplied output; add a Content-Security-Policy header.",
    "Web Attack": "Patch the affected web application and review input validation on all exposed endpoints.",
    "Malware Detected": "Isolate the affected host, run full AV/EDR remediation, and rotate any credentials used on it.",
    "Privilege Escalation": "Audit sudo/administrative group membership; patch the exploited privilege-escalation vector.",
    "Persistence Mechanism": "Remove the unauthorized persistence artifact and audit scheduled tasks / startup items fleet-wide.",
    "Lateral Movement": "Segment the network, restrict SMB/RDP between hosts, and rotate credentials used in the pivot.",
    "Data Exfiltration": "Block the destination, review DLP policy, and identify what data left the environment.",
    "Firewall Block": "No action required beyond monitoring — the control is working as intended.",
    "Authentication Failure": "Review the account for compromise; enforce MFA where not already required.",
    "Successful Login": "Confirm the login source is expected; review for anomalous login patterns.",
    "Vulnerability Exploit": "Patch the exploited CVE immediately and check for related IOCs across the fleet.",
    "System Error": "Review application/system logs for the underlying fault.",
    "Unclassified Event": "Manually triage — this event did not match a known classification rule.",
    "File Integrity Change": "Confirm the change was authorized (patch/deploy); investigate if unexpected.",
    "File Added": "Confirm the new file was part of an expected install/deploy; investigate if unexpected.",
    "File Removed": "Confirm the deletion was intentional; investigate if it affects security tooling or logs.",
    "Compliance Check Failed": "Review the failed CIS control and remediate or document an accepted exception.",
    "Compliance Scan Summary": "Informational — review the compliance score trend over time.",
    "Agent Disconnected": "Confirm the host is online and the Wazuh agent service is running as expected.",
    "Agent Connected": "No action required — informational connectivity event.",
    "Rootcheck Finding": "Review the rootcheck finding for unauthorized system changes or hidden processes.",
    "Active Response Triggered": "Confirm the automated response action was appropriate for the trigger.",
    "Vulnerability Advisory": "Schedule the affected package for patching per your normal vulnerability-management cadence.",
    "Account Logon/Logoff": "No action required — routine account session activity.",
    "Package Management Activity": "Confirm package changes were part of an expected update/deploy window.",
}


# Raw events are capped in the retained report_data so memory stays bounded
# on large real-world uploads (tens of thousands of events). Aggregated
# groups (now in the hundreds, post class-aware grouping) are always kept
# in full — that's the data that actually drives the UI/report.
RAW_EVENT_SAMPLE_CAP = 2000


def run_pipeline(uploaded_files: list[tuple[str, bytes]], window_minutes: int = 5,
                  progress_cb=None) -> dict:
    """progress_cb, if given, is called as progress_cb(stage: str, pct: int)
    so a caller (e.g. a background job) can report status without this
    module knowing anything about threads/HTTP."""
    def report(stage, pct):
        if progress_cb:
            progress_cb(stage, pct)

    report("ingesting", 5)
    ingested = ingest.ingest_many(uploaded_files)

    report("parsing", 20)
    events = []
    total_files = len(ingested) or 1
    for i, f in enumerate(ingested):
        if f.file_type == "alert_json":
            for record in f.json_records:
                parsed = parsers.parse_json_alert(record)
                events.append(normalize.normalize_json_alert(parsed, f.filename))
            f.json_records = []  # free — fully consumed, no longer needed
        elif f.file_type == "raw_log":
            for line in f.lines:
                parsed = parsers.parse_raw_log_line(line)
                events.append(normalize.normalize_raw_log(parsed, f.filename, f.source))
            f.lines = []  # free — fully consumed
        f.raw_text = ""  # free — large and unused past this point
        report("parsing", 20 + int(20 * (i + 1) / total_files))

    # ── Phase 1.5 — Gemma batch reclassification ──────────────────────────
    # Any event still tagged "Unclassified Event" after the deterministic
    # pass gets a second look from Gemma. One batched API call regardless of
    # how many unclassified events there are. Degrades silently if no key.
    report("classifying", 42)
    gemma_client = get_client()
    if gemma_client:
        unclassified = [(i, ev) for i, ev in enumerate(events)
                        if ev.get("event_type") == "Unclassified Event"]
        if unclassified:
            indices, ev_list = zip(*unclassified)
            reclassified = batch_classify(gemma_client, list(ev_list))
            for local_idx, new_type in reclassified.items():
                global_idx = indices[local_idx]
                events[global_idx]["event_type"] = new_type
                events[global_idx]["gemma_classified"] = True

    report("correlating", 45)
    events = correlate.sort_events(events)
    aggregated = correlate.group_events(events, window_minutes=window_minutes)

    report("mapping", 65)
    aggregated = mapping.annotate_aggregated(aggregated)

    report("scoring", 75)
    aggregated = risk.score_all(aggregated)

    report("reasoning", 80)
    # Phase 2 — Evidence Reasoning Engine. Runs after scoring (needs
    # confidence_breakdown) and after mapping (needs embedded_mitre already
    # resolved onto the group). Entirely deterministic — see
    # core/evidence_reasoning.py docstring for why this stays template-based
    # rather than reaching for an LLM at this stage.
    aggregated = evidence_reasoning.annotate(aggregated)

    report("building_timeline", 85)
    tl = timeline_mod.build_timeline(aggregated)
    tl = mapping.annotate_timeline(tl)

    for entry, group in zip(tl, aggregated):
        entry["risk_score"] = group["risk_score"]
        entry["risk_level"] = group["risk_level"]
        entry["group_id"] = group["group_id"]
        entry["possible_false_positive"] = group["possible_false_positive"]
        entry["confidence"] = group["confidence"]
        entry["priority"] = group["priority"]
        entry["auto_disposition"] = group["auto_disposition"]

    threats = risk.top_threats(aggregated, n=10)
    posture = risk.overall_risk_posture(aggregated)

    report("recommendations", 92)
    recommendations = []
    seen = set()
    for g in sorted(aggregated, key=lambda x: x["risk_score"], reverse=True):
        if g["event_type"] not in seen:
            seen.add(g["event_type"])
            rec = _RECOMMENDATIONS.get(g["event_type"])
            if rec:
                recommendations.append({"event_type": g["event_type"], "action": rec})

    fp_count = sum(1 for g in aggregated if g["possible_false_positive"])
    disposition_counts = {}
    for g in aggregated:
        d = g["auto_disposition"]
        disposition_counts[d] = disposition_counts.get(d, 0) + 1
    stats = {
        "total_files": len(ingested),
        "total_raw_events": len(events),
        "total_aggregated_events": len(aggregated),
        "high_risk_count": sum(1 for g in aggregated if g["risk_level"] == "High"),
        "medium_risk_count": sum(1 for g in aggregated if g["risk_level"] == "Medium"),
        "low_risk_count": sum(1 for g in aggregated if g["risk_level"] == "Low"),
        "possible_false_positive_count": fp_count,
        "disposition_counts": disposition_counts,
        "unique_source_ips": len({
            ip for g in aggregated for ip in g.get("source_ips", [])
        }),
        "overall_posture": posture,
        "stages_observed": sorted({e["stage"] for e in tl}, key=lambda s: timeline_mod.STAGE_ORDER.index(s) if s in timeline_mod.STAGE_ORDER else 99),
    }

    report("done", 100)
    return {
        "generated_at": datetime.utcnow(),
        "files": [{"filename": f.filename, "file_type": f.file_type, "source": f.source} for f in ingested],
        "events": events[:RAW_EVENT_SAMPLE_CAP],   # bounded sample — see module docstring
        "events_total_count": len(events),
        "aggregated_events": aggregated,
        "timeline": tl,
        "timeline_summary": timeline_mod.timeline_summary_paragraph(tl),
        "top_threats": threats,
        "recommendations": recommendations,
        "stats": stats,
    }


def apply_disposition(report_data: dict, disposition_by_group: dict[str, dict]) -> None:
    """Mutates aggregated_events/timeline in place to reflect analyst
    disposition overrides + notes. disposition_by_group maps
    group_id -> {"disposition": <one of risk.DISPOSITIONS>, "notes": str}.
    The engine's own auto_disposition is left untouched — this only sets
    the analyst override layered on top of it."""
    for g in report_data["aggregated_events"]:
        override = disposition_by_group.get(g["group_id"])
        g["user_disposition"] = override["disposition"] if override else None
        g["user_notes"] = override.get("notes", "") if override else ""
    for entry in report_data["timeline"]:
        gid = entry.get("group_id")
        override = disposition_by_group.get(gid)
        entry["user_disposition"] = override["disposition"] if override else None


def effective_disposition(g: dict) -> str:
    """The disposition to actually use for filtering/reporting: the
    analyst's override if they've made one, otherwise the engine's
    suggestion. Never presented as more authoritative than it is — see
    risk.compute_auto_disposition's docstring."""
    return g.get("user_disposition") or g.get("auto_disposition") or "unknown"


# Dispositions excluded from a report by default (Analyst mode) — i.e.
# things confirmed or auto-suggested as noise. Report modes (Executive/SOC/
# Forensic) apply their own, wider or narrower, include-sets — see
# core/report.py REPORT_MODES.
DEFAULT_EXCLUDED_DISPOSITIONS = {"benign", "likely_benign"}
