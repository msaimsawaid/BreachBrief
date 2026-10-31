"""
PHASE 2 — CORRELATION ENGINE
Sorts normalized events, groups related ones, and produces aggregated
events.

Grouping mode is decided PER EVENT, not just per event-type:

- IDENTITY-DRIVEN: the event's type is attack-relevant AND it carries a
  genuine source_ip. Grouped by (event_type, source_ip) within a rolling
  time window — because *who* is doing it is the meaningful correlating
  dimension, and windowing separates distinct campaigns from the same IP.

- CONDITION-DRIVEN: everything else — housekeeping/compliance event types
  outright, AND any attack-typed event that has NO real source_ip (common
  for host-local audit events like Windows logon auditing or sudo logging,
  which Wazuh/OSSEC report without network attacker context). Grouped by
  (event_type, rule_id, agent) with NO time-window limit, absorbing every
  distinct IP/agent touched into that one group instead of spawning a new
  group per occurrence.

Why per-event instead of a static type table: a fixed "these types are
always identity-driven" list still explodes into thousands of singleton
groups for event types like "Privilege Escalation" or "Successful Login"
that are attack-relevant WHEN a real attacker IP is present, but are just
routine, IP-less host auditing 95% of the time in real Wazuh exports
(Windows logon auditing, `sudo` logging). Keying by IP-presence rather than
type name lets the same event type route correctly either way.
"""
from __future__ import annotations
import hashlib
from datetime import datetime, timedelta

from .models import EventGroup, EvidenceItem

# Event types considered attack-relevant enough to use identity (IP-keyed,
# windowed) grouping WHEN a genuine source_ip is present on the event. If an
# event of one of these types has no real source_ip, it still falls through
# to condition-driven grouping (see module docstring).
IDENTITY_DRIVEN_TYPES = {
    "Nmap Scan", "SSH Brute Force", "Web Brute Force", "SQL Injection",
    "XSS Attempt", "Web Attack", "Malware Detected", "Privilege Escalation",
    "Persistence Mechanism", "Lateral Movement", "Data Exfiltration",
    "Firewall Block", "Authentication Failure", "Successful Login",
    "Vulnerability Exploit",
}


def sort_events(events: list[dict]) -> list[dict]:
    """Time-order events. Events with no parseable timestamp sink to the end,
    keeping their original relative order (stable sort)."""
    epoch = datetime(1970, 1, 1)
    return sorted(events, key=lambda e: e["timestamp"] or epoch)


def _make_group_id(event_type: str, key_parts: tuple) -> str:
    raw = event_type + "|" + "|".join(str(p) for p in key_parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


def _has_real_ip(ip: str | None) -> bool:
    return bool(ip) and ip != "unknown"


def group_events(events: list[dict], window_minutes: int = 5) -> list[dict]:
    events = sort_events(events)
    window = timedelta(minutes=window_minutes)

    # `latest_for_key` always points at the MOST RECENT group for a given
    # correlation key — this is what a new event's window check must
    # compare against. `all_groups` holds every group ever created, in
    # creation order, for final output. Using one dict for both (as before)
    # meant that once a windowed group closed out and a new one spun up,
    # the key kept pointing at the stale, closed group — so every
    # subsequent event's window check compared against an increasingly
    # ancient timestamp, always failed, and spun off its own singleton
    # group. That's why back-to-back scans a second apart were showing as
    # dozens of separate one-count rows instead of one row with a count.
    latest_for_key: dict[tuple, dict] = {}
    all_groups: list[dict] = []
    campaign_seq: dict[tuple, int] = {}

    for ev in events:
        event_type = ev["event_type"]
        src_ip = ev.get("source_ip")
        is_identity = event_type in IDENTITY_DRIVEN_TYPES and _has_real_ip(src_ip)

        if is_identity:
            key = ("identity", event_type, src_ip)
        else:
            # Condition-driven: key by event type + rule + agent, not IP.
            # No time window — the same recurring condition on the same
            # agent collapses into one group no matter when it re-fires.
            key = ("condition", event_type, ev.get("rule_id"), ev.get("agent"))

        g = latest_for_key.get(key)
        in_window = (
            g is not None and is_identity and ev["timestamp"] and g["_last_ts"]
            and (ev["timestamp"] - g["_last_ts"]) <= window
        )
        # Condition-driven groups never expire once created (no window check).
        continues_group = g is not None and (not is_identity or in_window)

        if continues_group:
            g["count"] += 1
            g["end_time"] = ev["timestamp"] or g["end_time"]
            g["_last_ts"] = ev["timestamp"] or g["_last_ts"]
            if src_ip and src_ip not in g["source_ips"]:
                g["source_ips"].append(src_ip)
            if ev.get("destination_ip") and ev["destination_ip"] not in g["destination_ips"]:
                g["destination_ips"].append(ev["destination_ip"])
            if ev.get("port") and ev["port"] not in g["ports"]:
                g["ports"].append(ev["port"])
            if ev.get("agent") and ev["agent"] not in g["agents_seen"]:
                g["agents_seen"].append(ev["agent"])
            g["severities"].append(ev["severity"])
            g["cves"].update(ev.get("cves", []))
            if ev.get("embedded_mitre") and not g.get("embedded_mitre"):
                g["embedded_mitre"] = ev["embedded_mitre"]
            g["_events"].append(ev)
        else:
            # New campaign for this key (either first time seen, or the
            # previous campaign's window has elapsed). group_id includes a
            # sequence number so repeated campaigns from the same IP/type
            # get distinct, stable ids rather than colliding.
            seq = campaign_seq.get(key, 0)
            campaign_seq[key] = seq + 1
            g = {
                "_key": key,
                "group_id": _make_group_id(event_type, key[1:] + (seq,)),
                "event_type": event_type,
                "is_identity_driven": is_identity,
                "source_ip": src_ip or "unknown",   # primary/first, for display
                "source_ips": [src_ip] if src_ip else [],
                "agents_seen": [ev["agent"]] if ev.get("agent") else [],
                "destination_ips": [ev["destination_ip"]] if ev.get("destination_ip") else [],
                "ports": [ev["port"]] if ev.get("port") else [],
                "count": 1,
                "start_time": ev["timestamp"],
                "end_time": ev["timestamp"],
                "severities": [ev["severity"]],
                "cves": set(ev.get("cves", [])),
                "embedded_mitre": ev.get("embedded_mitre"),
                "_last_ts": ev["timestamp"],
                "_events": [ev],
            }
            all_groups.append(g)
            latest_for_key[key] = g

    aggregated = []
    for g in all_groups:
        g["severity"] = _dominant_severity(g["severities"])
        g["cves"] = sorted(g["cves"])
        # Evidence layer: keep a small, bounded sample of the actual raw
        # events behind this group so an analyst can see WHY it was
        # classified/grouped this way, instead of just trusting a rolled-up
        # label. Capped at 5 — a group can represent thousands of events,
        # and retaining all of them defeats the memory-bounding work done
        # in pipeline.py; a handful of representative examples (first,
        # last, and a couple from the middle) is enough to inspect the
        # pattern without holding the whole group's raw event list.
        g["evidence"] = _sample_evidence(g["_events"])
        del g["_last_ts"], g["severities"], g["_key"], g["_events"]
        # Build the canonical EventGroup (Phase 1 data model) from the
        # working dict — keeping the accumulation phase above as plain
        # dicts was a deliberate choice to keep this already-tricky
        # windowing logic unchanged and low-risk; only the finished,
        # stable shape is promoted to the typed model.
        aggregated.append(EventGroup(**g))

    return sort_by_start(aggregated)


def _sample_evidence(events: list[dict], max_samples: int = 5) -> list[EvidenceItem]:
    if not events:
        return []
    if len(events) <= max_samples:
        picked = events
    else:
        # first, last, and evenly-spaced middle ones — representative
        # rather than just "the first N", which for a long-running
        # condition would only show the very start.
        step = (len(events) - 1) / (max_samples - 1)
        idxs = sorted({round(i * step) for i in range(max_samples)})
        picked = [events[i] for i in idxs]

    out = []
    for ev in picked:
        out.append(EvidenceItem(
            timestamp=ev["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if ev.get("timestamp") else None,
            source_ip=ev.get("source_ip"),
            destination_ip=ev.get("destination_ip"),
            port=ev.get("port"),
            agent=ev.get("agent"),
            rule_id=ev.get("rule_id"),
            rule_description=ev.get("rule_description"),
            raw_message=(ev.get("raw_message") or "")[:300],
        ))
    return out


def sort_by_start(aggregated: list[dict]) -> list[dict]:
    epoch = datetime(1970, 1, 1)
    return sorted(aggregated, key=lambda g: g["start_time"] or epoch)


_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _dominant_severity(sevs: list[str]) -> str:
    if not sevs:
        return "low"
    return max(sevs, key=lambda s: _SEVERITY_RANK.get(s, 0))
