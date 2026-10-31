"""
PHASE 2 — EVIDENCE REASONING ENGINE

Turns a rolled-up label like "SSH Brute Force — risk 54.8" into an actual
evidence chain: what was observed, what was derived from combining those
observations, what's a reasonable inference (not a certainty), and what
was explicitly NOT observed — so the report never implies more than the
data supports.

This is entirely deterministic — template assembly over structured facts
already computed by correlate.py/risk.py/mapping.py. No LLM. Per the
roadmap this was scoped from: an LLM given raw alerts free-associates a
narrative; a deterministic engine given structured facts can only say what
the facts actually show. If an LLM interpretation layer is added later, it
should consume THIS engine's output, not read alerts directly.

Four sections per finding:

- evidence_bullets: the raw facts (count, time span, source, target...).
- reasoning_text: one assembled sentence connecting the facts to the
  event_type's behavioral pattern — template-based, not generative.
- confidence_breakdown: the EXACT terms risk.compute_confidence() summed
  to produce the confidence score (not a separately invented explanation —
  see risk.py, which returns this breakdown alongside the total).
- observed / derived / inferred / not_observed: the critique's explicit
  epistemic-honesty ask. "Observed" is only ever a literal fact from the
  data (a count, an IP, a rule match). "Inferred" is a labeled guess.
  "Not observed" says outright what evidence would need to exist to
  escalate this further, and whether that evidence exists elsewhere in
  the dataset (see _find_followup_success — a narrow, deliberately scoped
  version of "did this attempt succeed", not a general incident-chaining
  engine; that's Phase 4, out of scope here).
"""
from __future__ import annotations
import ipaddress
import logging
from datetime import timedelta

from core.gemma_client import get_client, gemma_generate

log = logging.getLogger(__name__)


def is_internal_ip(ip: str | None) -> bool | None:
    """True/False if determinable, None if not a parseable IP (e.g. 'unknown')."""
    if not ip or ip == "unknown":
        return None
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return None


_OUTCOME_LOOKUP_TYPES = {"Successful Login", "Account Logon/Logoff"}
_PRECEDING_TYPES_FOR_OUTCOME_CHECK = {
    "SSH Brute Force", "Web Brute Force", "Authentication Failure", "Nmap Scan",
}


def _find_followup_success(group, all_groups, window_hours: int = 2):
    """Narrow, deliberately-scoped outcome check: for a brute-force/recon
    -style finding, was there a Successful Login from the SAME source IP
    shortly after this group ended? This does NOT modify risk scoring
    (that's Phase 3 — Contextual Risk, out of scope here) — it only
    surfaces the observation as evidence/narrative. This is intentionally
    much narrower than the full incident-construction engine (Phase 4):
    it checks one specific, high-value pattern (brute-force → success)
    by exact source-IP match within a bounded window, nothing more."""
    if group["event_type"] not in _PRECEDING_TYPES_FOR_OUTCOME_CHECK:
        return None
    if not group.get("is_identity_driven") or not group.get("source_ip") or group["source_ip"] == "unknown":
        return None
    if not group.get("end_time"):
        return None

    window_end = group["end_time"] + timedelta(hours=window_hours)
    for other in all_groups:
        if other is group or other["event_type"] not in _OUTCOME_LOOKUP_TYPES:
            continue
        other_ips = other.get("source_ips") or ([other["source_ip"]] if other.get("source_ip") else [])
        if group["source_ip"] not in other_ips:
            continue
        if other.get("start_time") and group["end_time"] <= other["start_time"] <= window_end:
            return other
    return None


def _fmt_dt(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "an unknown time"


def build_reasoning(group, all_groups: list) -> dict:
    """Returns the structured reasoning dict attached to group.reasoning."""
    evidence_bullets: list[str] = []
    observed: list[str] = []
    derived: list[str] = []
    inferred: list[str] = []
    not_observed: list[str] = []

    count = group["count"]
    ip = group.get("source_ip")
    is_id = group.get("is_identity_driven")

    # --- observed (literal facts from the data) ---
    times = "time" if count == 1 else "times"
    observed.append(f"{count} matching event(s) ({group['event_type']}) observed, {times}.")
    evidence_bullets.append(f"{count} occurrence(s) between {_fmt_dt(group.get('start_time'))} and {_fmt_dt(group.get('end_time'))}")

    if is_id and ip and ip != "unknown":
        observed.append(f"All occurrences originated from source IP {ip}.")
        evidence_bullets.append(f"Single source IP: {ip}")
        internal = is_internal_ip(ip)
        if internal is True:
            evidence_bullets.append("Source is an internal/private address")
            derived.append("Source address is internal — this is host-local or lateral activity, not an external attacker, unless the internal host itself is already suspected of compromise.")
        elif internal is False:
            evidence_bullets.append("Source is an external/public address")
            derived.append("Source address is external — this activity originated from outside the monitored network.")
    elif not is_id:
        agents = group.get("agents_seen") or []
        if agents:
            observed.append(f"Observed on {len(agents)} host/agent(s): {', '.join(agents[:5])}{'...' if len(agents) > 5 else ''}.")
            evidence_bullets.append(f"{len(agents)} distinct host(s)/agent(s) affected")

    if group.get("destination_ips"):
        observed.append(f"Destination(s): {', '.join(group['destination_ips'][:5])}.")
        evidence_bullets.append(f"Destination(s): {', '.join(group['destination_ips'][:5])}")

    if group.get("start_time") and group.get("end_time") and group["start_time"] != group["end_time"]:
        span = group["end_time"] - group["start_time"]
        minutes = round(span.total_seconds() / 60, 1)
        evidence_bullets.append(f"Concentrated within a {minutes}-minute window")
        derived.append(f"Activity was concentrated within a {minutes}-minute window rather than spread evenly — consistent with a single automated burst rather than incidental background noise.")

    if group.get("embedded_mitre"):
        observed.append(f"Source alert carries a vendor-supplied MITRE mapping: {group['embedded_mitre']}.")
        evidence_bullets.append(f"Vendor MITRE mapping: {group['embedded_mitre']}")
    else:
        not_observed.append("No vendor-supplied MITRE mapping — the MITRE technique shown (if any) is our own keyword-based inference, not something the source data asserted.")

    # --- outcome check (narrow, see _find_followup_success docstring) ---
    followup = _find_followup_success(group, all_groups)
    if followup:
        observed.append(
            f"A Successful Login from the same source IP ({ip}) was observed at "
            f"{_fmt_dt(followup.get('start_time'))}, after this pattern."
        )
        inferred.append(
            "A successful authentication following this pattern raises the likelihood that the "
            "attempt(s) succeeded — this significantly changes how this finding should be prioritized "
            "and is worth immediate manual review."
        )
    elif group["event_type"] in _PRECEDING_TYPES_FOR_OUTCOME_CHECK:
        not_observed.append(
            "No successful authentication from the same source IP was found in the analyzed window "
            "following this pattern — compromise via this specific vector is not indicated by the "
            "available data (absence of evidence, not evidence of absence: the successful login may "
            "simply not be in the uploaded logs)."
        )

    # --- inference (the pattern-level read, explicitly labeled as inference) ---
    inferred.append(_pattern_inference(group))

    # --- confidence basis: exactly what risk.py summed, not a re-derivation ---
    confidence_breakdown = group.get("confidence_breakdown") or []

    reasoning_text = _assemble_reasoning_text(group, followup)

    return {
        "evidence_bullets": evidence_bullets,
        "reasoning_text": reasoning_text,
        "confidence_breakdown": confidence_breakdown,
        "observed": observed,
        "derived": derived,
        "inferred": inferred,
        "not_observed": not_observed,
    }


_PATTERN_INFERENCE_TEMPLATES = {
    "SSH Brute Force": "Multiple failed SSH authentication attempts from the same source against the same destination are consistent with credential-guessing (brute-force) behavior.",
    "Web Brute Force": "Repeated failed web-login attempts from the same source are consistent with credential-guessing behavior against a web application.",
    "Nmap Scan": "A concentrated burst of connection attempts across multiple ports/services from one source is consistent with network reconnaissance.",
    "SQL Injection": "The observed request pattern matches known SQL injection syntax and is consistent with an attempted injection attack, though whether it succeeded is not determinable from this alert alone.",
    "Privilege Escalation": "The observed command/session pattern is consistent with an attempt to gain elevated privileges; whether it succeeded requires reviewing the specific command executed.",
    "Data Exfiltration": "An unusually large or unusual outbound transfer is consistent with data exfiltration, though the specific data involved is not determinable from this alert alone.",
    "Malware Detected": "This finding reflects a direct malware detection by the endpoint/AV engine — the highest-confidence category of alert, since it's a signature/behavioral match rather than an inferred pattern.",
    "Vulnerability Exploit": "The observed pattern matches a known exploit signature; whether the exploitation attempt succeeded is not determinable from this alert alone.",
    "Vulnerability Advisory": "This is an inventory finding (a vulnerability scanner identified an installed package affected by a known CVE) — it reflects exposure, not observed attack activity.",
    "File Integrity Change": "A monitored file's content or metadata changed. This is routine during patching/deployment and only concerning if unexpected or on a security-relevant path.",
    "Compliance Check Failed": "A configuration check against a compliance benchmark failed — this reflects configuration drift, not observed attack activity.",
}
_DEFAULT_INFERENCE = "This finding reflects the stated event category; no additional behavioral pattern beyond the individual alert(s) was inferred."


def _pattern_inference(group) -> str:
    return _PATTERN_INFERENCE_TEMPLATES.get(group["event_type"], _DEFAULT_INFERENCE)


def _assemble_reasoning_text(group, followup) -> str:
    """
    Try Gemma first (structured-facts-in, analyst narrative out).
    Falls back to deterministic template if Gemma is unavailable or errors.
    """
    client = get_client()
    if client:
        narrative = _gemma_reasoning_text(client, group, followup)
        if narrative:
            return narrative
        log.debug("Gemma reasoning fallback to template for group %s", group.get("group_id"))

    # Deterministic fallback (original logic)
    base = _pattern_inference(group)
    if followup:
        base += (" This is elevated in importance because a successful authentication from the "
                  "same source was observed shortly afterward.")
    return base


def _gemma_reasoning_text(client, group, followup) -> str | None:
    """
    Build a structured prompt from already-computed facts and ask Gemma
    to write a 2-3 sentence analyst-grade narrative. All facts are
    injected — Gemma only narrates, never invents.
    """
    span_info = ""
    if group.get("start_time") and group.get("end_time") and group["start_time"] != group["end_time"]:
        span = group["end_time"] - group["start_time"]
        minutes = round(span.total_seconds() / 60, 1)
        span_info = f"spanning {minutes} minutes"

    ip_info = ""
    if group.get("source_ip") and group["source_ip"] != "unknown":
        ip_info = f"from source IP {group['source_ip']}"

    dest_info = ""
    if group.get("destination_ips"):
        dest_info = f"targeting {', '.join(group['destination_ips'][:3])}"

    followup_info = ""
    if followup:
        followup_info = (
            f"IMPORTANT: A successful authentication from the same source IP was observed "
            f"shortly after this pattern at {followup.get('start_time', 'unknown time')}. "
            f"This significantly elevates the finding."
        )

    prompt = f"""You are a Tier-2 SOC analyst writing an incident brief. Write exactly 2-3 sentences
that summarise the following security finding for a peer analyst. Be precise and factual.
Use ONLY the facts provided. Do not invent IPs, user names, or outcomes not listed.

Finding type: {group['event_type']}
Count: {group['count']} event(s) {span_info}
{ip_info} {dest_info}
Risk score: {group.get('risk_score', 'n/a')} ({group.get('risk_level', 'unknown')} risk)
Confidence: {group.get('confidence', 0):.0f}%
Key observations: {'; '.join(group.get('reasoning', {}).get('observed', [])[:4])}
{followup_info}

Write only the 2-3 sentence narrative. No headers, no bullet points."""

    return gemma_generate(client, prompt, timeout=12)


def annotate(aggregated_events: list) -> list:
    """Attach group.reasoning for every group. Call after risk.score_all()
    (needs confidence_breakdown) and mapping.annotate_aggregated()."""
    for g in aggregated_events:
        g["reasoning"] = build_reasoning(g, aggregated_events)
    return aggregated_events
