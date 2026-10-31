"""
GEMMA CLIENT — thin wrapper around google-genai for Breach Brief.

Three integration points, each progressively deeper into the pipeline:

  1. NARRATIVE  (evidence_reasoning.py)
     reasoning_text field → Gemma writes analyst prose from structured facts.

  2. CLASSIFIER  (pipeline.py, Phase 1.5)
     After normalization, any event still tagged "Unclassified Event" gets
     a second pass: Gemma reads the raw rule description + full_log text
     and returns one of the known event_type labels (or keeps "Unclassified
     Event" if it genuinely can't tell). Called ONCE per pipeline run as a
     batched prompt — not once per event — so it's a single API call regardless
     of how many unclassified events there are.

  3. MAPPING ENRICHMENT  (mapping.py)
     For event types with no static MITRE mapping (or only a generic one),
     Gemma suggests a specific MITRE ATT&CK technique ID + name. Cached
     per event_type for the life of the process — the same type is never
     sent twice.

All three degrade silently to deterministic fallback when GEMMA_API_KEY is
unset or any call fails. The pipeline is identical in behaviour either way;
Gemma only enriches.
"""
from __future__ import annotations
import os
import json
import logging

log = logging.getLogger(__name__)

_MODEL = "gemma-4-26b-a4b-it"
_client_cache = None
_init_tried   = False

# ── module-level caches ────────────────────────────────────────────────────
# Mapping enrichment cache: event_type -> {"MITRE": ..., "CWE": ..., ...}
_MAPPING_CACHE: dict[str, dict] = {}

# Valid event_type labels the classifier may return
VALID_EVENT_TYPES = {
    "Nmap Scan", "SSH Brute Force", "Web Brute Force", "SQL Injection",
    "XSS Attempt", "Web Attack", "Malware Detected", "Privilege Escalation",
    "Persistence Mechanism", "Lateral Movement", "Data Exfiltration",
    "Firewall Block", "Authentication Failure", "Successful Login",
    "Vulnerability Exploit", "System Error", "Unclassified Event",
    "File Integrity Change", "File Added", "File Removed",
    "Compliance Check Failed", "Compliance Scan Summary",
    "Agent Disconnected", "Agent Connected", "Rootcheck Finding",
    "Active Response Triggered", "Vulnerability Advisory",
    "Account Logon/Logoff", "Package Management Activity",
}


def get_client():
    """Return a google.genai.Client if GEMMA_API_KEY is set, else None."""
    global _client_cache, _init_tried
    if _init_tried:
        return _client_cache
    _init_tried = True
    key = os.getenv("GEMMA_API_KEY")
    if not key:
        log.debug("GEMMA_API_KEY not set — Gemma features disabled.")
        return None
    try:
        from google import genai  # type: ignore
        _client_cache = genai.Client(api_key=key)
        log.info("Gemma client initialised (model=%s).", _MODEL)
    except ImportError:
        log.warning("google-genai not installed — Gemma features disabled. pip install google-genai")
    except Exception as exc:
        log.warning("Gemma client init failed: %s", exc)
    return _client_cache


def gemma_generate(client, prompt: str, timeout: int = 15) -> str | None:
    """Raw generate — returns stripped text or None on any error."""
    if client is None:
        return None
    try:
        response = client.models.generate_content(model=_MODEL, contents=prompt)
        text = response.text
        return text.strip() if text else None
    except Exception as exc:
        log.warning("Gemma generate failed: %s", exc)
        return None


# ── Integration Point 2: Batch Event Classifier ───────────────────────────

def batch_classify(client, unclassified_events: list[dict]) -> dict[int, str]:
    """
    Takes a list of event dicts that came back as "Unclassified Event" from
    the keyword classifier. Sends ONE batched prompt to Gemma asking it to
    assign an event_type to each one. Returns a dict mapping list-index ->
    new event_type string. Events Gemma can't classify stay "Unclassified Event".

    Each event dict should have: rule_description, raw_message (text only).
    """
    if not unclassified_events or client is None:
        return {}

    valid_labels = sorted(VALID_EVENT_TYPES)
    lines = []
    for i, ev in enumerate(unclassified_events):
        desc = (ev.get("rule_description") or ev.get("raw_message") or "")[:200]
        lines.append(f"[{i}] {desc}")

    prompt = f"""You are a security event classifier for a SIEM system.
Classify each numbered alert below into EXACTLY ONE of these labels:
{', '.join(valid_labels)}

Rules:
- Return ONLY a JSON object mapping index to label, e.g. {{"0": "SSH Brute Force", "1": "Unclassified Event"}}
- If genuinely ambiguous, use "Unclassified Event"
- No explanation, no markdown, just the JSON object

Alerts to classify:
{chr(10).join(lines)}"""

    raw = gemma_generate(client, prompt, timeout=30)
    if not raw:
        return {}

    # Parse — strip any markdown fences Gemma may add
    text = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        # Try to extract a JSON object from the response
        import re
        m = re.search(r'\{[^{}]+\}', text, re.DOTALL)
        if m:
            try:
                result = json.loads(m.group(0))
            except Exception:
                log.warning("Gemma classifier: could not parse response JSON")
                return {}
        else:
            log.warning("Gemma classifier: no JSON found in response")
            return {}

    out: dict[int, str] = {}
    for k, v in result.items():
        try:
            idx = int(k)
            label = str(v).strip()
            if label in VALID_EVENT_TYPES:
                out[idx] = label
        except (ValueError, TypeError):
            pass
    log.info("Gemma classifier: reclassified %d/%d events", len(out), len(unclassified_events))
    return out


# ── Integration Point 3: Framework Mapping Enrichment ─────────────────────

def enrich_mapping(client, event_type: str, current_mapping: dict) -> dict:
    """
    For an event_type that has no vendor-embedded MITRE mapping and only a
    static-guess or missing mapping, ask Gemma for a more specific
    MITRE ATT&CK technique ID and a CWE. Results are cached per event_type
    so each unique type is only ever sent once per process lifetime.

    Returns a (possibly enriched) copy of current_mapping.
    Only called when: mitre_source == "static-mapping" or MITRE is None.
    """
    if client is None:
        return current_mapping

    # Check process-level cache first
    if event_type in _MAPPING_CACHE:
        cached = _MAPPING_CACHE[event_type]
        merged = dict(current_mapping)
        merged.update({k: v for k, v in cached.items() if v})
        merged["mitre_source"] = "gemma-enriched"
        merged["mitre_confidence"] = 75
        return merged

    prompt = f"""You are a cybersecurity framework mapping assistant.
For the security event type "{event_type}", provide:
1. The single most specific MITRE ATT&CK technique ID and name (e.g. "T1110.001 - Password Guessing")
2. The most relevant CWE ID and name (e.g. "CWE-307 - Improper Restriction of Excessive Authentication Attempts")

Return ONLY a JSON object with keys "MITRE" and "CWE". Example:
{{"MITRE": "T1110.001 - Password Guessing", "CWE": "CWE-307 - Improper Restriction of Excessive Authentication Attempts"}}

If no relevant mapping exists for a field, use null.
No explanation, no markdown, just the JSON object."""

    raw = gemma_generate(client, prompt, timeout=15)
    enriched: dict = {}
    if raw:
        text = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        try:
            enriched = json.loads(text)
        except json.JSONDecodeError:
            import re
            m = re.search(r'\{[^{}]+\}', text, re.DOTALL)
            if m:
                try:
                    enriched = json.loads(m.group(0))
                except Exception:
                    pass

    # Cache raw enrichment (may be empty — still caches to avoid re-calling)
    _MAPPING_CACHE[event_type] = enriched

    if not enriched:
        return current_mapping

    merged = dict(current_mapping)
    if enriched.get("MITRE"):
        merged["MITRE"] = enriched["MITRE"]
        merged["mitre_source"] = "gemma-enriched"
        merged["mitre_confidence"] = 75
    if enriched.get("CWE"):
        merged["CWE"] = enriched["CWE"]
    log.debug("Gemma mapping enriched %s -> MITRE: %s", event_type, merged.get("MITRE"))
    return merged


# ── convenience flag ──────────────────────────────────────────────────────
GEMMA_ENABLED: bool = bool(os.getenv("GEMMA_API_KEY"))
