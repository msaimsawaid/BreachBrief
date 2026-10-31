"""
PHASE 5 — RISK ANALYSIS ENGINE (v2)

v1 used Risk = Severity x Frequency x Impact, which let raw repeat-count
dominate the ranking — 30,000+ routine authentication failures outscored
rare, high-signal findings purely on volume. Frequency is evidence that a
pattern is real, not evidence that it's malicious; it shouldn't be a linear
multiplier.

v2 uses a weighted-sum model on a 0-100 scale, deliberately NOT a pure
product of four factors — an early pure-multiplicative version (Severity x
Confidence x Impact x FrequencyFactor) compressed every single-occurrence
finding toward the bottom of the scale regardless of severity, since four
sub-1.0-ish factors multiply down fast. A lone Critical-severity finding
should never be indistinguishable from routine noise just because it only
happened once — severity needs to dominate the score directly, with
confidence/impact/frequency as modulating adjustments, not co-equal
multipliers:

    RiskScore = SeverityBase x ConfidenceFactor x ImpactMultiplier
                + FrequencyBonus   (small, log-scaled, capped)

- SeverityBase (15/40/65/90 for low/medium/high/critical): the dominant
  term. This is "how bad is this kind of behavior," and it alone should be
  able to put a finding in the High band.
- ConfidenceFactor (0.05-0.99): "how sure are we this label is right" —
  built from HOW the event was classified (structured Wazuh metadata vs.
  keyword guess vs. unclassified) plus supporting evidence (genuine
  attacker IP, vendor-supplied MITRE mapping). This is the axis v1 didn't
  have at all.
- ImpactMultiplier (0.875-1.25): a modest swing based on the category of
  harm (exfiltration/lateral movement/priv-esc weighted higher than
  routine housekeeping) — intentionally NOT a 1x-4x swing, so it shapes
  but doesn't dominate.
- FrequencyBonus (0-15, log-scaled and capped): repetition still matters —
  a pattern seen 1,000 times is more likely to be a real, ongoing
  condition than one seen once — but it can add at most 15 points, so it
  can nudge a Medium into High, not turn routine noise into the top
  finding on its own.

This is what lets "10 SSH failures from one IP + a successful login +
sudo" (rare, high severity, decent confidence) outrank "30,000 unrelated
auth failures" (frequent, but lower confidence and no corroborating
pattern) — the ordering the critique specifically asked for.

Calibration note: the SeverityBase/threshold numbers below are a starting
point, not derived from labeled ground truth (we don't have any — see the
project notes on why fabricating precision/recall numbers without real
ground truth would be dishonest). They're deliberately simple and
documented so they can be tuned against real analyst feedback over time.
"""
from __future__ import annotations
import math

_SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_BASE = {"low": 15, "medium": 40, "high": 65, "critical": 90}

_IMPACT_WEIGHT = {
    "Data Exfiltration": 4,
    "Privilege Escalation": 4,
    "Lateral Movement": 4,
    "Malware Detected": 4,
    "Vulnerability Exploit": 3,
    "SQL Injection": 3,
    "Persistence Mechanism": 3,
    "Web Attack": 3,
    "XSS Attempt": 3,
    "SSH Brute Force": 2,
    "Web Brute Force": 2,
    "Authentication Failure": 2,
    "Nmap Scan": 2,
    "Firewall Block": 1,
    "Successful Login": 1,
    "System Error": 1,
    "Unclassified Event": 1,
}
_DEFAULT_IMPACT = 1

# --- confidence -------------------------------------------------------
# Base confidence by how the event was classified. Structured (rule
# groups/decoder/rule-id derived) classification is Wazuh's own
# categorization — we trust it more than our free-text keyword fallback,
# which is a best-effort guess for raw syslog / generic alerts. This
# mirrors the "MITRE mapping based on category resemblance, not evidence"
# critique — the fix is the same: know and expose how sure we actually are.
STRUCTURED_EVENT_TYPES = {
    "File Integrity Change", "File Added", "File Removed",
    "Compliance Check Failed", "Compliance Scan Summary",
    "Agent Disconnected", "Agent Connected", "Rootcheck Finding",
    "Active Response Triggered", "Vulnerability Advisory",
}
_BASE_CONFIDENCE = {
    "Unclassified Event": 20,
}
_STRUCTURED_BASE = 82
_KEYWORD_BASE = 55


def _base_confidence(event_type: str) -> float:
    if event_type in _BASE_CONFIDENCE:
        return _BASE_CONFIDENCE[event_type]
    if event_type in STRUCTURED_EVENT_TYPES:
        return _STRUCTURED_BASE
    return _KEYWORD_BASE


def compute_confidence(g: dict) -> tuple[float, list[dict]]:
    """Returns (total 0-100, breakdown). The breakdown is not a separate,
    invented explanation bolted on for display — it's the literal list of
    terms that were summed to produce the total, so the confidence-basis
    section a report shows is guaranteed to add up to the number next to
    it (see core/evidence_reasoning.py, which renders this breakdown
    verbatim rather than re-deriving its own version)."""
    breakdown = []

    base = _base_confidence(g["event_type"])
    if g["event_type"] in STRUCTURED_EVENT_TYPES or g["event_type"] in _BASE_CONFIDENCE:
        basis = "Structured Wazuh classification (rule groups/decoder)" if base == _STRUCTURED_BASE else "Unclassified — no reliable basis"
    else:
        basis = "Keyword-pattern classification (best-effort guess)"
    breakdown.append({"label": basis, "points": base})

    # A genuine attacker IP behind an attack-relevant, windowed finding is
    # real supporting evidence (this is exactly what makes it identity-
    # driven in correlate.py in the first place).
    if g.get("is_identity_driven"):
        breakdown.append({"label": "Genuine attacker IP behind an attack-relevant, windowed pattern", "points": 8})

    # A vendor-embedded MITRE mapping (straight from the Wazuh alert) is
    # more trustworthy than our static keyword-based guess.
    if g.get("embedded_mitre"):
        breakdown.append({"label": "Vendor-supplied MITRE mapping present on the source alert", "points": 10})

    # Multiple agents/hosts touched by the SAME condition-driven pattern is
    # mild corroborating evidence it's a systemic condition, not a fluke.
    agents = g.get("agents_seen") or []
    if not g.get("is_identity_driven") and len(agents) > 3:
        breakdown.append({"label": f"Same condition observed on {len(agents)} hosts (corroborating breadth)", "points": 5})

    total = max(5.0, min(99.0, sum(item["points"] for item in breakdown)))
    return total, breakdown


_IMPACT_MULT_MIN, _IMPACT_MULT_SPAN = 0.75, 0.125  # impact 1 -> 0.875, impact 4 -> 1.25


def _impact_multiplier(impact_w: int) -> float:
    return _IMPACT_MULT_MIN + _IMPACT_MULT_SPAN * impact_w


def _frequency_bonus(count: int) -> float:
    """0-15, log-scaled and capped. Repetition supports a finding without
    letting raw volume alone carry it into a higher risk band on its own —
    it can nudge a score, not dominate it. count=1 -> 0, 10 -> 4, 100 -> 8,
    1,000 -> 12, 10,000+ -> capped at 15."""
    return min(15.0, 4.0 * math.log10(max(1, count)))


def risk_level(score: float) -> str:
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def compute_priority(risk_lvl: str, confidence: float) -> str:
    """Priority answers 'how urgently should an analyst look at this' —
    distinct from severity/risk. A High-risk finding we're not very
    confident about is worth a look sooner than nothing, but shouldn't
    page someone at 3am the way a High-risk, high-confidence one should."""
    if risk_lvl == "High" and confidence >= 70:
        return "P1"
    if risk_lvl == "High" or (risk_lvl == "Medium" and confidence >= 70):
        return "P2"
    if risk_lvl == "Medium":
        return "P3"
    return "P4"

# --- disposition --------------------------------------------------------
# The engine's own best-guess disposition. This is a SUGGESTION, always
# overridable by an analyst (see pipeline.apply_disposition / app.py) —
# never presented as ground truth.
DISPOSITIONS = [
    "malicious", "likely_malicious", "suspicious",
    "benign", "likely_benign", "informational", "unknown",
]

_INFORMATIONAL_TYPES = {
    "Agent Connected", "Compliance Scan Summary", "Account Logon/Logoff",
    "Package Management Activity", "Successful Login",
}


def compute_auto_disposition(g: dict, possible_false_positive: bool) -> str:
    if g["event_type"] in _INFORMATIONAL_TYPES:
        return "informational"
    if possible_false_positive and g["severity"] in ("low", "medium"):
        return "likely_benign"
    if g["risk_level"] == "High" and g["confidence"] >= 70 and g.get("is_identity_driven"):
        return "likely_malicious"
    if g["risk_level"] == "High":
        return "suspicious"
    if g["risk_level"] == "Medium" and g["confidence"] >= 60:
        return "suspicious"
    return "unknown"


# --- false-positive flag (kept — still useful as a quick noise signal
# alongside, not instead of, the fuller disposition system) -------------
_FALSE_POSITIVE_CANDIDATE_TYPES = {
    "File Integrity Change", "File Added", "File Removed",
    "Compliance Check Failed", "Compliance Scan Summary",
    "Agent Disconnected", "Agent Connected", "Rootcheck Finding",
    "System Error", "Unclassified Event",
    "Privilege Escalation", "Persistence Mechanism", "Successful Login",
    "Vulnerability Advisory", "Account Logon/Logoff", "Package Management Activity",
}
FALSE_POSITIVE_REPEAT_THRESHOLD = 25


def is_likely_false_positive(event_type: str, severity: str, count: int) -> bool:
    if severity not in ("low", "medium"):
        return False
    if event_type not in _FALSE_POSITIVE_CANDIDATE_TYPES:
        return False
    return count >= FALSE_POSITIVE_REPEAT_THRESHOLD


def score_group(g: dict) -> dict:
    severity_base = _SEVERITY_BASE.get(g["severity"], _SEVERITY_BASE["low"])
    impact_w = _IMPACT_WEIGHT.get(g["event_type"], _DEFAULT_IMPACT)

    confidence, confidence_breakdown = compute_confidence(g)
    confidence_factor = confidence / 100.0
    impact_mult = _impact_multiplier(impact_w)
    freq_bonus = _frequency_bonus(g["count"])

    score = severity_base * confidence_factor * impact_mult + freq_bonus
    score = max(0.0, min(100.0, score))

    g["confidence"] = round(confidence, 1)
    g["confidence_breakdown"] = confidence_breakdown
    g["risk_score"] = round(score, 1)
    g["risk_level"] = risk_level(score)
    g["priority"] = compute_priority(g["risk_level"], confidence)
    g["possible_false_positive"] = is_likely_false_positive(g["event_type"], g["severity"], g["count"])
    g["auto_disposition"] = compute_auto_disposition(g, g["possible_false_positive"])
    g.setdefault("user_disposition", None)
    g.setdefault("user_notes", "")
    return g


def score_all(aggregated_events: list[dict]) -> list[dict]:
    for g in aggregated_events:
        score_group(g)
    return aggregated_events


def top_threats(aggregated_events: list[dict], n: int = 5) -> list[dict]:
    return sorted(aggregated_events, key=lambda g: g["risk_score"], reverse=True)[:n]


def overall_risk_posture(aggregated_events: list[dict]) -> str:
    if not aggregated_events:
        return "Low"
    highest = max(g["risk_score"] for g in aggregated_events)
    return risk_level(highest)
