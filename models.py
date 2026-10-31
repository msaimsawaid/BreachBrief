"""
PHASE 1 — CANONICAL DATA MODEL

One authoritative internal shape for an event, a correlated group of
events, and (eventually) a multi-group incident — instead of information
scattered across ad-hoc dicts with slightly different keys in different
modules. This is what the evidence reasoning engine (Phase 2) and, later,
the incident construction engine (Phase 4) are built on top of.

Design choice — dict-compatible dataclasses, not a full rewrite:
Every existing module (correlate.py, risk.py, mapping.py, timeline.py,
report.py, app.py) was built around plain dicts accessed with
`ev["timestamp"]`, `g["confidence"] = ...`, `g.get("evidence")`, etc.
Rewriting all of that to attribute access in one pass is the single most
expensive, highest-risk step in the whole roadmap (see the conversation
this was scoped from) — every consumer would need to change at once, with
no way to test them independently.

Instead, SecurityEvent and EventGroup are real dataclasses (typed fields,
constructors, identity, room for real methods) that ALSO implement the
Mapping protocol (__getitem__/__setitem__/get/setdefault/keys/...), so
`ev["timestamp"]` and `ev.timestamp` both work on the exact same object.
Existing code didn't have to change; new code (evidence_reasoning.py) can
use proper attribute access and type hints. This is a deliberate,
documented bridge — the honest long-term direction is for downstream
modules to migrate to attribute access over time, not a permanent design.
"""
from __future__ import annotations
from dataclasses import dataclass, field, fields, asdict
from datetime import datetime
from typing import Any, Optional
import uuid


class _DictCompatMixin:
    """Makes a dataclass behave like a dict for existing bracket-access
    and .get()/.setdefault() call sites, while remaining a real typed
    object. See module docstring for why this exists."""

    def __getitem__(self, key):
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __contains__(self, key):
        return hasattr(self, key)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def setdefault(self, key, default=None):
        if not hasattr(self, key) or getattr(self, key) is None:
            setattr(self, key, default)
        return getattr(self, key)

    def pop(self, key, default=None):
        val = getattr(self, key, default)
        if hasattr(self, key):
            try:
                setattr(self, key, None)
            except Exception:
                pass
        return val

    def keys(self):
        return [f.name for f in fields(self)]

    def items(self):
        return [(f.name, getattr(self, f.name)) for f in fields(self)]

    def to_dict(self) -> dict:
        """Plain-dict snapshot — used where a consumer genuinely needs a
        serializable dict copy rather than the live object (e.g. JSON
        responses, evidence samples)."""
        return {f.name: getattr(self, f.name) for f in fields(self)}


@dataclass
class SecurityEvent(_DictCompatMixin):
    """One normalized log/alert event — the atomic unit everything else
    is built from. Constructed by core/normalize.py."""
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: Optional[datetime] = None
    raw_timestamp: Optional[str] = None
    event_type: str = "Unclassified Event"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[str] = None
    protocol: str = ""
    severity: str = "low"
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    raw_message: Optional[str] = None
    source_file: str = ""
    agent: Optional[str] = None
    cves: list = field(default_factory=list)
    embedded_mitre: Optional[str] = None


@dataclass
class EvidenceItem(_DictCompatMixin):
    """One sampled raw event, kept as supporting evidence for a group —
    see core/correlate.py's _sample_evidence."""
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[str] = None
    agent: Optional[str] = None
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    raw_message: Optional[str] = None


@dataclass
class EventGroup(_DictCompatMixin):
    """A correlated group of SecurityEvents — the unit risk scoring,
    disposition, and (Phase 2) evidence reasoning operate on. Constructed
    by core/correlate.py's group_events."""
    group_id: str = ""
    event_type: str = "Unclassified Event"
    is_identity_driven: bool = False
    source_ip: str = "unknown"
    source_ips: list = field(default_factory=list)
    agents_seen: list = field(default_factory=list)
    destination_ips: list = field(default_factory=list)
    ports: list = field(default_factory=list)
    count: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    severity: str = "low"
    cves: list = field(default_factory=list)
    embedded_mitre: Optional[str] = None
    evidence: list = field(default_factory=list)   # list[EvidenceItem]

    # populated by core/risk.py
    confidence: float = 0.0
    confidence_breakdown: list = field(default_factory=list)  # [{"label":.., "points":..}]
    risk_score: float = 0.0
    risk_level: str = "Low"
    priority: str = "P4"
    possible_false_positive: bool = False
    auto_disposition: str = "unknown"
    user_disposition: Optional[str] = None
    user_notes: str = ""

    # populated by core/mapping.py
    mapping: dict = field(default_factory=dict)

    # populated by core/evidence_reasoning.py (Phase 2)
    reasoning: Optional[dict] = None

    # populated by core/timeline.py (kept in sync but timeline entries are
    # currently their own lightweight dicts — see timeline.py)
    incident_id: Optional[str] = None   # set once Phase 4 incident construction exists


@dataclass
class Incident(_DictCompatMixin):
    """PLACEHOLDER — Phase 4 (Incident Construction Engine) is not yet
    implemented. This exists now so the schema has a defined home for it,
    and so pipeline.py can expose an (always-empty, for now) `incidents`
    list without a breaking shape change when Phase 4 lands. Chaining
    EventGroups of DIFFERENT event types into one incident by shared
    IP/asset/time-window/attack-stage sequence is a materially different
    correlation problem from anything group_events() does today (which
    only merges events of the SAME type) — see the roadmap discussion this
    was scoped from for why it's deliberately out of scope for this pass.
    """
    incident_id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    title: str = ""
    group_ids: list = field(default_factory=list)
    created_at: Optional[datetime] = None
