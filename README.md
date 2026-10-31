# Sentry·X — Security Log Correlation & Reporting Engine

A browser UI on top of a Python correlation core. Upload Wazuh/OSSEC-style
JSON alert exports and/or raw logs (auth.log, syslog, etc.), and it will:

1. **Ingest** — detect file type (JSON alert export vs. raw log) per file.
2. **Parse & normalize** — extract timestamp, event type, source/destination
   IP, port, severity, CVEs, etc. into one unified schema.
3. **Correlate** — sort events chronologically and group repeated activity
   (same event type + source IP, within a configurable time window).
4. **Build a timeline** — classify each correlated group into an attack
   stage (Reconnaissance → Initial Access → Execution → Persistence →
   Privilege Escalation → Lateral Movement → Exfiltration) and produce a
   chain-of-custody narrative.
5. **Map to frameworks** — MITRE ATT&CK, CWE, OWASP Top 10, NIST CSF, CIS
   Controls, plus any CVEs found in the raw log text.
6. **Score risk** — `Risk = Severity × Frequency × Impact`, bucketed into
   Low / Medium / High.
7. **Generate a report** — Executive Summary, Attack Overview table,
   Timeline, Detailed Findings, Risk Assessment, Recommendations, and an
   appendix of source files — exportable as **.docx** or **.pdf**.

This covers the roadmap through Phase 6 (Report Generation). Phases 7–10
(AI narrative generation, visualization graphs, automated test harness,
and productization as a CLI/SaaS) are intentionally left for a v2 — the
architecture (a clean `core/` package with no UI dependencies) is built so
any of those can be layered on without touching the pipeline itself.

## v5: Canonical data model, evidence reasoning engine, regression harness

Following a second external roadmap review (proposing a full deterministic
"Intelligence + Decision layer": canonical event model → evidence reasoning
→ contextual risk → incident construction → attack graph → confidence
provenance → LLM interpretation → investigation loop → analyst feedback →
QA guardrail → decision engine), this version implements the three most
foundational, purely-deterministic pieces — Phase 0, 1, and 2 of that
roadmap — deliberately holding off on incident-chaining (a materially
harder correlation problem — see core/models.py's Incident docstring),
contextual/outcome-driven risk scoring, and any LLM layer (which needs
your own infrastructure/provider decisions, not ones this tool should make
for you).

- **Phase 0 — Regression harness.** `tests/test_regression_synthetic.py`
  (8 tests, ships with the repo, runs against the safe synthetic incident)
  and `tools/baseline.py` (a snapshot/diff CLI you run locally against your
  own real alert files — never bundled here, since that's your
  organization's data). Both were verified to actually catch a regression:
  a simulated reversion to the old frequency-dominant risk formula was
  caught immediately by both — group-count-by-type drift, high-risk-count
  drift, and "the #1-ranked finding silently changed from Malware Detected
  to Unclassified Event" were all flagged before the code could ship.
- **Phase 1 — Canonical data model** (`core/models.py`): `SecurityEvent`,
  `EvidenceItem`, `EventGroup` dataclasses (dict-compatible — both
  `g["event_type"]` and `g.event_type` work on the same object — so every
  existing consumer kept working without a full rewrite), plus a stub
  `Incident` class documenting why full incident construction is out of
  scope for this pass. `normalize.py` and `correlate.py` now construct
  these directly instead of plain dicts.
- **Phase 2 — Evidence Reasoning Engine** (`core/evidence_reasoning.py`):
  entirely deterministic (no LLM) — turns "SSH Brute Force — risk 54.8"
  into an actual evidence chain: evidence bullets, a confidence-basis
  breakdown that's the literal terms `risk.py` summed (not a separately
  invented explanation), and explicit Observed / Derived / Inferred / Not
  Observed sections so the report never implies more certainty than the
  data supports. Includes a narrow, source-IP-scoped outcome check
  (did a brute-force/recon pattern's source IP successfully authenticate
  afterward?) — verified on real data to find a genuine SSH-brute-force →
  successful-login chain, and verified to correctly stay silent (no false
  claim) when IPs don't match. Rendered in both DOCX/PDF reports and the
  UI's expandable evidence panel.

## v4: Risk model overhaul, evidence layer, disposition system, report modes

Following an external critique of the v3 report output, this version
addresses the four highest-priority gaps identified (window selector
removed per your request — the background job's real progress bar made
picking a window upfront unnecessary friction):

- **Risk scoring redesigned.** v1-v3 used `Severity x Frequency x Impact`,
  which let raw repeat-count dominate — 33,382 routine auth failures
  scored 133,528 and topped every report, outranking rare high-signal
  findings purely on volume. v4 uses a weighted-sum model:
  `RiskScore = SeverityBase x ConfidenceFactor x ImpactMultiplier + FrequencyBonus`,
  where FrequencyBonus is log-scaled and capped at 15 points — repetition
  now nudges a score, it can't carry it. Verified on real data: the
  7,201-event auth-failure bucket dropped from rank #1 to rank #17 of 205,
  correctly below genuine attack chains from real attacker IPs with far
  fewer events. See `core/risk.py` docstring for the full model and the
  calibration caveat (these thresholds are a documented starting point,
  not derived from labeled ground truth — we don't have any, and fabricating
  precision/recall numbers without it would be dishonest).
- **Confidence added as its own axis** (0-100%), built from HOW a finding
  was classified (structured Wazuh metadata vs. keyword guess vs.
  unclassified) plus supporting evidence (genuine attacker IP, vendor-
  embedded MITRE mapping) — not from repeat count. MITRE mappings now
  carry their own confidence + source (`vendor-embedded` vs
  `static-mapping`), so a technique assigned only because the category name
  resembles it is never presented with the same confidence as one the
  source data itself asserted.
- **Priority and Disposition** are separate fields from Severity/Confidence
  (four axes, not one collapsed badge): Priority (P1-P4) answers "how
  urgently to act"; Disposition (`malicious` / `likely_malicious` /
  `suspicious` / `benign` / `likely_benign` / `informational` / `unknown`)
  is the engine's suggested read, always overridable by an analyst with
  notes, persisted per finding (`POST /api/analysis/<id>/disposition`).
- **Evidence layer**: every finding now carries a bounded sample (up to 5,
  first/last/middle) of the actual raw events behind it — visible in the
  UI (expandable "Show evidence" panel) and in the DOCX/PDF Detailed
  Findings section — so an analyst can see *why* something was classified
  and grouped the way it was, not just trust a rolled-up label.
- **Four report modes** (`?mode=analyst|executive|soc|forensic`):
  Analyst (default, excludes confirmed/likely-benign), Executive (only
  P1/P2 + confidence ≥60%, informational/benign collapsed to a count),
  SOC (suspicious+ only, benign/informational collapsed not deleted),
  Forensic (everything, uncapped, full evidence + raw-event appendix).

## v3: real-world burst-grouping fix

See prior section below — a windowed-group lookup bug caused rapid bursts
from the same IP to fragment into dozens of singleton rows instead of one
row with a count; fixed by separating "lookup for window continuation"
from "storage for final output."

## v2 overhaul (real-world scale)

Validated against 11 real Wazuh/OSSEC export files (~74 MB, ~30,000 raw
events): correlation now completes in ~16s (down from minutes/hangs),
producing 547 well-differentiated groups instead of 1,800+ near-duplicate
rows, with peak memory around 480 MB. Key fixes:

- **IP extraction** now octet-validates and filters out CIS-control-ID /
  version-string lookalikes that were previously misread as IPv4 addresses.
- **Classification** covers syscheck, SCA/compliance, rootcheck, agent
  connectivity, package management, and account logon/logoff — previously
  the bulk of real Wazuh volume fell through to "Unclassified Event".
- **A vendor MITRE mapping embedded in the alert is preferred** over our
  static keyword guess when present — but critically, that embedded
  metadata is now kept OUT of the text fed to the free-text classifier;
  it was previously leaking into a raw-JSON-dump fallback and causing the
  classifier to match its own answer key (e.g. routine Windows logon
  auditing was misclassified as "Privilege Escalation" because the alert's
  own `rule.mitre.tactic` field literally contained that phrase).
- **Vulnerability advisories** (`vulnerability-detector` — "this package is
  affected by CVE-X") are now classified separately from active
  exploitation attempts; conflating the two turned routine vulnerability-
  scan output into thousands of false "active attack" rows.
- **Grouping mode is decided per-event**: identity-driven (IP-keyed,
  windowed) only when the event both belongs to an attack-relevant type AND
  carries a genuine source IP; everything else groups by
  `(event_type, rule_id, agent)` with no window limit, absorbing every
  IP/agent touched into one row instead of spawning a new group per
  occurrence. This is what collapses 10,000 recurring low-signal alerts
  into one row with a count.
- **False-positive auto-flagging**: high-repeat, low/medium-severity groups
  of noise-prone types get `possible_false_positive: true` — never
  dropped, just flagged and filterable. The UI has per-row Dismiss/Keep
  controls and a "Hide likely noise" toggle; dismissed groups are excluded
  from exported reports by default (`?include_dismissed=1` to include).
- **Analysis runs as a background job** (`POST /api/analyze` returns a
  `job_id` immediately; the UI polls `/api/analyze/<job_id>/status` for
  real stage/percentage progress) instead of blocking the HTTP request —
  this is what fixed both the "5 minute hang" and the "couldn't download
  the report at all" symptoms, since the old synchronous request held tens
  of thousands of raw Python objects in memory for the life of the request.
- **Bounded retention**: only an aggregated view + a capped sample (2,000)
  of raw events is retained in memory per analysis; the DOCX/PDF "Detailed
  Findings" section is capped to the top 100 groups by risk score (the
  Attack Overview table still lists everything).
- **Tables paginate** (50 rows/page) in the UI instead of rendering
  thousands of DOM rows at once.

See `IMPLEMENTATION_PLAN.md` for the full before/after diagnosis.

## Post-launch fix: fragmented burst grouping

After the overhaul above, real data surfaced one more bug: rapid bursts
from the same IP (e.g. dozens of Nmap probes a second apart) were still
showing as many separate single-count rows instead of one row with a
count and a start–end time range. Root cause: when a windowed group closed
out and a new one started, the lookup table used for the *next* event's
window check was never updated to point at the new group — it kept
pointing at the stale, closed-out one. Every following event's gap check
then compared against an increasingly ancient timestamp, always failed,
and spun off its own singleton group. Fixed by separating "lookup for
window continuation" (always the most recent group per key) from "storage
for final output" (every group ever created, in order). Verified against
the real dataset: Nmap Scan groups went from 304 (fragmented) to 61
(genuine distinct campaigns), with a 2,586-occurrence burst and several
88/28-count bursts now each correctly a single row.

## Project layout

```
seccorr/
├── app.py                 # Flask app — the "browser UI on top of" layer
├── core/                  # the Python correlation/report core (UI-agnostic)
│   ├── ingest.py          # Phase 1.1–1.2 — file intake & identification
│   ├── parsers.py         # Phase 1.3 — JSON alert / raw log parsing
│   ├── normalize.py       # Phase 1.4 — unified schema + event classification
│   ├── correlate.py       # Phase 2 — time ordering, grouping, aggregation
│   ├── timeline.py        # Phase 3 — attack-stage classification & narrative
│   ├── mapping.py         # Phase 4 — MITRE / CWE / OWASP / NIST / CIS mapping
│   ├── risk.py             # Phase 5 — risk scoring
│   ├── report.py          # Phase 6 — DOCX + PDF report generation
│   ├── models.py           # canonical data model (SecurityEvent, EventGroup, EvidenceItem, Incident stub)
│   ├── evidence_reasoning.py  # deterministic evidence-chain / confidence-basis engine
│   └── pipeline.py        # orchestrates all of the above into one call
├── templates/index.html   # single-page UI (Saturn·X visual language)
├── static/style.css
├── static/app.js
├── sample_data/           # a synthetic multi-stage "incident" for the demo button
├── tests/                 # regression suite against the bundled synthetic incident
├── tools/baseline.py      # regression snapshot/diff CLI for YOUR real data (run locally, not bundled)
└── requirements.txt
```

## Running it

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://localhost:5000`. Drop in `.json` alert exports and/or
`.log`/`.txt` raw logs and run the engine — or click **Try Sample
Incident** to see it work against bundled synthetic data immediately
(nmap scan → SSH brute force → SQLi → priv-esc → persistence →
exfiltration, across two files).

## Testing / regression protection

```bash
# Safe synthetic suite — ships with the repo, no real data involved:
pytest tests/test_regression_synthetic.py -v

# Your own real data — run locally, keep the baseline file OUTSIDE this repo:
python3 tools/baseline.py snapshot --files "/path/to/your/alerts-*.json" --out my_baseline.json
# ... after changing anything under core/ ...
python3 tools/baseline.py check --files "/path/to/your/alerts-*.json" --baseline my_baseline.json
```

Run the synthetic suite before trusting any change to `core/`. If you're
iterating on classification/scoring against your own real alert corpus,
snapshot a baseline first and re-check after each change — this is what
would have caught the burst-grouping bug and the risk-model regression
described in the version history below, before either shipped.

## Using it with real Wazuh data

- **JSON alerts**: point it at your `alerts.json` (or any JSON-lines export)
  — it reads `rule.description`, `rule.level`, `agent.name`, `data.srcip`,
  `full_log`, etc., with sensible fallbacks if your export uses flatter key
  names (`rule_description`, `srcip`, `source_ip`, ...).
- **Raw logs**: works with standard syslog-formatted lines
  (`Mon DD HH:MM:SS host process[pid]: message`) or ISO-timestamped lines;
  IPs, ports, and CVE IDs are extracted directly from the message text.

## Extending it

- **Event classification** (`normalize.py: _CLASSIFY_RULES`) and **framework
  mapping** (`mapping.py: _FRAMEWORK_MAP`) are both plain Python
  dictionaries/lists — add a new event type in one place and its mapping in
  the other to extend coverage.
- **Recommendations** live in `pipeline.py: _RECOMMENDATIONS`, keyed the
  same way.
- The whole `core/` package has zero Flask/UI imports, so it's usable
  directly from a CLI or notebook: `core.pipeline.run_pipeline([(filename,
  bytes), ...])` returns the full report_data dict that both the UI and
  `core/report.py` consume.
# BreachBrief
