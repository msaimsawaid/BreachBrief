# Sentry·X — Implementation Plan: Real-World Scale Correlation Overhaul

**Context:** v1 was validated against synthetic attack data (dozens of events).
Real OSSEC/Wazuh exports (84k+ events across 30+ files/month) exposed three
compounding failures: bad grouping logic, incomplete classification, and a
blocking single-pass backend. This plan fixes all three, in order, plus the
UI/workflow changes needed to make the output usable at this scale.

---

## PART 0 — Theoretical reframe (read this before touching code)

The current model treats **repetition as noise to survive** — every event
tries to find or create its own group, so 10,000 near-identical low-severity
events become 10,000 near-identical rows. The correct model treats
**repetition as signal to compress**: 10,000 occurrences of the same
underlying condition should become *one* row with `count: 10000`, a list of
every IP/host it touched, and a severity-aware flag saying "this looks like
routine noise — confirm or dismiss."

This reframe drives every fix below:

| Old assumption | New assumption |
|---|---|
| Group key = `(event_type, exact source_ip)` | Group key depends on event *class*: identity-bearing attack events key on IP; housekeeping/compliance events key on `(event_type, rule_id, agent)` and absorb IPs into a list |
| Unmatched event_type → generic bucket | Every major Wazuh/OSSEC event family (syscheck, SCA, rootcheck, agent status, active-response) has an explicit classification rule |
| A regex match for 4 dot-separated numbers = an IP | An IP must pass octet validation (0–255) and not originate from a known non-IP field (CIS control IDs, version strings) |
| Whole file set loaded, sorted, grouped, mapped, scored, serialized, reported — all in one blocking request | Long-running analysis is a background job with progress polling; nothing about "10 minutes is fine" is honored by a synchronous HTTP request timing out at 30–60s anyway |
| High-volume low-severity = still shown as-is | High-volume low-severity = auto-flagged `possible_false_positive`, user confirms/dismisses, filterable in UI |

---

## PART 1 — Correctness fixes (do these first; they alone kill most of the noise)

### 1.1 Fix IP extraction (`core/parsers.py`)
- Replace the naive `IP_RE` dotted-quad regex with an **octet-validated**
  version (each segment 0–255).
- Add a rejection list of contexts that produce false positives: CIS
  `compliance.cis` / `cis_csc_v7` fields, version-looking strings, and
  anything pulled from `rule.*` metadata rather than `data.srcip` /
  `full_log` free text. Only trust IPs extracted from actual network-context
  fields or explicitly-labelled log text ("from `<ip>`", "src `<ip>`").
- Add unit tests using real lines from `ossec-alerts-11.json` (the CIS
  `3.5.2.3` case, the syscheck `sha256` hex strings, the SCA `scan_id`
  numbers) as negative examples that must **not** produce an IP.

### 1.2 Expand event classification (`core/normalize.py`)
Real Wazuh/OSSEC alert streams are dominated by families your current
`_CLASSIFY_RULES` doesn't cover at all. Add explicit rules keyed off
`rule.groups` / `decoder.name` (far more reliable than free-text regex on
`full_log`) with text regex as a fallback only:

| New event_type | Trigger (groups / decoder) | Stage |
|---|---|---|
| File Integrity Change | `groups` contains `syscheck`, `syscheck_entry_modified` | Persistence (if binary/system path) or Other |
| File Added | `groups` contains `syscheck_entry_added` | Other (low) / Persistence (if `/etc`, `/usr/bin`, systemd unit paths) |
| Compliance Check Failed | `groups` contains `sca`, `decoder.name == sca`, result `failed` | Other |
| Compliance Scan Summary | `groups` contains `sca`, `type: summary` | Other (informational, always low) |
| Agent Disconnected | `rule.id == 504` / `groups` contains `ossec` + "disconnected" text | Defense Evasion (uses the alert's own `mitre` block when present — see 1.3) |
| Agent Connected/Reconnected | rule id 502/503 equivalent | Other |
| Rootcheck Finding | `groups` contains `rootcheck` | varies by rule level |
| Active Response Triggered | `groups` contains `active-response` | Response (new stage, informational) |

This alone should reclassify the large majority of the "Unclassified Event"
volume in your sample file into 4–5 honest buckets.

### 1.3 Use the alert's own MITRE mapping when present
Wazuh alerts frequently embed `rule.mitre.id` / `tactic` / `technique`
directly (see `T1565.001`, `T1562.001` in your sample). **Prefer this over
our static keyword-mapping table** — it's more accurate than guessing from
free text, and it's already vendor-classified. Fall back to
`core/mapping.py`'s static table only when `rule.mitre` is absent (e.g. for
raw syslog lines with no structured metadata).

### 1.4 Redesign the grouping key (`core/correlate.py`)
Split grouping strategy by event class instead of one universal key:

- **Identity-driven events** (brute force, scans, exploitation, lateral
  movement, exfiltration — anything where *who* is attacking matters): keep
  `(event_type, source_ip)` windowed grouping as today.
- **Condition-driven events** (syscheck, SCA, rootcheck, agent status,
  system housekeeping — anything where *what condition recurred* matters
  more than *which IP*): group by `(event_type, rule_id, agent_name)`,
  **no time window limit** (or a much larger one, e.g. whole-file), and
  **accumulate every distinct IP/host seen into `destination_ips` /
  `agents_seen` on that single group** rather than starting a new group.
- Result: a condition that fires 10,000 times across 40 hosts becomes
  **one row**, `count: 10000`, `agents_seen: [40 items]`, not 10,000 rows.

### 1.5 Recalibrate severity for compliance/housekeeping noise
SCA "failed" checks at `rule.level: 9` are compliance drift, not an attack —
don't let raw Wazuh `level` alone drive severity for this class; use a
per-event-type severity ceiling (e.g. SCA/syscheck capped at `medium` unless
the file path matches a sensitive-system-binary allowlist).

---

## PART 2 — False-positive workflow (your explicit ask)

### 2.1 Auto-flagging rule (`core/risk.py`)
Add `possible_false_positive: bool` to every aggregated group:
```
flag = True if (severity in {low, medium}) AND (count >= threshold, e.g. 25)
       AND event_type in {File Integrity Change, File Added,
                           Compliance Check Failed, Compliance Scan Summary,
                           Agent Disconnected}
       else False
```
This is a *suggestion*, never a silent drop — flagged groups still appear in
the report/UI, just visually deprioritized and filterable.

### 2.2 User confirm/dismiss workflow
- New endpoint `POST /api/analysis/<id>/dismiss` — accepts a list of group
  ids to mark `user_dismissed: true`. Stored against the in-memory (or
  persisted, see Part 3) analysis record.
- New endpoint `POST /api/analysis/<id>/confirm` — un-flags a group the
  user wants kept as a real finding despite the heuristic.
- Report generation (DOCX/PDF) takes a `include_dismissed: bool` param
  (default false) so the exported report reflects the analyst's triage, not
  raw noise.
- UI: every Overview/Findings row gets a "Mark as false positive" /
  "Confirmed finding" toggle; a filter chip to show/hide dismissed rows;
  a running count ("142 flagged as likely noise, 8 dismissed by you").

### 2.3 Group ids
Aggregated groups need a stable `group_id` (hash of event_type + rule_id +
key fields) so dismiss/confirm actions survive re-render and can be
persisted/re-applied if the same analysis is re-opened.

---

## PART 3 — Performance & scale (backend)

### 3.1 Stop blocking the HTTP request
A single `POST /api/analyze` doing ingest→parse→normalize→correlate→map→
score→serialize for 84k+ events across 30+ files is exactly the wrong shape
for a browser request (timeouts, no progress, the whole "5 minute hang"
you're seeing). Move to a **background job model**:
- `POST /api/analyze` → validates files, kicks off a background thread/
  process, returns `{job_id}` immediately.
- `GET /api/analyze/<job_id>/status` → polled every ~1–2s by the frontend,
  returns `{stage: "parsing"|"correlating"|"mapping"|"scoring"|"done"|"error", progress: 0-100, message}`.
- `GET /api/analyze/<job_id>/result` → returns the serialized result once
  `status == done`.
- Implementation: Python `threading` + a simple in-memory job dict is
  sufficient for a single-instance deployment (no need for Celery/Redis at
  this scale) — a `concurrent.futures.ThreadPoolExecutor` with 1–2 workers
  keeps it simple while freeing the request thread immediately.

### 3.2 Reduce algorithmic complexity in correlation
- Current grouping is already close to O(n) per event with dict lookups,
  but the **explosion in group count** (Part 1.4) is what makes it feel
  O(n²) — fixing the grouping key is 80% of the performance fix by itself.
- Pre-bucket events by `event_type` before grouping (single pass), then run
  the windowing logic within each bucket — avoids repeated dict-key
  reconstruction across the full event list.
- Avoid re-sorting the full event list multiple times; sort once, reuse.

### 3.3 Memory discipline
- Don't retain the full parsed+normalized event list (with `datetime`
  objects, full raw messages) for the lifetime of the analysis. After
  correlation + report data are built:
  - Keep aggregated groups (small — hundreds, not tens of thousands, after
    Part 1 fixes) in memory for the session.
  - Store only a **capped, sampled** slice of raw events (e.g. first 500 per
    file, or first 2,000 total) for the report appendix and UI "raw events"
    tab — never all 84k.
  - Drop the full raw event list from the in-memory analysis store once
    aggregation is complete; nothing downstream needs it at full volume.
- This directly fixes the "PDF download hangs / never completes" symptom —
  that's the report generator re-walking tens of thousands of retained
  events on every export.

### 3.4 Streaming file ingestion
- Read/parse each uploaded file's JSON-lines incrementally (line-by-line
  `json.loads`) instead of loading the whole file into one Python list
  before processing — matters once files are large (a month of alerts can
  be tens of MB per file × 30 files).
- Process files one at a time, feeding events into the same bucketed
  correlation structure, rather than concatenating everything into one giant
  list first.

### 3.5 Report generation at scale
- DOCX/PDF "Detailed Findings" section currently iterates every aggregated
  group — fine post-Part-1 (hundreds, not thousands), but cap the "Detailed
  Findings" deep section to the top N by risk score (e.g. top 100) with a
  summary table covering the rest, and cap the raw-event appendix table
  (already capped at 200 — keep this, just make sure it's pulling from the
  *sampled* store from 3.3, not the full list).

---

## PART 4 — Frontend / UX changes

### 4.1 Progress, not a spinner
Replace the single blocking fetch + generic "Parsing files…" cycling
messages with real polling against `/api/analyze/<job_id>/status`, showing
actual stage + a numeric progress bar. This is the single biggest perceived-
lag fix — a 10-minute job with real progress feels fine; a 10-minute job
behind a static spinner feels broken (which is what you're experiencing now).

### 4.2 Table scale handling
- Paginate / virtualize the Overview and Raw Events tables — do not render
  thousands of DOM rows at once (this is a real contributor to the browser-
  side lag you saw, independent of backend speed).
- Default sort by risk score descending so the signal is at the top instead
  of buried under alphabetically-first "Unclassified Event" rows.
- Add the false-positive filter chip and per-row dismiss/confirm controls
  from Part 2.2.

### 4.3 Multi-file, month-scale upload UX
- Show per-file parse status as files complete (not just one global
  spinner) — useful when one file among 30 is malformed.
- Enforce a sane per-file and total size cap with a clear inline message
  (not a raw Flask 413 HTML page — already flagged as a bug from the prior
  fix; folds into this work).

---

## PART 5 — Testing plan

1. **Unit tests** for the IP-regex fix using real lines from your uploaded
   `ossec-alerts-*.json` files as fixtures (CIS IDs, syscheck hashes must
   NOT parse as IPs; genuine `data.srcip` values must).
2. **Unit tests** for classification coverage — feed every distinct
   `rule.groups` / `decoder.name` combination present in your sample files
   through `classify_event_type` and assert none fall through to
   "Unclassified Event" unless genuinely novel.
3. **Load test** with your actual 14-file sample (and a synthetically
   duplicated 30-file/84k-event set) run through the background job —
   assert: job completes, memory stays bounded (track via
   `tracemalloc`/`resource` during the test), aggregated group count stays
   in the hundreds (not thousands), and DOCX/PDF export completes in
   seconds once the job is done (not minutes).
4. **Regression test** against the original synthetic incident
   (`sample_data/`) to confirm the attack-style grouping (IP-keyed,
   windowed) still produces the expected multi-stage timeline.

---

## PART 6 — Build order

1. Part 1.1 (IP regex) + 1.2 (classification coverage) + 1.3 (use embedded
   MITRE data) — pure correctness, no architecture change, immediately
   testable against your uploaded files.
2. Part 1.4 (grouping key redesign) + 1.5 (severity recalibration) — the
   change that collapses thousands of rows into hundreds.
3. Part 2 (false-positive flag + dismiss/confirm workflow + endpoints).
4. Part 3 (background job model + memory discipline + streaming ingestion)
   — now that group counts are sane, confirm whether this is still needed
   at your target scale (84k events/30 files) or whether 1–2 minutes is
   acceptable without it; implement regardless since month-over-month
   growth will need it.
5. Part 4 (frontend polling, pagination, dismiss UI).
6. Part 5 (tests) — written alongside each step above, not deferred to the
   end.

Steps 1–2 alone should take your 14-file sample from "thousands of
Unclassified rows, minutes of lag" to "a few hundred honestly-classified,
honestly-aggregated rows" — worth validating against your real files before
moving on to the job-queue/UI work in steps 3–5.
