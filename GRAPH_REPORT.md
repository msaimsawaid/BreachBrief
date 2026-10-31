# Graph Report - breach-brief  (2026-10-31)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 280 nodes · 524 edges · 12 communities
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 8 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- report.py
- run_pipeline
- _DictCompatMixin
- app.py
- app.js
- test_regression_synthetic.py
- risk.py
- parsers.py
- baseline.py
- normalize.py
- ingest.py
- timeline.py

## God Nodes (most connected - your core abstractions)
1. `run_pipeline()` - 25 edges
2. `renderDashboard()` - 18 edges
3. `_DictCompatMixin` - 15 edges
4. `generate_docx()` - 13 edges
5. `generate_pdf()` - 13 edges
6. `_run()` - 10 edges
7. `get_client()` - 9 edges
8. `group_events()` - 9 edges
9. `score_group()` - 9 edges
10. `identify_and_load()` - 8 edges

## Surprising Connections (you probably didn't know these)
- `test_reports_generate_without_error()` --calls--> `generate_docx()`  [EXTRACTED]
  tests/test_regression_synthetic.py → core/report.py
- `test_reports_generate_without_error()` --calls--> `generate_pdf()`  [EXTRACTED]
  tests/test_regression_synthetic.py → core/report.py
- `_run_analysis_job()` --calls--> `run_pipeline()`  [EXTRACTED]
  app.py → core/pipeline.py
- `sample()` --calls--> `run_pipeline()`  [EXTRACTED]
  app.py → core/pipeline.py
- `_run()` --calls--> `run_pipeline()`  [EXTRACTED]
  tests/test_regression_synthetic.py → core/pipeline.py

## Import Cycles
- None detected.

## Communities (12 total, 0 thin omitted)

### Community 0 - "report.py"
Cohesion: 0.06
Nodes (24): download_report(), effective_disposition(), _add_docx_cover_background(), _add_docx_cover_page(), _disp_label(), _draw_footer_page_number(), _draw_watermark(), _fmt_time() (+16 more)

### Community 1 - "run_pipeline"
Cohesion: 0.10
Nodes (16): annotate(), _assemble_reasoning_text(), build_reasoning(), _find_followup_success(), _fmt_dt(), _gemma_reasoning_text(), is_internal_ip(), _pattern_inference() (+8 more)

### Community 2 - "_DictCompatMixin"
Cohesion: 0.09
Nodes (11): _dominant_severity(), group_events(), _has_real_ip(), _make_group_id(), _sample_evidence(), sort_by_start(), sort_events(), _DictCompatMixin (+3 more)

### Community 3 - "app.py"
Cohesion: 0.11
Nodes (18): analyze(), analyze_result(), analyze_status(), _apply_triage_to(), _evict_if_needed(), gemma_status(), handle_any_error(), handle_too_large() (+10 more)

### Community 4 - "app.js"
Cohesion: 0.19
Nodes (24): addFiles(), badge(), confidenceBar(), dispositionSelect(), escapeHtml(), evidenceHtml(), ipDisplay(), mapChips() (+16 more)

### Community 5 - "test_regression_synthetic.py"
Cohesion: 0.13
Nodes (9): _run(), test_confidence_breakdown_sums_to_confidence(), test_every_group_has_confidence_and_reasoning(), test_expected_event_types_present(), test_group_count_is_stable(), test_identity_driven_grouping_uses_real_ip(), test_no_group_missing_required_fields(), test_rare_severe_finding_outranks_routine_ones() (+1 more)

### Community 6 - "risk.py"
Cohesion: 0.18
Nodes (12): _base_confidence(), compute_auto_disposition(), compute_confidence(), compute_priority(), _frequency_bonus(), _impact_multiplier(), is_likely_false_positive(), overall_risk_posture() (+4 more)

### Community 7 - "parsers.py"
Cohesion: 0.19
Nodes (5): extract_ips(), _get(), parse_json_alert(), parse_raw_log_line(), _safe_int()

### Community 8 - "baseline.py"
Cohesion: 0.32
Nodes (6): cmd_check(), cmd_snapshot(), _load_files(), main(), _pct_diff(), _summarize()

### Community 9 - "normalize.py"
Cohesion: 0.35
Nodes (9): SecurityEvent, apply_severity_ceiling(), classify_event_type(), _guess_protocol(), normalize_json_alert(), normalize_raw_log(), parse_timestamp(), severity_from_level() (+1 more)

### Community 10 - "ingest.py"
Cohesion: 0.29
Nodes (6): _extract_json_records(), _guess_source(), identify_and_load(), ingest_many(), IngestedFile, _looks_like_json()

### Community 11 - "timeline.py"
Cohesion: 0.43
Nodes (5): build_timeline(), classify_stage(), _fmt(), _narrative_line(), timeline_summary_paragraph()

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `run_pipeline()` connect `run_pipeline` to `_DictCompatMixin`, `app.py`, `test_regression_synthetic.py`, `risk.py`, `parsers.py`, `baseline.py`, `normalize.py`, `ingest.py`, `timeline.py`?**
  _High betweenness centrality (0.143) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `generate_pdf()` (e.g. with `_pdf_cover_page()` and `_pdf_page_border()`) actually correct?**
  _`generate_pdf()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Should `report.py` be split into smaller, more focused modules?**
  _Cohesion score 0.05565638233514821 - nodes in this community are weakly interconnected._
- **Why does `_DictCompatMixin` connect `_DictCompatMixin` to `normalize.py`?**
  _High betweenness centrality (0.071) - this node is a cross-community bridge._
- **Should `run_pipeline` be split into smaller, more focused modules?**
  _Cohesion score 0.09815078236130868 - nodes in this community are weakly interconnected._
- **Should `_DictCompatMixin` be split into smaller, more focused modules?**
  _Cohesion score 0.0855614973262032 - nodes in this community are weakly interconnected._
- **Should `app.py` be split into smaller, more focused modules?**
  _Cohesion score 0.11083743842364532 - nodes in this community are weakly interconnected._