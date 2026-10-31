"""
Flask app: browser UI on top of the Python correlation/reporting core.

Real-world exports (tens of thousands of events across dozens of files) are
too slow for a single blocking request, so analysis runs as a background
job with progress polling:

  POST /api/analyze                    -> starts a background job, returns {job_id}
  GET  /api/analyze/<job_id>/status    -> {stage, pct, message} — poll this
  GET  /api/analyze/<job_id>/result    -> full serialized result once done
  POST /api/sample                     -> small bundled demo, runs inline (fast)

There is no correlation-window control anymore — the progress loader made
picking a window upfront unnecessary friction, and a fixed default
(DEFAULT_WINDOW_MINUTES below) is applied to every run.

Disposition workflow (replaces the old binary dismiss/confirm):
  POST /api/analysis/<id>/disposition  -> {group_ids: [...], disposition: <one of core.risk.DISPOSITIONS>, notes?: str}
  The engine's own auto_disposition is always shown; this sets the
  analyst's override on top of it. Persisted per analysis for the life of
  the process (in-memory — see _TRIAGE).

Reports:
  GET  /api/report/docx/<id>?mode=analyst|executive|soc|forensic
  GET  /api/report/pdf/<id>?mode=analyst|executive|soc|forensic

Every error path returns JSON, never Flask's default HTML error page —
a raw HTML 413/500 page is what broke the frontend's res.json() call
previously.
"""
from __future__ import annotations
import io
import os
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, request, jsonify, render_template, send_file, abort
from werkzeug.exceptions import HTTPException

from core import pipeline, report, risk as risk_mod
from core.gemma_client import get_client, gemma_generate, GEMMA_ENABLED

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500 MB — a month of alerts across many files

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "sample_data")
DEFAULT_WINDOW_MINUTES = 5

# ---- job store -------------------------------------------------------
# Single-process, in-memory. Fine for a local/self-hosted tool at this
# scale; swap for Redis/a real queue if this becomes multi-instance.
_JOBS: dict[str, dict] = {}          # job_id -> {status, stage, pct, message, analysis_id, error}
_ANALYSES: dict[str, dict] = {}      # analysis_id -> report_data (post-completion)
_TRIAGE: dict[str, dict] = {}        # analysis_id -> {group_id: {"disposition": str, "notes": str}}
_MAX_STORED = 15
_LOCK = threading.Lock()
_EXECUTOR = ThreadPoolExecutor(max_workers=2)


def _evict_if_needed(store: dict):
    if len(store) > _MAX_STORED:
        oldest = next(iter(store))
        store.pop(oldest, None)


def _run_analysis_job(job_id: str, payload: list[tuple[str, bytes]]):
    def progress_cb(stage: str, pct: int):
        with _LOCK:
            if job_id in _JOBS:
                _JOBS[job_id].update(stage=stage, pct=pct, message=_STAGE_MESSAGES.get(stage, stage))

    try:
        report_data = pipeline.run_pipeline(payload, window_minutes=DEFAULT_WINDOW_MINUTES, progress_cb=progress_cb)
        analysis_id = str(uuid.uuid4())[:10]
        with _LOCK:
            _ANALYSES[analysis_id] = report_data
            _TRIAGE[analysis_id] = {}
            _evict_if_needed(_ANALYSES)
            _JOBS[job_id].update(status="done", stage="done", pct=100,
                                  message="Analysis complete.", analysis_id=analysis_id)
    except Exception as exc:  # noqa: BLE001
        with _LOCK:
            if job_id in _JOBS:
                _JOBS[job_id].update(status="error", error=str(exc))


_STAGE_MESSAGES = {
    "ingesting": "Reading uploaded files…",
    "parsing": "Parsing log & alert events…",
    "classifying": "Gemma: reclassifying ambiguous events…",
    "correlating": "Correlating related activity…",
    "mapping": "Mapping to MITRE / CWE / OWASP / NIST / CIS…",
    "scoring": "Scoring risk & confidence…",
    "reasoning": "Building evidence chains…",
    "building_timeline": "Building the attack timeline…",
    "recommendations": "Compiling recommendations…",
    "done": "Analysis complete.",
}


def _serialize(report_data: dict, analysis_id: str, triage: dict) -> dict:
    def ts(dt):
        return dt.strftime("%H:%M:%S") if dt else None

    events_preview = []
    for ev in (report_data.get("events") or [])[:300]:
        events_preview.append({
            "timestamp": ts(ev.get("timestamp")),
            "event_type": ev.get("event_type"),
            "source_ip": ev.get("source_ip"),
            "destination_ip": ev.get("destination_ip"),
            "severity": ev.get("severity"),
            "source_file": ev.get("source_file"),
            "raw_message": (ev.get("raw_message") or "")[:200],
        })

    def with_disposition(g):
        group_id = g.get("group_id")
        override = triage.get(group_id)
        return {
            "group_id": group_id,
            "event_type": g.get("event_type"),
            "is_identity_driven": g.get("is_identity_driven", True),
            "source_ip": g.get("source_ip"),
            "source_ips": g.get("source_ips", []),
            "agents_seen": g.get("agents_seen", []),
            "destination_ips": g.get("destination_ips", []),
            "ports": g.get("ports", []),
            "count": g.get("count"),
            "start_time": ts(g.get("start_time")),
            "end_time": ts(g.get("end_time")),
            "severity": g.get("severity"),
            "confidence": g.get("confidence"),
            "risk_score": g.get("risk_score"),
            "risk_level": g.get("risk_level"),
            "priority": g.get("priority"),
            "possible_false_positive": g.get("possible_false_positive", False),
            "auto_disposition": g.get("auto_disposition"),
            "user_disposition": override["disposition"] if override else None,
            "user_notes": override.get("notes", "") if override else "",
            "mapping": g.get("mapping", {}),
            "evidence": [ev.to_dict() if hasattr(ev, "to_dict") else ev for ev in g.get("evidence", [])],
            "reasoning": g.get("reasoning"),
            "gemma_classified": g.get("gemma_classified", False),
        }

    aggregated = [with_disposition(g) for g in (report_data.get("aggregated_events") or [])]

    timeline = []
    for t in (report_data.get("timeline") or []):
        override = triage.get(t.get("group_id"))
        timeline.append({
            "group_id": t.get("group_id"),
            "time_label": t.get("time_label"),
            "stage": t.get("stage"),
            "event_type": t.get("event_type"),
            "count": t.get("count"),
            "source_ip": t.get("source_ip"),
            "source_ips": t.get("source_ips", []),
            "destination_ips": t.get("destination_ips", []),
            "severity": t.get("severity"),
            "narrative": t.get("narrative"),
            "risk_score": t.get("risk_score"),
            "risk_level": t.get("risk_level"),
            "confidence": t.get("confidence"),
            "priority": t.get("priority"),
            "possible_false_positive": t.get("possible_false_positive", False),
            "auto_disposition": t.get("auto_disposition"),
            "user_disposition": override["disposition"] if override else None,
            "mapping": t.get("mapping"),
        })

    top_threats = [{
        "event_type": g.get("event_type"), "source_ip": g.get("source_ip"),
        "risk_score": g.get("risk_score"), "risk_level": g.get("risk_level"),
        "confidence": g.get("confidence"), "priority": g.get("priority"),
        "count": g.get("count"),
    } for g in (report_data.get("top_threats") or [])]

    return {
        "analysis_id": analysis_id,
        "generated_at": report_data.get("generated_at").strftime("%Y-%m-%d %H:%M UTC")
            if hasattr(report_data.get("generated_at"), "strftime") else (report_data.get("generated_at") or ""),
        "files": report_data.get("files") or [],
        "stats": report_data.get("stats") or {},
        "events": events_preview,
        "events_total": report_data.get("events_total_count", len(report_data.get("events") or [])),
        "aggregated_events": aggregated,
        "timeline": timeline,
        "timeline_summary": report_data.get("timeline_summary") or {},
        "top_threats": top_threats,
        "recommendations": report_data.get("recommendations") or [],
        "dispositions": risk_mod.DISPOSITIONS,
    }


def _apply_triage_to(report_data: dict, analysis_id: str) -> dict:
    triage = _TRIAGE.get(analysis_id, {})
    pipeline.apply_disposition(report_data, triage)
    return report_data


# ---- error handling: always JSON, never Flask's HTML error page ------
@app.errorhandler(Exception)
def handle_any_error(e):
    if isinstance(e, HTTPException):
        return jsonify({"error": e.description or str(e)}), e.code
    return jsonify({"error": f"Unexpected server error: {e}"}), 500


@app.errorhandler(413)
def handle_too_large(e):
    return jsonify({"error": "Upload too large for the configured limit."}), 413


# ---- routes -----------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "No files uploaded."}), 400

    payload = []
    for f in files:
        data = f.read()
        if data:
            payload.append((f.filename, data))

    if not payload:
        return jsonify({"error": "Uploaded files were empty."}), 400

    job_id = str(uuid.uuid4())[:10]
    with _LOCK:
        _JOBS[job_id] = {"status": "running", "stage": "ingesting", "pct": 0, "message": "Starting…"}
        _evict_if_needed(_JOBS)
    _EXECUTOR.submit(_run_analysis_job, job_id, payload)

    return jsonify({"job_id": job_id})


@app.route("/api/analyze/<job_id>/status")
def analyze_status(job_id):
    job = _JOBS.get(job_id)
    if not job:
        abort(404, "Job not found or has expired.")
    return jsonify({k: v for k, v in job.items() if k != "result"})


@app.route("/api/analyze/<job_id>/result")
def analyze_result(job_id):
    job = _JOBS.get(job_id)
    if not job:
        abort(404, "Job not found or has expired.")
    if job["status"] == "error":
        return jsonify({"error": job.get("error", "Analysis failed.")}), 500
    if job["status"] != "done":
        return jsonify({"error": "Analysis still in progress."}), 409

    analysis_id = job["analysis_id"]
    report_data = _ANALYSES.get(analysis_id)
    if not report_data:
        abort(404, "Analysis result has expired.")
    triage = _TRIAGE.get(analysis_id, {})
    return jsonify(_serialize(report_data, analysis_id, triage))


@app.route("/api/sample", methods=["POST"])
def sample():
    payload = []
    for fname in ("sample_alerts.json", "sample.log"):
        path = os.path.join(SAMPLE_DIR, fname)
        with open(path, "rb") as fh:
            payload.append((fname, fh.read()))
    report_data = pipeline.run_pipeline(payload, window_minutes=DEFAULT_WINDOW_MINUTES)
    analysis_id = str(uuid.uuid4())[:10]
    with _LOCK:
        _ANALYSES[analysis_id] = report_data
        _TRIAGE[analysis_id] = {}
        _evict_if_needed(_ANALYSES)
    return jsonify(_serialize(report_data, analysis_id, _TRIAGE[analysis_id]))


@app.route("/api/analysis/<analysis_id>/disposition", methods=["POST"])
def set_disposition(analysis_id):
    if analysis_id not in _ANALYSES:
        abort(404, "Analysis not found or has expired.")
    body = request.get_json(silent=True) or {}
    ids = body.get("group_ids") or []
    disposition = body.get("disposition")
    notes = body.get("notes", "")

    if disposition is not None and disposition not in risk_mod.DISPOSITIONS:
        return jsonify({"error": f"disposition must be one of {risk_mod.DISPOSITIONS} or null to clear."}), 400

    with _LOCK:
        for gid in ids:
            if disposition is None:
                _TRIAGE[analysis_id].pop(gid, None)
            else:
                _TRIAGE[analysis_id][gid] = {"disposition": disposition, "notes": notes}

    return jsonify({"updated": ids, "disposition": disposition})


@app.route("/api/gemma-status")
def gemma_status():
    """Quick probe so the UI can show/hide the Gemma badge."""
    return jsonify({"enabled": GEMMA_ENABLED})


@app.route("/api/report/<fmt>/<analysis_id>")
def download_report(fmt, analysis_id):
    report_data = _ANALYSES.get(analysis_id)
    if not report_data:
        abort(404, "Analysis not found or has expired. Re-run the analysis.")

    report_mode = request.args.get("mode", "analyst")
    if report_mode not in report.REPORT_MODES:
        return jsonify({"error": f"mode must be one of {list(report.REPORT_MODES)}"}), 400

    report_data = _apply_triage_to(report_data, analysis_id)
    report_data["analysis_id"] = analysis_id  # for the report cover page

    if fmt == "docx":
        blob = report.generate_docx(report_data, report_mode=report_mode)
        mimetype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        filename = f"security-report-{analysis_id}-{report_mode}.docx"
    elif fmt == "pdf":
        blob = report.generate_pdf(report_data, report_mode=report_mode)
        mimetype = "application/pdf"
        filename = f"security-report-{analysis_id}-{report_mode}.pdf"
    else:
        abort(404, "Unknown report format.")

    return send_file(io.BytesIO(blob), mimetype=mimetype, as_attachment=True, download_name=filename)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # threaded=True: the dev server needs to serve status-polling requests
    # while a background analysis job is running.
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)
