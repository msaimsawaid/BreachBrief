#!/usr/bin/env python3
"""
PHASE 0 — REGRESSION HARNESS (your own real data)

The bundled test suite (tests/test_regression_synthetic.py) only covers
the safe-to-ship synthetic incident. It can't catch a regression that only
shows up on YOUR real alert corpus's specific shape — the burst-grouping
bug in an earlier version, for example, only surfaced once tested against
real Wazuh exports. This script lets you build that safety net yourself,
locally, without your data ever being bundled into this repo or leaving
your machine.

Usage:

    # 1. Generate a baseline snapshot from your current (known-good) engine,
    #    against your own real files:
    python3 tools/baseline.py snapshot \
        --files /path/to/ossec-alerts-*.json \
        --out my_baseline.json

    # 2. After changing core/ code, re-run and compare:
    python3 tools/baseline.py check \
        --files /path/to/ossec-alerts-*.json \
        --baseline my_baseline.json

check exits non-zero and prints every field that moved beyond its
tolerance — group count, event-type distribution, top-10 risk ranking,
disposition counts. Tune tolerances with --tolerance-pct (default 10%).

Keep my_baseline.json and your alert files OUTSIDE this repo (e.g. in a
sibling directory, or add them to your own .gitignore) — they contain
your real environment's data and should never be committed alongside the
tool itself.
"""
from __future__ import annotations
import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import pipeline  # noqa: E402


def _load_files(patterns: list[str]) -> list[tuple[str, bytes]]:
    payload = []
    for pattern in patterns:
        matches = glob.glob(pattern)
        if not matches:
            print(f"WARNING: no files matched '{pattern}'", file=sys.stderr)
        for path in matches:
            with open(path, "rb") as f:
                payload.append((os.path.basename(path), f.read()))
    if not payload:
        print("ERROR: no input files found.", file=sys.stderr)
        sys.exit(2)
    return payload


def _summarize(data: dict) -> dict:
    """A compact, comparable summary — not the full report_data (which
    holds datetimes and internal-only fields not meant for a stored
    snapshot)."""
    groups = data["aggregated_events"]
    by_type = {}
    for g in groups:
        by_type[g["event_type"]] = by_type.get(g["event_type"], 0) + 1

    top10 = sorted(groups, key=lambda g: -g["risk_score"])[:10]

    return {
        "stats": {
            "total_raw_events": data["stats"]["total_raw_events"],
            "total_aggregated_events": data["stats"]["total_aggregated_events"],
            "high_risk_count": data["stats"]["high_risk_count"],
            "medium_risk_count": data["stats"]["medium_risk_count"],
            "low_risk_count": data["stats"]["low_risk_count"],
            "possible_false_positive_count": data["stats"]["possible_false_positive_count"],
            "unique_source_ips": data["stats"]["unique_source_ips"],
            "disposition_counts": data["stats"]["disposition_counts"],
        },
        "group_count_by_event_type": by_type,
        "top10_by_risk": [
            {"event_type": g["event_type"], "source_ip": g["source_ip"],
             "risk_score": g["risk_score"], "risk_level": g["risk_level"],
             "confidence": g["confidence"]}
            for g in top10
        ],
    }


def cmd_snapshot(args):
    payload = _load_files(args.files)
    data = pipeline.run_pipeline(payload, window_minutes=5)
    summary = _summarize(data)
    with open(args.out, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Baseline written to {args.out}")
    print(f"  {summary['stats']['total_raw_events']} raw events -> "
          f"{summary['stats']['total_aggregated_events']} groups")
    print(f"  Top finding: {summary['top10_by_risk'][0]['event_type']} "
          f"(risk {summary['top10_by_risk'][0]['risk_score']})" if summary["top10_by_risk"] else "  No groups.")


def _pct_diff(old, new) -> float:
    if old == 0:
        return 0.0 if new == 0 else 100.0
    return abs(new - old) / abs(old) * 100.0


def cmd_check(args):
    with open(args.baseline) as f:
        baseline = json.load(f)

    payload = _load_files(args.files)
    data = pipeline.run_pipeline(payload, window_minutes=5)
    current = _summarize(data)

    problems = []

    # --- stats drift ---
    for key, old_val in baseline["stats"].items():
        if key == "disposition_counts":
            continue
        new_val = current["stats"].get(key)
        if isinstance(old_val, (int, float)):
            drift = _pct_diff(old_val, new_val)
            if drift > args.tolerance_pct:
                problems.append(f"stats.{key}: {old_val} -> {new_val} ({drift:.0f}% drift, tolerance {args.tolerance_pct}%)")

    # --- group count per event type: flag types that disappeared or
    # newly dominate ---
    old_types = baseline["group_count_by_event_type"]
    new_types = current["group_count_by_event_type"]
    for t, old_c in old_types.items():
        new_c = new_types.get(t, 0)
        drift = _pct_diff(old_c, new_c)
        if drift > args.tolerance_pct:
            problems.append(f"event_type '{t}' group count: {old_c} -> {new_c} ({drift:.0f}% drift)")
    for t in new_types:
        if t not in old_types:
            problems.append(f"event_type '{t}' is NEW (not in baseline) — {new_types[t]} group(s)")

    # --- top finding identity: the #1 risk-ranked finding's event_type
    # shouldn't silently change (this is exactly what the v1->v4 risk
    # model rewrite was designed to fix — a regression back to frequency-
    # dominance would show up here first) ---
    old_top = baseline["top10_by_risk"][0]["event_type"] if baseline["top10_by_risk"] else None
    new_top = current["top10_by_risk"][0]["event_type"] if current["top10_by_risk"] else None
    if old_top != new_top:
        problems.append(f"TOP-RANKED finding changed: '{old_top}' -> '{new_top}' — investigate before accepting")

    if problems:
        print(f"REGRESSION CHECK FAILED — {len(problems)} issue(s):\n")
        for p in problems:
            print(f"  - {p}")
        sys.exit(1)
    else:
        print(f"OK — no drift beyond {args.tolerance_pct}% tolerance across "
              f"{current['stats']['total_aggregated_events']} groups.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_snap = sub.add_parser("snapshot", help="Generate a baseline from your current engine + real data.")
    p_snap.add_argument("--files", nargs="+", required=True, help="Glob pattern(s) for input files.")
    p_snap.add_argument("--out", required=True, help="Path to write the baseline JSON.")
    p_snap.set_defaults(func=cmd_snapshot)

    p_check = sub.add_parser("check", help="Compare current engine output against a saved baseline.")
    p_check.add_argument("--files", nargs="+", required=True, help="Glob pattern(s) for input files (same as snapshot).")
    p_check.add_argument("--baseline", required=True, help="Path to the baseline JSON from `snapshot`.")
    p_check.add_argument("--tolerance-pct", type=float, default=10.0, help="Allowed drift percentage before flagging (default 10).")
    p_check.set_defaults(func=cmd_check)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
