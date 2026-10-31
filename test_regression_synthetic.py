"""
PHASE 0 — REGRESSION HARNESS (synthetic fixture)

This is the baseline that must NEVER silently change. The synthetic
incident in sample_data/ (nmap -> SSH brute force -> SQLi -> priv-esc ->
persistence -> exfiltration, across two files) has known-correct behavior
that was hand-verified during development. If a future change to
correlate.py/risk.py/normalize.py/mapping.py breaks one of these
assertions, that's a regression to investigate BEFORE shipping — not
something to "fix" by loosening the test.

This intentionally does NOT use the user's real Wazuh data as a fixture —
that's sensitive organizational data and doesn't belong bundled into this
repository. See tools/baseline.py for a snapshot/diff tool the user runs
locally against their own real files to catch regressions on their actual
dataset, without that data ever leaving their machine or being checked in
here.

Run with: pytest tests/test_regression_synthetic.py -v
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import pipeline

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_data")


def _run():
    with open(os.path.join(SAMPLE_DIR, "sample_alerts.json"), "rb") as f:
        alerts = f.read()
    with open(os.path.join(SAMPLE_DIR, "sample.log"), "rb") as f:
        log = f.read()
    return pipeline.run_pipeline([("sample_alerts.json", alerts), ("sample.log", log)])


def test_group_count_is_stable():
    """The synthetic incident's 16 raw events must always correlate into
    exactly 9 groups. A change here means the grouping key logic changed —
    verify it was intentional (see core/correlate.py) before accepting."""
    data = _run()
    assert data["stats"]["total_aggregated_events"] == 9
    assert data["stats"]["total_raw_events"] == 16


def test_expected_event_types_present():
    data = _run()
    types = {g["event_type"] for g in data["aggregated_events"]}
    expected = {
        "Nmap Scan", "SSH Brute Force", "SQL Injection", "Privilege Escalation",
        "Persistence Mechanism", "Data Exfiltration", "Firewall Block", "Successful Login",
    }
    assert expected.issubset(types), f"Missing expected types: {expected - types}"


def test_rare_severe_finding_outranks_routine_ones():
    """The core claim of the v4 risk model: a single Critical-severity
    Data Exfiltration event must rank #1 overall, ahead of everything
    else — including higher-COUNT but lower-severity findings. If this
    ever fails, the risk model has regressed toward the v1 failure mode
    (frequency dominating severity) — see core/risk.py docstring."""
    data = _run()
    ranked = sorted(data["aggregated_events"], key=lambda g: -g["risk_score"])
    assert ranked[0]["event_type"] == "Data Exfiltration"
    assert ranked[0]["risk_level"] == "High"


def test_identity_driven_grouping_uses_real_ip():
    """Attack-relevant events with a genuine attacker IP must be grouped
    as identity-driven (is_identity_driven=True) and carry that IP."""
    data = _run()
    ssh = [g for g in data["aggregated_events"] if g["event_type"] == "SSH Brute Force"]
    assert len(ssh) >= 1
    for g in ssh:
        assert g["is_identity_driven"] is True
        assert g["source_ip"] not in (None, "unknown")


def test_every_group_has_confidence_and_reasoning():
    """Phase 1/2 contract: every group must carry confidence (0-100),
    a risk_level, and a populated reasoning dict with all four sections."""
    data = _run()
    for g in data["aggregated_events"]:
        assert 0 <= g["confidence"] <= 100
        assert g["risk_level"] in ("Low", "Medium", "High")
        assert g["reasoning"] is not None
        for key in ("evidence_bullets", "reasoning_text", "confidence_breakdown",
                    "observed", "derived", "inferred", "not_observed"):
            assert key in g["reasoning"]


def test_confidence_breakdown_sums_to_confidence():
    """The confidence-basis breakdown shown to an analyst must be the
    ACTUAL terms that were summed (see risk.compute_confidence) — not a
    separately invented explanation that could drift out of sync."""
    data = _run()
    for g in data["aggregated_events"]:
        total = sum(item["points"] for item in g["confidence_breakdown"])
        clipped = max(5.0, min(99.0, total))
        assert abs(clipped - g["confidence"]) < 0.01, (
            f"{g['event_type']}: breakdown sums to {clipped}, confidence field says {g['confidence']}"
        )


def test_no_group_missing_required_fields():
    """Catches accidental removal of a field some downstream consumer
    (report.py, app.py serialization) depends on."""
    data = _run()
    required = {
        "group_id", "event_type", "count", "severity", "confidence",
        "risk_score", "risk_level", "priority", "auto_disposition", "mapping",
    }
    for g in data["aggregated_events"]:
        missing = required - set(g.keys())
        assert not missing, f"{g['event_type']} missing fields: {missing}"


def test_reports_generate_without_error():
    """All four report modes, both formats, must generate without
    exceptions and produce non-trivial output."""
    from core import report
    data = _run()
    for mode in ("analyst", "executive", "soc", "forensic"):
        docx = report.generate_docx(data, report_mode=mode)
        pdf = report.generate_pdf(data, report_mode=mode)
        assert len(docx) > 5000, f"{mode} docx suspiciously small"
        assert len(pdf) > 1000, f"{mode} pdf suspiciously small"


if __name__ == "__main__":
    # allow `python3 tests/test_regression_synthetic.py` without pytest installed
    import traceback
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
        except Exception:
            failed += 1
            print(f"ERROR {t.__name__}:")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
