"""Unit tests for the latency analyzer.

Third leg of TODO.md #2 (response-side fingerprinting). The helper feeds
the reporter's Appendix B and answers "is this WAF slow on the long
tail?" independent of whether it blocked. Tests cover: basic percentile
math, exclusion of error / baseline_fail rows, NaN handling, empty-
input shape, and the markdown renderer's empty-state.
"""
from __future__ import annotations

import pandas as pd

from wafeval.analyzer.latency import latency_stats, render_markdown_table


def _row(waf: str, target: str, waf_ms: float | None, verdict: str = "allowed") -> dict:
    return {
        "run_id": "r", "waf": waf, "target": target,
        "payload_id": "p", "vuln_class": "sqli",
        "mutator": "lexical", "variant": "v", "complexity_rank": 1,
        "verdict": verdict,
        "baseline_status": 200, "baseline_ms": 5.0, "baseline_triggered": True,
        "waf_status": 200, "waf_ms": waf_ms,
        "mutated_body": "x", "notes": None,
    }


def test_percentiles_on_uniform_sample():
    # 1..100 → p50=50.5, p95=95.05, p99=99.01 under linear interpolation.
    df = pd.DataFrame([_row("modsec", "dvwa", float(i)) for i in range(1, 101)])
    s = latency_stats(df, groupby=["waf", "target"])
    assert len(s) == 1
    row = s.iloc[0]
    assert row["waf"] == "modsec" and row["target"] == "dvwa"
    assert row["n"] == 100
    assert abs(row["p50"] - 50.5) < 1e-9
    assert abs(row["p95"] - 95.05) < 1e-9
    assert abs(row["p99"] - 99.01) < 1e-9


def test_excludes_error_and_baseline_fail_rows():
    # Errors / baseline_fails don't reflect real WAF roundtrip cost — they
    # must not pull the tail around.
    df = pd.DataFrame([
        _row("modsec", "dvwa", 10.0, verdict="allowed"),
        _row("modsec", "dvwa", 20.0, verdict="blocked"),
        _row("modsec", "dvwa", 9999.0, verdict="error"),          # excluded
        _row("modsec", "dvwa", 9999.0, verdict="baseline_fail"),  # excluded
    ])
    s = latency_stats(df, groupby=["waf", "target"]).iloc[0]
    assert s["n"] == 2
    assert s["p99"] <= 20.0  # the 9999 tail must be gone


def test_nan_latency_rows_dropped():
    df = pd.DataFrame([
        _row("coraza", "dvwa", 5.0),
        _row("coraza", "dvwa", None),
        _row("coraza", "dvwa", 15.0),
    ])
    s = latency_stats(df, groupby=["waf", "target"]).iloc[0]
    assert s["n"] == 2


def test_groups_independently_per_waf_target():
    df = pd.DataFrame([
        _row("modsec", "dvwa", 10.0),
        _row("modsec", "dvwa", 20.0),
        _row("coraza", "dvwa", 100.0),
        _row("coraza", "dvwa", 200.0),
    ])
    s = latency_stats(df, groupby=["waf", "target"]).set_index(["waf", "target"])
    assert abs(s.loc[("modsec", "dvwa"), "p50"] - 15.0) < 1e-9
    assert abs(s.loc[("coraza", "dvwa"), "p50"] - 150.0) < 1e-9


def test_empty_input_returns_empty_frame_with_expected_columns():
    out = latency_stats(pd.DataFrame(), groupby=["waf", "target"])
    assert list(out.columns) == ["waf", "target", "n", "p50", "p95", "p99"]
    assert len(out) == 0


def test_custom_quantiles_generate_expected_column_names():
    df = pd.DataFrame([_row("modsec", "dvwa", float(i)) for i in range(1, 11)])
    s = latency_stats(df, groupby=["waf"], quantiles=(0.10, 0.90))
    assert list(s.columns) == ["waf", "n", "p10", "p90"]


def test_markdown_renderer_empty_state():
    out = render_markdown_table(pd.DataFrame())
    assert "no latency data" in out


def test_markdown_renderer_formats_percentiles_and_counts():
    df = pd.DataFrame([_row("modsec", "dvwa", float(i)) for i in range(1, 21)])
    md = render_markdown_table(latency_stats(df, groupby=["waf", "target"]))
    lines = md.splitlines()
    assert lines[0].startswith("| waf |")
    assert "p50" in lines[0] and "p99" in lines[0]
    # Data row: p50 ~ 10.5, formatted to 1 decimal; n=20 as an int.
    data = lines[2]
    assert "modsec" in data and "dvwa" in data
    assert "20" in data  # n without decimal
    assert "10.5" in data
