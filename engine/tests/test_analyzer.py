"""Unit tests for the analyzer — aggregator, Wilson CI, lens math, CSV export."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from wafeval.analyzer.aggregate import latest_run_id, load_run
from wafeval.analyzer.bypass import compute_rates, wilson_ci
from wafeval.analyzer.export import write_csvs


# ---------- Wilson CI -------------------------------------------------------


def test_wilson_degenerate_zero_n():
    p, lo, hi = wilson_ci(0, 0)
    assert pd.isna(p) and pd.isna(lo) and pd.isna(hi)


def test_wilson_all_successes():
    p, lo, hi = wilson_ci(10, 10)
    assert p == 1.0
    assert lo < 1.0 and hi == pytest.approx(1.0, abs=1e-9)


def test_wilson_all_failures():
    p, lo, hi = wilson_ci(0, 10)
    assert p == 0.0
    assert lo == pytest.approx(0.0, abs=1e-9) and hi > 0.0


def test_wilson_midpoint_tightens_with_n():
    _, lo1, hi1 = wilson_ci(5, 10)
    _, lo2, hi2 = wilson_ci(500, 1000)
    assert (hi1 - lo1) > (hi2 - lo2), "CI should narrow as n grows"


# ---------- verdict → bypass math ------------------------------------------


def _row(waf: str, mutator: str, verdict: str, target="dvwa", vuln_class="sqli",
         payload_id="p1", variant="v", complexity_rank=1) -> dict:
    return {
        "run_id": "r", "waf": waf, "target": target,
        "payload_id": payload_id, "vuln_class": vuln_class,
        "mutator": mutator, "variant": variant,
        "complexity_rank": complexity_rank, "verdict": verdict,
        "baseline_status": 200, "baseline_ms": 1.0,
        "baseline_triggered": verdict != "baseline_fail",
        "waf_status": 200, "waf_ms": 1.0,
        "mutated_body": "x", "notes": None,
    }


def test_true_bypass_excludes_baseline_fail():
    df = pd.DataFrame([
        _row("modsec", "lexical", "allowed"),
        _row("modsec", "lexical", "blocked"),
        _row("modsec", "lexical", "baseline_fail"),  # should NOT move the rate
    ])
    r = compute_rates(df, ["waf", "mutator"], lens="true_bypass")
    assert len(r) == 1
    row = r.iloc[0]
    assert row["k"] == 1 and row["n"] == 2
    assert abs(row["rate"] - 0.5) < 1e-12


def test_waf_view_excludes_baseline_fail_and_error():
    """Bundle-5 fix: waf_view denominator excludes baseline_fail + error.

    Before: "anything not blocked" counted baseline_fails as bypasses, which
    inflated rates on Juice Shop XSS / DVWA SSTI etc. After: the denominator
    is "requests that actually tested the WAF".
    """
    df = pd.DataFrame([
        _row("modsec", "lexical", "allowed"),
        _row("modsec", "lexical", "blocked"),
        _row("modsec", "lexical", "baseline_fail"),  # excluded
        _row("modsec", "lexical", "error"),          # excluded
    ])
    r = compute_rates(df, ["waf", "mutator"], lens="waf_view").iloc[0]
    assert r["n"] == 2 and r["k"] == 1   # allowed counts; blocked doesn't


def test_blocked_silent_is_waf_win_in_true_bypass_lens():
    """blocked_silent must count in the denominator (WAF win, not a bypass).

    Three datapoints: one bypass, one hard block, one silent sanitise →
    rate = 1 / 3, not 1 / 2 (which would happen if blocked_silent were
    swept into baseline_fail / ignored).
    """
    df = pd.DataFrame([
        _row("modsec", "lexical", "allowed"),
        _row("modsec", "lexical", "blocked"),
        _row("modsec", "lexical", "blocked_silent"),
    ])
    r = compute_rates(df, ["waf", "mutator"], lens="true_bypass").iloc[0]
    assert r["k"] == 1 and r["n"] == 3
    assert abs(r["rate"] - 1.0 / 3) < 1e-12


def test_blocked_silent_subtracts_from_waf_view_numerator():
    """waf_view: denom counts everything that tested the WAF; num excludes
    both hard blocks and silent sanitises."""
    df = pd.DataFrame([
        _row("modsec", "lexical", "allowed"),
        _row("modsec", "lexical", "blocked"),
        _row("modsec", "lexical", "blocked_silent"),
        _row("modsec", "lexical", "baseline_fail"),  # excluded from denom
    ])
    r = compute_rates(df, ["waf", "mutator"], lens="waf_view").iloc[0]
    # denom = 4 - 0 (error) - 1 (baseline_fail) = 3
    # num   = 3 - 1 (blocked) - 1 (blocked_silent) = 1
    assert r["n"] == 3 and r["k"] == 1


def test_compute_rates_empty_input_shape():
    r = compute_rates(pd.DataFrame(), ["waf", "mutator"], lens="true_bypass")
    assert list(r.columns) == ["waf", "mutator", "k", "n", "rate", "ci_lo", "ci_hi", "lens"]
    assert len(r) == 0


# ---------- aggregator IO --------------------------------------------------


def _write_verdict(root: Path, waf: str, target: str, payload_id: str, variant: str,
                   verdict: str, mutator: str = "lexical") -> None:
    p = root / waf / target
    p.mkdir(parents=True, exist_ok=True)
    (p / f"{payload_id}__{variant}.json").write_text(json.dumps({
        "run_id": "r1", "timestamp": "2026-01-01T00:00:00+00:00",
        "waf": waf, "target": target,
        "payload_id": payload_id, "vuln_class": "sqli",
        "variant": variant, "mutator": mutator, "complexity_rank": 1,
        "mutated_body": "x", "verdict": verdict,
        "baseline": {"route": "baseline", "status_code": 200, "response_ms": 1,
                     "response_bytes": 10, "response_snippet": "ok", "error": None, "notes": None},
        "waf_route": {"route": waf, "status_code": 200, "response_ms": 1,
                      "response_bytes": 10, "response_snippet": "ok", "error": None, "notes": None},
    }))


def test_load_run_reads_all_files(tmp_path: Path):
    root = tmp_path / "raw"
    run = root / "r1"
    for waf, verdict in [("baseline", "allowed"), ("modsec", "blocked"), ("coraza", "allowed")]:
        _write_verdict(run, waf, "dvwa", "p1", "v1", verdict)
    (run / "manifest.json").write_text('{"totals":{"datapoints":3}}')
    df = load_run(root, "r1")
    assert len(df) == 3
    assert set(df["verdict"]) == {"allowed", "blocked"}


def test_latest_run_id_picks_newest(tmp_path: Path):
    (tmp_path / "20260101T000000Z_aaaaaaaa").mkdir()
    (tmp_path / "20260201T000000Z_bbbbbbbb").mkdir()
    assert latest_run_id(tmp_path) == "20260201T000000Z_bbbbbbbb"


def test_write_csvs_emits_three_files(tmp_path: Path):
    root = tmp_path / "raw"
    run = root / "r1"
    _write_verdict(run, "modsec", "dvwa", "p1", "v1", "blocked")
    _write_verdict(run, "modsec", "dvwa", "p1", "v2", "allowed")
    _write_verdict(run, "baseline", "dvwa", "p1", "v1", "allowed")
    df = load_run(root, "r1")

    out = tmp_path / "processed"
    paths = write_csvs(df, out)
    assert set(paths) == {"per_variant", "per_payload", "bypass_rates"}
    for p in paths.values():
        assert p.exists() and p.stat().st_size > 0
