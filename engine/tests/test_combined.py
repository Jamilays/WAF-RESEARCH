"""Cross-run aggregator + combined reporter + combined API endpoint tests.

Seeds a tiny three-run results/raw tree where each run owns a different set
of WAFs, then verifies:

  1. ``combine_runs`` returns the union of WAFs with last-in-list provenance
  2. A WAF that appears in two runs is sourced from the later run only
  3. The combined Markdown reporter emits a headline table listing every WAF
  4. The combined LaTeX reporter emits a valid tabular with the same WAFs
  5. ``GET /runs/combined`` returns the expected waf_provenance mapping
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from wafeval.analyzer.combined import combine_runs
from wafeval.api.app import build_app
from wafeval.reporter import render_combined_latex, render_combined_markdown


def _write_record(base: Path, run_id: str, waf: str, target: str,
                  payload_id: str, variant: str, verdict: str,
                  mutator: str = "lexical", vuln_class: str = "sqli",
                  complexity_rank: int = 1) -> None:
    p = base / run_id / waf / target
    p.mkdir(parents=True, exist_ok=True)
    rec = {
        "run_id": run_id,
        "timestamp": "2026-04-21T00:00:00+00:00",
        "waf": waf,
        "target": target,
        "payload_id": payload_id,
        "vuln_class": vuln_class,
        "variant": variant,
        "mutator": mutator,
        "complexity_rank": complexity_rank,
        "mutated_body": f"{payload_id}::{variant}",
        "verdict": verdict,
        "baseline": {
            "route": f"baseline-{target}.local",
            "status_code": 200, "response_ms": 5.0,
            "response_bytes": 42, "response_snippet": "ok",
            "error": None, "notes": None,
        },
        "waf_route": {
            "route": f"{waf}-{target}.local",
            "status_code": 403 if verdict == "blocked" else 200,
            "response_ms": 7.0,
            "response_bytes": 12, "response_snippet": "",
            "error": None, "notes": None,
        },
        "notes": None,
    }
    (p / f"{payload_id}__{variant}.json").write_text(json.dumps(rec))


def _seed(raw: Path) -> tuple[str, str, str]:
    """Three runs, each contributing different WAFs (mirrors the real
    research / paranoia-high / openappsec split)."""
    run_a = "20260421T140000Z_research"      # modsec, coraza, shadowd
    run_b = "20260421T150000Z_paranoia"      # modsec-ph, coraza-ph
    run_c = "20260421T160000Z_openappsec"    # openappsec

    for waf in ("baseline", "modsec", "coraza", "shadowd"):
        for i in range(6):
            verdict = "allowed" if (waf == "baseline" or (waf == "shadowd" and i < 3)) else "blocked"
            _write_record(raw, run_a, waf, "dvwa", f"sqli-{i:03d}", "case_0", verdict)

    for waf in ("baseline", "modsec-ph", "coraza-ph"):
        for i in range(6):
            verdict = "allowed" if waf == "baseline" else "blocked"
            _write_record(raw, run_b, waf, "dvwa", f"sqli-{i:03d}", "case_0", verdict)

    for waf in ("baseline", "openappsec"):
        for i in range(6):
            verdict = "allowed" if waf == "baseline" else "blocked"
            _write_record(raw, run_c, waf, "dvwa", f"sqli-{i:03d}", "case_0", verdict)

    for rid, wafs in ((run_a, "modsec,coraza,shadowd"),
                      (run_b, "modsec-ph,coraza-ph"),
                      (run_c, "openappsec")):
        (raw / rid / "manifest.json").write_text(json.dumps({
            "run_id": rid,
            "started_at": "2026-04-21T00:00:00+00:00",
            "mutators": ["lexical"],
            "classes": ["sqli"],
            "totals": {"datapoints": 0, "allowed": 0, "blocked": 0},
            "wafs": wafs,
        }))
    return run_a, run_b, run_c


def test_combine_runs_union(tmp_path):
    raw = tmp_path / "raw"
    a, b, c = _seed(raw)
    df, provenance = combine_runs(raw, [a, b, c])
    assert not df.empty
    assert set(provenance) == {"baseline", "modsec", "coraza", "shadowd",
                               "modsec-ph", "coraza-ph", "openappsec"}
    # Baseline appears in all three runs → the *last* one wins.
    assert provenance["baseline"] == c
    # Each unique WAF's rows should be sourced only from its owning run.
    for waf, source_run in provenance.items():
        rows = df[df["waf"] == waf]
        assert (rows["run_id"] == source_run).all(), (
            f"{waf} rows came from {rows['run_id'].unique().tolist()}, expected {source_run}"
        )


def test_combine_runs_overlap_last_wins(tmp_path):
    """If modsec appears in runs a AND b, b's rows must win."""
    raw = tmp_path / "raw"
    a, _, _ = _seed(raw)
    # Inject a modsec row into run_b as well — make sure it wins.
    b = "20260421T150000Z_paranoia"
    _write_record(raw, b, "modsec", "dvwa", "sqli-999", "case_0", "allowed")
    df, provenance = combine_runs(raw, [a, b])
    assert provenance["modsec"] == b
    modsec_rows = df[df["waf"] == "modsec"]
    assert (modsec_rows["run_id"] == b).all()
    # The a-provenance rows must be dropped.
    assert "sqli-999" in modsec_rows["payload_id"].values


def test_combine_runs_empty_list(tmp_path):
    df, provenance = combine_runs(tmp_path / "raw", [])
    assert df.empty
    assert provenance == {}


def test_combine_runs_skips_missing(tmp_path):
    raw = tmp_path / "raw"
    a, _, _ = _seed(raw)
    df, provenance = combine_runs(raw, ["does-not-exist", a])
    assert not df.empty
    assert "modsec" in provenance


def test_combined_markdown_renders(tmp_path):
    raw = tmp_path / "raw"
    a, b, c = _seed(raw)
    df, provenance = combine_runs(raw, [a, b, c])
    out = tmp_path / "report-combined.md"
    render_combined_markdown(df, provenance, out, run_ids=[a, b, c])
    text = out.read_text()
    assert "combined report" in text.lower()
    # Every WAF label should appear in the provenance table.
    for waf in ("modsec", "coraza", "shadowd", "openappsec", "modsec-ph", "coraza-ph"):
        assert waf in text, f"expected {waf} in combined report"
    # Headline Table 1 header row.
    assert "Mutator" in text
    # Bibliography carries over from _data.BIBLIOGRAPHY.
    assert "Bibliography" in text


def test_combined_latex_renders(tmp_path):
    raw = tmp_path / "raw"
    a, b, c = _seed(raw)
    df, provenance = combine_runs(raw, [a, b, c])
    out = tmp_path / "report-combined.tex"
    render_combined_latex(df, provenance, out, run_ids=[a, b, c])
    text = out.read_text()
    assert r"\documentclass[conference]{IEEEtran}" in text
    assert r"\label{tab:combined}" in text
    assert "openappsec" in text
    # Paranoia-high columns carry the escaped underscore (coraza-ph) and
    # appear in the tabular.
    assert "modsec-ph" in text
    assert "coraza-ph" in text


def test_combined_markdown_empty_run_ids(tmp_path):
    out = tmp_path / "report-combined.md"
    import pandas as pd
    render_combined_markdown(pd.DataFrame(), {}, out, run_ids=[])
    text = out.read_text()
    assert "combined report" in text.lower()


@pytest.fixture
def api_seeded(tmp_path, monkeypatch):
    raw = tmp_path / "raw"
    monkeypatch.setenv("RESULTS_RAW_DIR", str(raw))
    monkeypatch.setenv("RESULTS_PROCESSED_DIR", str(tmp_path / "processed"))
    monkeypatch.setenv("RESULTS_FIGURES_DIR", str(tmp_path / "figures"))
    monkeypatch.setenv("RESULTS_REPORTS_DIR", str(tmp_path / "reports"))
    runs = _seed(raw)
    # Invalidate any leaked store cache from other tests sharing tmp_path order.
    from wafeval.api import store
    store._df_cache.clear()
    return runs


def test_api_combined_endpoint(api_seeded):
    a, b, c = api_seeded
    client = TestClient(build_app())
    r = client.get("/runs/combined", params={"ids": ",".join([a, b, c])})
    assert r.status_code == 200
    body = r.json()
    assert body["run_ids"] == [a, b, c]
    # All 6 non-baseline WAFs must be present.
    assert set(body["wafs"]) == {"modsec", "coraza", "shadowd", "openappsec",
                                 "modsec-ph", "coraza-ph"}
    # Provenance mapping must cover every WAF (baseline included).
    assert body["waf_provenance"]["openappsec"] == c
    assert body["waf_provenance"]["baseline"] == c  # last-in-list wins
    assert body["waf_provenance"]["modsec"] == a
    # Rate rows exist with the expected lens tags.
    lenses = {row["lens"] for row in body["rows"]}
    assert "true_bypass" in lenses


def test_api_combined_rejects_empty_ids(api_seeded):
    client = TestClient(build_app())
    r = client.get("/runs/combined", params={"ids": ",,"})
    assert r.status_code == 400


def test_api_combined_ignores_missing_ids(api_seeded):
    a, _, _ = api_seeded
    client = TestClient(build_app())
    r = client.get("/runs/combined", params={"ids": f"nonexistent,{a}"})
    assert r.status_code == 200
    assert "modsec" in r.json()["waf_provenance"]
