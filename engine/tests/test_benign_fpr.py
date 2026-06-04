"""Benign-corpus + FPR-overlay tests.

Covers:
  * The shipped ``benign.yaml`` loads and passes Payload validation.
  * ``build_fpr_table`` aggregates a synthetic benign-run correctly:
    FPR = 1 − waf_view-bypass, benign-class filter applied, per-waf
    grouping, target filter applied.
  * ``render_ladder_markdown`` gains an FPR table when ``fpr_table`` is
    supplied, and the provenance table grows a second column.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from wafeval.analyzer.ladder import build_fpr_table, render_ladder_markdown
from wafeval.models import VulnClass
from wafeval.payloads.loader import load_corpus


def test_benign_corpus_yaml_loads():
    payloads = load_corpus(classes=[VulnClass.BENIGN])
    assert len(payloads) >= 10, (
        "ship at least ten benign entries so the per-step denominator is "
        "usable (Wilson CI below ±0.3 at N=10)"
    )
    for p in payloads:
        assert p.vuln_class is VulnClass.BENIGN
        assert p.id.startswith("benign-"), f"id {p.id!r} breaks the benign- prefix convention"


def _write_verdict(
    raw_root: Path, run_id: str, waf: str, target: str, vuln_class: str,
    verdict: str, payload_id: str = "p", variant: str = "v",
    mutator: str = "noop",
) -> None:
    p = raw_root / run_id / waf / target
    p.mkdir(parents=True, exist_ok=True)
    (p / f"{payload_id}__{variant}.json").write_text(json.dumps({
        "run_id": run_id,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "waf": waf, "target": target,
        "payload_id": payload_id, "vuln_class": vuln_class,
        "variant": variant, "mutator": mutator,
        "complexity_rank": 0, "mutated_body": "x",
        "verdict": verdict,
        "baseline": {
            "route": f"baseline-{target}.local", "status_code": 200,
            "response_ms": 1.0, "response_bytes": 1,
            "response_snippet": "ok", "error": None, "notes": None,
        },
        "waf_route": {
            "route": f"{waf}-{target}.local",
            "status_code": 200 if verdict == "allowed" else 403,
            "response_ms": 1.0, "response_bytes": 1,
            "response_snippet": "ok" if verdict == "allowed" else "blocked",
            "error": None, "notes": None,
        },
        "notes": None,
    }))


def test_build_fpr_table_inverts_bypass_rate(tmp_path: Path):
    raw = tmp_path / "raw"
    run_id = "benign-pl1-test"
    # Modsec: 7 allowed, 3 blocked  → FPR 3/10 = 0.3.
    for i in range(7):
        _write_verdict(raw, run_id, "modsec-ph", "dvwa", "benign", "allowed",
                       payload_id=f"b{i}", variant="v")
    for i in range(3):
        _write_verdict(raw, run_id, "modsec-ph", "dvwa", "benign", "blocked",
                       payload_id=f"bb{i}", variant="v")
    # A non-benign verdict on the same run must be ignored.
    _write_verdict(raw, run_id, "modsec-ph", "dvwa", "sqli", "blocked",
                   payload_id="s1", variant="v")
    # Baseline routes must be excluded (not a WAF).
    _write_verdict(raw, run_id, "baseline", "dvwa", "benign", "allowed",
                   payload_id="bp", variant="v")

    fpr = build_fpr_table(raw, [("pl1", run_id)], target="dvwa")
    assert len(fpr) == 1
    row = fpr.iloc[0]
    assert row["waf"] == "modsec-ph"
    assert row["step"] == "pl1"
    assert row["n"] == 10
    assert abs(row["fpr"] - 0.3) < 1e-9
    # Wilson CI must bracket the point, and flipping preserves the interval.
    assert row["fpr_ci_lo"] < row["fpr"] < row["fpr_ci_hi"]


def test_build_fpr_table_filters_by_target(tmp_path: Path):
    raw = tmp_path / "raw"
    run_id = "benign-multi-target"
    # DVWA modsec-ph: 0 blocked out of 5 → FPR 0.
    for i in range(5):
        _write_verdict(raw, run_id, "modsec-ph", "dvwa", "benign", "allowed",
                       payload_id=f"d{i}", variant="v")
    # Juice Shop modsec-ph: 5 blocked out of 5 → FPR 1.0.
    for i in range(5):
        _write_verdict(raw, run_id, "modsec-ph", "juiceshop", "benign", "blocked",
                       payload_id=f"j{i}", variant="v")

    on_dvwa = build_fpr_table(raw, [("pl1", run_id)], target="dvwa")
    on_js = build_fpr_table(raw, [("pl1", run_id)], target="juiceshop")
    assert on_dvwa.iloc[0]["fpr"] == 0.0
    assert on_js.iloc[0]["fpr"] == 1.0


def test_render_ladder_markdown_includes_fpr_section(tmp_path: Path):
    # Hand-build the smallest plausible bypass-ladder table.
    bypass_table = pd.DataFrame([{
        "step": "pl1", "waf": "modsec-ph", "mutator": "lexical",
        "rate": 0.10, "ci_lo": 0.05, "ci_hi": 0.15,
        "n": 100, "k": 10, "target": "dvwa", "lens": "waf_view",
    }])
    fpr_table = pd.DataFrame([{
        "step": "pl1", "waf": "modsec-ph",
        "fpr": 0.20, "fpr_ci_lo": 0.10, "fpr_ci_hi": 0.30,
        "n": 50, "k": 40, "target": "dvwa",
    }])
    out = tmp_path / "report-ladder.md"
    render_ladder_markdown(
        bypass_table,
        steps=[("pl1", "attack-run-id")],
        out_path=out,
        figures=[],
        title="Test ladder",
        fpr_table=fpr_table,
        fpr_steps=[("pl1", "benign-run-id")],
    )
    text = out.read_text()
    # Provenance table now carries both run_id columns.
    assert "Attack run_id" in text
    assert "FPR run_id" in text
    assert "attack-run-id" in text
    assert "benign-run-id" in text
    # Dedicated FPR section with the percentage rendered.
    assert "False-positive rate" in text
    assert "20.0%" in text
