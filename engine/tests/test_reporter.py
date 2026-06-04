"""Reporter smoke tests — Markdown & LaTeX render without exceptions on a
minimal synthetic DataFrame, and the result contains the Table 1 structure
and bibliography entries."""
from __future__ import annotations

from pathlib import Path

import pandas as pd

from wafeval.reporter import render_latex, render_markdown


def _df() -> pd.DataFrame:
    rows = []
    # 10 variants per (waf, mutator) on DVWA — 4 allowed, 6 blocked for modsec;
    # all allowed for coraza. Gives us a non-degenerate table.
    for i in range(10):
        rows.append({
            "run_id": "r1", "waf": "modsec", "target": "dvwa",
            "payload_id": f"p{i}", "vuln_class": "sqli",
            "mutator": "lexical", "variant": f"v{i}", "complexity_rank": 1,
            "verdict": "allowed" if i < 4 else "blocked",
            "baseline_status": 200, "baseline_ms": 1.0, "baseline_triggered": True,
            "waf_status": 200 if i < 4 else 403, "waf_ms": 1.0,
            "mutated_body": "x", "notes": None,
        })
    for i in range(10):
        rows.append({**rows[0], "waf": "coraza", "verdict": "allowed",
                     "payload_id": f"p{i}", "variant": f"v{i}"})
    return pd.DataFrame(rows)


def test_markdown_renders(tmp_path: Path):
    out = tmp_path / "report.md"
    render_markdown(
        _df(), out, run_id="r1", figures=[],
        manifest={"totals": {"datapoints": 20, "allowed": 14, "blocked": 6},
                  "mutators": ["lexical"], "classes": ["sqli"]},
    )
    text = out.read_text()
    assert "# WAF Evasion Lab" in text
    assert "Table 1" in text or "true-bypass" in text
    assert "lexical" in text
    assert "Bibliography" in text


def test_latex_renders(tmp_path: Path):
    out = tmp_path / "report.tex"
    render_latex(
        _df(), out, run_id="r1", figures=[],
        manifest={"totals": {"datapoints": 20}, "mutators": ["lexical"], "classes": ["sqli"]},
    )
    text = out.read_text()
    assert r"\documentclass[conference]{IEEEtran}" in text
    assert r"\begin{thebibliography}" in text
    assert r"\bibitem{yusifova2024}" in text


def test_markdown_handles_empty_df(tmp_path: Path):
    out = tmp_path / "report.md"
    render_markdown(
        pd.DataFrame(columns=[
            "run_id", "waf", "target", "payload_id", "vuln_class", "mutator",
            "variant", "complexity_rank", "verdict", "baseline_triggered",
        ]),
        out, run_id="empty", figures=[],
    )
    assert out.exists()
    assert "empty" in out.read_text()
