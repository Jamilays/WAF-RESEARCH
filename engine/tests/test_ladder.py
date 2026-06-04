"""Ladder / ordered-ablation analyzer tests.

Seeds three tiny runs representing (openappsec @ critical / high / medium)
and verifies:

  1. build_ladder_table produces one row per (step, waf, mutator)
  2. render_ladder_chart writes PNG + SVG without matplotlib errors
  3. render_ladder_markdown emits provenance + per-WAF tables + figure refs
  4. Rate ordering within a mutator matches the synthetic gradient
     (higher "looseness" step → more bypasses)
"""
from __future__ import annotations

import json
from pathlib import Path

from wafeval.analyzer.ladder import (
    build_ladder_table,
    render_ladder_chart,
    render_ladder_markdown,
)


def _write_record(base: Path, run_id: str, waf: str, target: str,
                  payload_id: str, variant: str, verdict: str,
                  mutator: str = "lexical", vuln_class: str = "sqli",
                  complexity_rank: int = 1) -> None:
    p = base / run_id / waf / target
    p.mkdir(parents=True, exist_ok=True)
    rec = {
        "run_id": run_id,
        "timestamp": "2026-04-21T00:00:00+00:00",
        "waf": waf, "target": target,
        "payload_id": payload_id, "vuln_class": vuln_class,
        "variant": variant, "mutator": mutator,
        "complexity_rank": complexity_rank,
        "mutated_body": f"{payload_id}::{variant}",
        "verdict": verdict,
        "baseline": {"route": f"baseline-{target}.local", "status_code": 200,
                     "response_ms": 5.0, "response_bytes": 42,
                     "response_snippet": "ok", "error": None, "notes": None},
        "waf_route": {"route": f"{waf}-{target}.local",
                      "status_code": 403 if verdict == "blocked" else 200,
                      "response_ms": 7.0, "response_bytes": 12,
                      "response_snippet": "", "error": None, "notes": None},
        "notes": None,
    }
    (p / f"{payload_id}__{variant}.json").write_text(json.dumps(rec))


def _seed_ladder(raw: Path) -> list[tuple[str, str]]:
    """Three runs with a monotone gradient: critical blocks everything,
    medium lets half through, high in between. Makes the ladder chart's
    slope visible without needing hundreds of datapoints."""
    steps = [
        ("critical", "20260421T160000Z_critical"),
        ("high",     "20260421T160500Z_high"),
        ("medium",   "20260421T161000Z_medium"),
    ]
    # Verdict mix per step: allowed_count (blocked = 20 - allowed)
    gradient = {"critical": 0, "high": 5, "medium": 10}

    for label, run_id in steps:
        allowed = gradient[label]
        for mutator in ("lexical", "encoding"):
            for i in range(20):
                verdict = "allowed" if i < allowed else "blocked"
                # variant name threads the mutator so (payload_id, variant)
                # stays unique — otherwise lexical and encoding writes
                # collide on the same JSON filename.
                _write_record(raw, run_id, "openappsec", "juiceshop",
                              f"sqli-{i:03d}", f"{mutator}_case_0", verdict,
                              mutator=mutator)
            _write_record(raw, run_id, "baseline", "juiceshop",
                          "sqli-001", f"{mutator}_case_0", "allowed",
                          mutator=mutator)
        (raw / run_id / "manifest.json").write_text(json.dumps({
            "run_id": run_id, "mutators": ["lexical", "encoding"],
            "classes": ["sqli"], "totals": {},
        }))
    return steps


def test_build_ladder_table_rows(tmp_path):
    raw = tmp_path / "raw"
    steps = _seed_ladder(raw)
    table = build_ladder_table(raw, steps, target="juiceshop")
    assert not table.empty
    # 3 steps × 1 waf × 2 mutators = 6 rows
    assert len(table) == 6
    # gradient check: encoding rate should climb critical → high → medium
    crit = float(table[(table["step"] == "critical") &
                       (table["mutator"] == "encoding")].iloc[0]["rate"])
    med  = float(table[(table["step"] == "medium") &
                       (table["mutator"] == "encoding")].iloc[0]["rate"])
    assert crit < med


def test_render_ladder_chart_writes_figures(tmp_path):
    raw = tmp_path / "raw"
    steps = _seed_ladder(raw)
    table = build_ladder_table(raw, steps, target="juiceshop")
    out = tmp_path / "figs"
    paths = render_ladder_chart(table, steps, out, stem="ladder",
                                title="open-appsec min-confidence ladder")
    assert len(paths) == 2
    assert any(p.suffix == ".png" for p in paths)
    assert any(p.suffix == ".svg" for p in paths)
    for p in paths:
        assert p.stat().st_size > 0


def test_render_ladder_markdown_has_provenance_and_tables(tmp_path):
    raw = tmp_path / "raw"
    steps = _seed_ladder(raw)
    table = build_ladder_table(raw, steps, target="juiceshop")
    md_path = tmp_path / "out" / "report-ladder.md"
    render_ladder_markdown(table, steps, md_path, figures=[], title="t")
    text = md_path.read_text()
    assert "## Provenance" in text
    for label, run_id in steps:
        assert label in text
        assert run_id in text
    # Per-WAF table
    assert "openappsec" in text
    # Gradient rendered (critical 0%, medium 50%) — look for the right cells
    assert "0.0%" in text
    assert "50.0%" in text


def test_build_ladder_empty_when_target_missing(tmp_path):
    raw = tmp_path / "raw"
    steps = _seed_ladder(raw)
    table = build_ladder_table(raw, steps, target="dvwa")  # seeded juiceshop only
    assert table.empty
