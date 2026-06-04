"""Tests for the single-run paranoia ablation pivot."""
from __future__ import annotations

import pandas as pd
import pytest

from wafeval.analyzer.paranoia import build_paranoia_table, render_markdown


def _row(waf: str, mutator: str, verdict: str, target="juiceshop") -> dict:
    return {
        "run_id": "r", "waf": waf, "target": target,
        "payload_id": "p", "vuln_class": "sqli",
        "mutator": mutator, "variant": "v",
        "complexity_rank": 2, "verdict": verdict,
        "baseline_status": 200, "baseline_ms": 1.0,
        "baseline_triggered": verdict != "baseline_fail",
        "waf_status": 200, "waf_ms": 1.0,
        "mutated_body": "x", "notes": None,
    }


def _populate(verdicts: dict[str, list[str]]) -> pd.DataFrame:
    """``verdicts[(waf, mutator)] = [verdict, …]`` → DataFrame the analyzer can read."""
    rows: list[dict] = []
    for (waf, mutator), vs in verdicts.items():
        for v in vs:
            rows.append(_row(waf, mutator, v))
    return pd.DataFrame(rows)


def test_empty_input_returns_empty_frame():
    out = build_paranoia_table(pd.DataFrame())
    assert out.empty
    assert list(out.columns) == ["family", "mutator", "rate_pl1", "rate_pl4",
                                   "delta_pp", "n_pl1", "n_pl4"]


def test_pl4_closing_a_gap_yields_negative_delta():
    """Coraza PL1 leaks 50% on encoding; PL4 closes to 0% → delta = -50pp."""
    df = _populate({
        ("coraza", "encoding"):    ["allowed"] * 5 + ["blocked"] * 5,  # 50% bypass
        ("coraza-ph", "encoding"): ["blocked"] * 10,                    # 0% bypass
    })
    table = build_paranoia_table(df, target="juiceshop")
    coraza = table[table["family"] == "Coraza"].iloc[0]
    assert coraza["rate_pl1"] == pytest.approx(0.5)
    assert coraza["rate_pl4"] == pytest.approx(0.0)
    assert coraza["delta_pp"] == pytest.approx(-50.0)
    assert coraza["n_pl1"] == 10 and coraza["n_pl4"] == 10


def test_modsec_env_var_gotcha_yields_zero_delta():
    """ModSec PL4 doesn't reach JSON-SQL rules; same rate at PL1 and PL4."""
    df = _populate({
        ("modsec", "encoding"):    ["allowed"] * 4 + ["blocked"] * 6,
        ("modsec-ph", "encoding"): ["allowed"] * 4 + ["blocked"] * 6,
    })
    table = build_paranoia_table(df, target="juiceshop")
    modsec = table[table["family"] == "ModSec"].iloc[0]
    assert modsec["rate_pl1"] == pytest.approx(0.4)
    assert modsec["rate_pl4"] == pytest.approx(0.4)
    assert modsec["delta_pp"] == pytest.approx(0.0)


def test_only_one_level_present_keeps_row_with_dash():
    """If PL4 wasn't run for a mutator, the row still appears with rate_pl4=None."""
    df = _populate({
        ("coraza", "structural"): ["allowed", "blocked"],
        # no coraza-ph rows → PL4 column should be None
    })
    table = build_paranoia_table(df, target="juiceshop")
    structural = table[(table["family"] == "Coraza") & (table["mutator"] == "structural")]
    assert len(structural) == 1
    row = structural.iloc[0]
    assert row["rate_pl1"] == pytest.approx(0.5)
    assert row["rate_pl4"] is None
    assert row["delta_pp"] is None


def test_target_filter_restricts_to_anchor():
    """Rows on the wrong target are excluded from the pivot."""
    df = _populate({
        ("coraza", "lexical"):    ["allowed", "blocked"],
        ("coraza-ph", "lexical"): ["blocked", "blocked"],
    })
    # Reassign the second pair to a different target — they must NOT contribute
    # when target=juiceshop.
    other = _populate({
        ("coraza-ph", "lexical"): ["allowed", "allowed"],
    })
    other["target"] = "dvwa"
    df = pd.concat([df, other], ignore_index=True)

    table = build_paranoia_table(df, target="juiceshop")
    pl4 = table[table["family"] == "Coraza"].iloc[0]
    # PL4 should reflect the juiceshop-only rows: 0/2 = 0%, not the dvwa bypasses.
    assert pl4["rate_pl4"] == pytest.approx(0.0)


def test_render_markdown_handles_empty_and_partial():
    assert render_markdown(pd.DataFrame()) == "*(no paranoia-high variants present in this run)*"

    df = _populate({
        ("coraza", "encoding"):    ["allowed"] * 5 + ["blocked"] * 5,
        ("coraza-ph", "encoding"): ["blocked"] * 10,
    })
    md = render_markdown(build_paranoia_table(df, target="juiceshop"))
    assert "| Family |" in md
    assert "Coraza" in md
    # Big delta should be **bolded** in the output.
    assert "**" in md
