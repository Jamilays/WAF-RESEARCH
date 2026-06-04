"""Tests for the deduplicated Hall of Fame mode."""
from __future__ import annotations

import pandas as pd

from wafeval.reporter.hall_of_fame import hall_of_fame


def _row(payload_id: str, variant: str, waf: str, target: str, verdict: str,
         mutator: str = "lexical", vuln_class: str = "sqli") -> dict:
    return {
        "run_id": "r", "waf": waf, "target": target,
        "payload_id": payload_id, "vuln_class": vuln_class,
        "mutator": mutator, "variant": variant,
        "complexity_rank": 1, "verdict": verdict,
        "baseline_status": 200, "baseline_ms": 1.0,
        "baseline_triggered": verdict != "baseline_fail",
        "waf_status": 200 if verdict == "allowed" else 403, "waf_ms": 1.0,
        "mutated_body": f"body_{variant}", "notes": None,
    }


def test_dedup_keeps_only_best_variant_per_payload():
    """Eleven variants of one payload should collapse to one row in dedup mode.

    This is the headline-table fix: the un-deduped Hall of Fame had a single
    payload (`admin'-- -`) crowding rows 2-12 with eleven nearly-identical
    body strings. Dedup keeps the best variant per payload so the gallery is
    diverse instead of a monoculture.
    """
    rows: list[dict] = []
    # Payload A: 11 variants, each bypassing on shadowd × juiceshop.
    for i in range(11):
        rows.append(_row("payload-A", f"variant-{i}", "shadowd", "juiceshop", "allowed"))
    # Payload B: 1 variant, bypassing on coraza × juiceshop.
    rows.append(_row("payload-B", "variant-0", "coraza", "juiceshop", "allowed"))
    df = pd.DataFrame(rows)

    full = hall_of_fame(df, top_n=20, dedup_by_payload=False)
    assert len(full) == 12, "without dedup we should see all 12 variants"

    deduped = hall_of_fame(df, top_n=20, dedup_by_payload=True)
    assert len(deduped) == 2
    payload_ids = set(deduped["payload_id"])
    assert payload_ids == {"payload-A", "payload-B"}


def test_dedup_picks_variant_with_most_bypasses():
    """When two variants of the same payload differ in bypass count, keep the leader."""
    rows: list[dict] = [
        # Variant A bypasses 1 cell.
        _row("p1", "var-A", "modsec", "juiceshop", "allowed"),
        # Variant B bypasses 3 cells.
        _row("p1", "var-B", "modsec", "juiceshop", "allowed"),
        _row("p1", "var-B", "coraza", "juiceshop", "allowed"),
        _row("p1", "var-B", "shadowd", "juiceshop", "allowed"),
    ]
    df = pd.DataFrame(rows)
    out = hall_of_fame(df, top_n=20, dedup_by_payload=True)
    assert len(out) == 1
    assert out.iloc[0]["variant"] == "var-B"
    assert int(out.iloc[0]["bypasses"]) == 3


def test_dedup_off_by_default_is_backward_compatible():
    """Existing callers (single-run reporter) keep the per-variant ranking."""
    rows = [
        _row("p1", "v1", "modsec", "juiceshop", "allowed"),
        _row("p1", "v2", "modsec", "juiceshop", "allowed"),
    ]
    df = pd.DataFrame(rows)
    out = hall_of_fame(df, top_n=20)  # dedup_by_payload defaults to False
    assert len(out) == 2


def test_top_n_applies_after_dedup():
    """top_n caps the *deduped* result, not the pre-dedup row count."""
    rows = []
    # 5 distinct payloads × 3 variants each, all bypassing on modsec × juiceshop.
    for p in range(5):
        for v in range(3):
            rows.append(_row(f"p{p}", f"v{v}", "modsec", "juiceshop", "allowed"))
    df = pd.DataFrame(rows)
    out = hall_of_fame(df, top_n=2, dedup_by_payload=True)
    assert len(out) == 2  # not 6 — top_n is the post-dedup ceiling
