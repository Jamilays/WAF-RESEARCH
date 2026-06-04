"""CSV export — three canonical tables per run (prompt.md §9).

  bypass_rates.csv  — headline pivot: (mutator × waf), both lenses, with CIs.
                      DVWA-only for true_bypass (paper fidelity). All targets
                      for waf_view.
  per_payload.csv   — one row per (payload_id × waf × target), listing
                      allowed/blocked/total counts.
  per_variant.csv   — long-format dump: one row per datapoint. Lets the
                      reporter or a notebook re-slice without re-reading
                      raw JSON.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

from wafeval.analyzer.bypass import compute_rates


def write_csvs(df: pd.DataFrame, out_dir: Path, anchor_target: str = "dvwa") -> dict[str, Path]:
    """Write the three canonical CSVs. Returns a map of name → path."""
    out_dir.mkdir(parents=True, exist_ok=True)

    # ---- per-variant dump -----------------------------------------------
    pv_path = out_dir / "per_variant.csv"
    df.to_csv(pv_path, index=False)

    # ---- per-payload roll-up --------------------------------------------
    per_payload = (
        df.assign(
            n_allowed=(df["verdict"] == "allowed").astype(int),
            n_blocked=(df["verdict"] == "blocked").astype(int),
            n_blocked_silent=(df["verdict"] == "blocked_silent").astype(int),
            n_flagged=(df["verdict"] == "flagged").astype(int),
            n_baseline_fail=(df["verdict"] == "baseline_fail").astype(int),
            n_error=(df["verdict"] == "error").astype(int),
        )
        .groupby(["payload_id", "vuln_class", "waf", "target"], as_index=False)
        .agg({
            "variant": "count",
            "n_allowed": "sum", "n_blocked": "sum", "n_blocked_silent": "sum",
            "n_flagged": "sum", "n_baseline_fail": "sum", "n_error": "sum",
        })
        .rename(columns={"variant": "n_total"})
    )
    pp_path = out_dir / "per_payload.csv"
    per_payload.to_csv(pp_path, index=False)

    # ---- bypass-rate pivot ----------------------------------------------
    frames: list[pd.DataFrame] = []

    # true-bypass on the anchor target only — baseline triggers dependably
    dvwa = df[df["target"] == anchor_target]
    frames.append(
        compute_rates(dvwa[dvwa["waf"] != "baseline"], ["waf", "mutator"], lens="true_bypass")
        .assign(target=anchor_target)
    )
    # waf-view across every target: baseline-agnostic
    frames.append(
        compute_rates(df[df["waf"] != "baseline"], ["waf", "mutator", "target"], lens="waf_view")
    )

    bypass = pd.concat(frames, ignore_index=True)
    br_path = out_dir / "bypass_rates.csv"
    bypass.to_csv(br_path, index=False)

    return {"per_variant": pv_path, "per_payload": pp_path, "bypass_rates": br_path}
