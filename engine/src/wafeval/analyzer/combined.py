"""Cross-run aggregator — merge datapoints from N runs into one DataFrame.

The 4-WAF comparison in prompt.md §15 never fits in a single run: ModSec,
Coraza, and Shadow Daemon live in the default profile; the paranoia-high
variants live behind ``--profile paranoia-high``; and open-appsec needs its
four-sidecar standalone stack under ``--profile ml``. In practice we land
those results across separate runs and compare them after the fact.

``combine_runs`` stitches the raw per-variant records from a list of run_ids
into a single long-format DataFrame suitable for feeding the existing
``bypass.compute_rates`` / ``hall_of_fame`` machinery. For WAFs that appear in
more than one run, the **last-in-list run wins** — callers order their
run_ids so the freshest data for each WAF is the one that survives. That
rule also gives the caller a predictable way to pull baseline stats from
exactly one run.

The module is deliberately unopinionated about which run should contribute
which WAF: it simply keeps rows tagged with the canonical (waf → run_id)
mapping returned as ``waf_provenance``. The reporter surfaces that so
readers can trace every headline cell back to its source run.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

from wafeval.analyzer.aggregate import load_run


def combine_runs(
    results_root: Path,
    run_ids: list[str],
) -> tuple[pd.DataFrame, dict[str, str]]:
    """Return ``(combined_df, waf_provenance)`` for the given run_ids.

    ``combined_df`` is the long-format per-variant DataFrame — identical in
    shape to ``analyzer.aggregate.load_run`` output — but contains rows from
    every run_id, with duplicate (WAF, …) rows resolved by last-in-list
    wins. ``waf_provenance`` maps ``waf → run_id`` so the reporter can cite
    "this cell came from run X" without re-scanning the DataFrame.
    """
    if not run_ids:
        return pd.DataFrame(), {}

    frames: list[pd.DataFrame] = []
    provenance: dict[str, str] = {}
    for run_id in run_ids:
        try:
            df = load_run(Path(results_root), run_id)
        except FileNotFoundError:
            continue
        if df.empty:
            continue
        for waf in df["waf"].unique():
            provenance[waf] = run_id   # last-in-list wins
        frames.append(df)

    if not frames:
        return pd.DataFrame(), {}

    merged = pd.concat(frames, ignore_index=True)
    # Drop any (waf, run_id) row that isn't the provenance-winning one.
    # A vectorised filter using .map keeps this O(n) without a Python loop.
    canonical = merged["waf"].map(provenance)
    merged = merged[merged["run_id"] == canonical].reset_index(drop=True)
    return merged, provenance
