"""Bypass-rate computation with Wilson 95% confidence intervals.

Two lenses implemented (prompt.md §9, Phase 5 design decision):

  true_bypass  — the paper's definition: among datapoints where the baseline
                 trigger fired, the fraction the WAF allowed through.
                 Denominator = allowed + blocked (baseline-triggered subset).
  waf_view     — baseline-agnostic: (total − blocked) / total. Captures what
                 fraction of requests the WAF failed to block even when the
                 app-side exploit isn't observable, which matters for
                 context_displacement + multi_request variants that reshape
                 the request beyond the vulnerable app's sink.

Wilson score interval (prompt.md §9): stable at small n and near 0/1 where
the normal approximation breaks. ``statsmodels`` would give us this for free
but is ~40 MB; the closed form is ~6 lines.
"""
from __future__ import annotations

import math
from typing import Literal

import pandas as pd

Lens = Literal["true_bypass", "waf_view"]

_Z_95 = 1.959963984540054   # normal quantile for 95% two-sided


def wilson_ci(k: int, n: int, z: float = _Z_95) -> tuple[float, float, float]:
    """Return (point, lo, hi) for k successes out of n at given z.

    Wilson score: (p + z²/2n ± z·√(p(1-p)/n + z²/4n²)) / (1 + z²/n).
    Undefined at n=0 — we return (nan, nan, nan) so aggregators can drop or
    display the gap without special-casing.
    """
    if n <= 0:
        return (float("nan"), float("nan"), float("nan"))
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    lo = max(0.0, centre - half)
    hi = min(1.0, centre + half)
    return (p, lo, hi)


def _num_denom(df: pd.DataFrame, lens: Lens) -> tuple[int, int]:
    """Return (numerator, denominator) for the bypass-rate definition.

    ``blocked_silent`` (WAF let the request through but the response carries
    no exploit marker — silent sanitise) is treated as a WAF win in both
    lenses: it lands in the denominator alongside ``blocked`` but never in
    the numerator. It's a *different kind* of win (rule-level rewrite vs
    hard-deny), surfaced separately in the per-payload CSV and the dashboard
    heatmap; the headline rate stays on what the paper cares about.
    """
    verdicts = df["verdict"]
    if lens == "true_bypass":
        allowed = int((verdicts == "allowed").sum())
        blocked = int((verdicts == "blocked").sum())
        blocked_silent = int((verdicts == "blocked_silent").sum())
        flagged = int((verdicts == "flagged").sum())
        # Paper's headline ratio: allowed over (allowed + blocked +
        # blocked_silent + flagged). Flagged stays in the denominator
        # because the WAF did detect the request even if it forwarded — the
        # "bypass" meant slipping a payload past the WAF undetected.
        denom = allowed + blocked + blocked_silent + flagged
        return allowed, denom
    # waf_view — baseline-agnostic, but we still drop datapoints where no
    # bypass attempt was possible. Excluding baseline_fail + error makes the
    # denominator "requests that actually tested the WAF" rather than
    # "all files on disk". Without this, targets/endpoints with broken
    # baselines (Juice Shop XSS pre-fix, DVWA SSTI endpoint) reported
    # rate=1.0 because "not blocked" swept in every baseline-fail too.
    blocked = int((verdicts == "blocked").sum())
    blocked_silent = int((verdicts == "blocked_silent").sum())
    error = int((verdicts == "error").sum())
    baseline_fail = int((verdicts == "baseline_fail").sum())
    denom = len(df) - error - baseline_fail
    num = max(0, denom - blocked - blocked_silent)
    return num, denom


def compute_rates(
    df: pd.DataFrame,
    groupby: list[str],
    lens: Lens = "true_bypass",
) -> pd.DataFrame:
    """Aggregate bypass rates over ``groupby`` columns.

    Columns: ``<groupby…>, k, n, rate, ci_lo, ci_hi, lens``. Groups with
    ``n==0`` are dropped (common for target/class combos with no endpoint).
    """
    if df.empty:
        return pd.DataFrame(
            columns=[*groupby, "k", "n", "rate", "ci_lo", "ci_hi", "lens"]
        )

    rows: list[dict] = []
    for key, sub in df.groupby(groupby, dropna=False):
        k, n = _num_denom(sub, lens)
        p, lo, hi = wilson_ci(k, n)
        row = dict(zip(groupby, key if isinstance(key, tuple) else (key,)))
        row.update({"k": k, "n": n, "rate": p, "ci_lo": lo, "ci_hi": hi, "lens": lens})
        rows.append(row)
    out = pd.DataFrame(rows).dropna(subset=["rate"])
    return out.sort_values(groupby).reset_index(drop=True)
