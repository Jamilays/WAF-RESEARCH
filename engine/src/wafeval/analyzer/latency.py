"""Latency statistics — p50/p95/p99 per (waf, …) over ``waf_ms``.

Third leg of TODO.md #2 (response-side fingerprinting). A WAF's latency
distribution is informative independent of whether it blocked: a 400 ms
tail on a "fast" WAF may signal ML-agent cold-cache, a rule that ran
through many regex alternatives, or an upstream timeout chain. Surface
it alongside bypass rates so a reviewer can read latency and detection
on the same axes.

We skip ``error`` and ``baseline_fail`` rows on the grounds that they
aren't real WAF verdicts — a request that timed out at the transport
layer carries no signal about WAF processing cost, and a baseline that
never fired means the sink didn't consume the payload at all.
"""
from __future__ import annotations

import numpy as np
import pandas as pd


_DEFAULT_QUANTILES = (0.50, 0.95, 0.99)


def latency_stats(
    df: pd.DataFrame,
    groupby: list[str] | None = None,
    column: str = "waf_ms",
    quantiles: tuple[float, ...] = _DEFAULT_QUANTILES,
) -> pd.DataFrame:
    """Return percentile table per group over ``column``.

    Columns: ``<groupby…>, n, p50, p95, p99`` (or whatever ``quantiles``
    specifies — names are ``p{int(q*100)}``). Rows with NaN in ``column``
    or with verdict in {error, baseline_fail} are excluded so the
    numerator is "real WAF roundtrips" only.
    """
    groupby = groupby or ["waf", "target"]

    quantile_cols = [f"p{int(q*100)}" for q in quantiles]

    if df.empty or column not in df.columns:
        return pd.DataFrame(columns=[*groupby, "n", *quantile_cols])

    usable = df.copy()
    if "verdict" in usable.columns:
        usable = usable[~usable["verdict"].isin(("error", "baseline_fail"))]
    usable = usable[usable[column].notna()]

    if usable.empty:
        return pd.DataFrame(columns=[*groupby, "n", *quantile_cols])

    rows: list[dict] = []
    for key, sub in usable.groupby(groupby, dropna=False):
        n = len(sub)
        if n == 0:
            continue
        row = dict(zip(groupby, key if isinstance(key, tuple) else (key,)))
        row["n"] = n
        values = sub[column].to_numpy(dtype=float)
        for q, label in zip(quantiles, quantile_cols):
            # ``np.quantile`` with ``method="linear"`` (default) is what pandas
            # uses and what matplotlib boxplots expect — keeps downstream
            # consumers consistent.
            row[label] = float(np.quantile(values, q))
        rows.append(row)

    out = pd.DataFrame(rows)
    return out.sort_values(groupby).reset_index(drop=True)


def render_markdown_table(stats: pd.DataFrame) -> str:
    """Format the latency-stats frame as a Markdown table.

    Used by the run reporter's Appendix B. Empty frames render as a
    placeholder so the reporter doesn't have to branch on shape.
    """
    if stats.empty:
        return (
            "*(no latency data — every record had an error/baseline_fail "
            "verdict or NaN response_ms)*"
        )

    cols = list(stats.columns)
    header = "| " + " | ".join(cols) + " |"
    sep = "|" + "|".join([":--" if c in ("waf", "target", "mutator") else "--:"
                           for c in cols]) + "|"
    lines = [header, sep]
    for _, r in stats.iterrows():
        cells: list[str] = []
        for c in cols:
            v = r[c]
            if c == "n":
                cells.append(str(int(v)))
            elif c.startswith("p"):
                cells.append(f"{v:.1f}")
            else:
                cells.append(str(v))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)
